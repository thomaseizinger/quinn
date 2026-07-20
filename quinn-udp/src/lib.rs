//! Uniform interface to send and receive UDP packets with advanced features useful for QUIC
//!
//! This crate exposes kernel UDP stack features available on most modern systems which are required
//! for an efficient and conformant QUIC implementation. As of this writing, these are not available
//! in std or major async runtimes, and their niche character and complexity are a barrier to adding
//! them. Hence, a dedicated crate.
//!
//! Exposed features include:
//!
//! - Segmentation offload for bulk send and receive operations, reducing CPU load.
//! - Reporting the exact destination address of received packets and specifying explicit source
//!   addresses for sent packets, allowing responses to be sent from the address that the peer
//!   expects when there are multiple possibilities. This is common when bound to a wildcard address
//!   in IPv6 due to [RFC 8981] temporary addresses.
//! - [Explicit Congestion Notification], which is required by QUIC to prevent packet loss and reduce
//!   latency on congested links when supported by the network path.
//! - Disabled IP-layer fragmentation, which allows the true physical MTU to be detected and reduces
//!   risk of QUIC packet loss.
//!
//! Some features are unavailable in some environments. This can be due to an outdated operating
//! system or drivers. Some operating systems may not implement desired features at all, or may not
//! yet be supported by the crate. When support is unavailable, functionality will gracefully
//! degrade.
//!
//! [RFC 8981]: https://www.rfc-editor.org/rfc/rfc8981.html
//! [Explicit Congestion Notification]: https://www.rfc-editor.org/rfc/rfc3168.html
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use core::time::Duration;
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    fmt, io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
};
#[cfg(not(wasm_browser))]
use std::{sync::Mutex, time::Instant};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock;

#[cfg(apple_fast)]
mod apple_fast;

#[cfg(any(unix, windows))]
mod cmsg;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

// No ECN support
#[cfg(not(any(wasm_browser, unix, windows)))]
#[path = "fallback.rs"]
mod imp;

#[allow(unused_imports, unused_macros)]
mod log {
    #[cfg(all(feature = "log", not(feature = "tracing-log")))]
    pub(crate) use log::{debug, error, info, trace, warn};

    #[cfg(feature = "tracing-log")]
    pub(crate) use tracing::{debug, error, info, trace, warn};

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    mod no_op {
        macro_rules! trace    ( ($($tt:tt)*) => {{}} );
        macro_rules! debug    ( ($($tt:tt)*) => {{}} );
        macro_rules! info     ( ($($tt:tt)*) => {{}} );
        macro_rules! log_warn ( ($($tt:tt)*) => {{}} );
        macro_rules! error    ( ($($tt:tt)*) => {{}} );

        pub(crate) use {debug, error, info, log_warn as warn, trace};
    }

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    pub(crate) use no_op::*;
}

#[cfg(not(wasm_browser))]
pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
#[cfg(not(wasm_browser))]
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;
/// Number of UDP packets to send/receive at a time
#[cfg(wasm_browser)]
pub const BATCH_SIZE: usize = 1;

/// Metadata for a single buffer filled with bytes received from the network
///
/// This associated buffer can contain one or more datagrams, see [`stride`].
///
/// [`stride`]: RecvMeta::stride
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct RecvMeta {
    /// The source address of the datagram(s) contained in the buffer
    pub addr: SocketAddr,
    /// The number of bytes the associated buffer has
    pub len: usize,
    /// The size of a single datagram in the associated buffer
    ///
    /// When GRO (Generic Receive Offload) is used this indicates the size of a single
    /// datagram inside the buffer. If the buffer is larger, that is if [`len`] is greater
    /// then this value, then the individual datagrams contained have their boundaries at
    /// `stride` increments from the start. The last datagram could be smaller than
    /// `stride`.
    ///
    /// [`len`]: RecvMeta::len
    pub stride: usize,
    /// The Explicit Congestion Notification bits for the datagram(s) in the buffer
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address which was encoded in this datagram
    ///
    /// Populated on platforms: Windows, Linux, Android (API level > 25),
    /// FreeBSD, OpenBSD, NetBSD, macOS, and iOS.
    pub dst_ip: Option<IpAddr>,
    /// The interface index of the interface on which the datagram was received
    pub interface_index: Option<u32>,
    /// Kernel receive timestamp as Unix epoch
    ///
    /// Populated on platforms: Linux, Android.
    pub timestamp: Option<Duration>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            interface_index: None,
            timestamp: None,
        }
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: &'a [u8],
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    /// and must be non-zero when set.
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

impl<'a> Transmit<'a> {
    /// Returns the number of datagrams encoded by this transmit.
    ///
    /// A transmit without a `segment_size` always represents one datagram, including when its
    /// contents are empty.
    pub fn datagram_count(&self) -> usize {
        match self.segment_size {
            Some(0) => panic!("segment size must be non-zero"),
            Some(size) if size < self.contents.len() => self.contents.len().div_ceil(size),
            Some(_) | None => 1,
        }
    }

    /// Advances past `datagrams` leading datagrams.
    ///
    /// This only adjusts the borrowed view of `contents`; it never copies packet data. The caller
    /// must not use the transmit again after advancing by [`Self::datagram_count`] datagrams. This
    /// caveat matters for empty UDP datagrams, for which there is no shorter slice that can encode
    /// completion.
    ///
    /// # Panics
    ///
    /// Panics if `datagrams` exceeds [`Self::datagram_count`].
    pub fn advance(&mut self, datagrams: impl Into<usize>) {
        let datagrams = datagrams.into();
        let total = self.datagram_count();
        assert!(
            datagrams <= total,
            "cannot advance {datagrams} datagrams past a {total}-datagram transmit"
        );

        if datagrams == total {
            self.contents = &self.contents[self.contents.len()..];
            return;
        }

        let Some(segment_size) = self.segment_size else {
            debug_assert_eq!(datagrams, 0);
            return;
        };
        self.contents = &self.contents[datagrams * segment_size..];
    }

    /// Plans a send containing at most `max_datagrams.max(1)` leading datagrams.
    #[cfg(not(wasm_browser))]
    fn send_plan(&self, max_datagrams: usize) -> SendPlan<'_> {
        let max_datagrams = max_datagrams.max(1);

        let segment_size = self
            .segment_size
            .filter(|&size| size != 0 && size < self.contents.len());

        let contents = match segment_size {
            Some(size) => {
                &self.contents[..self.contents.len().min(size.saturating_mul(max_datagrams))]
            }
            None => self.contents,
        };

        let datagram_count = match segment_size {
            Some(size) => contents.len().div_ceil(size),
            None => 1,
        };
        let segment_size = segment_size.filter(|&size| size < contents.len());

        SendPlan {
            transmit: self,
            contents,
            segment_size,
            datagram_count,
        }
    }
}

/// The prefix of a [`Transmit`] attempted by one platform send operation.
///
/// Metadata remains borrowed from the original transmit. This only describes the payload view and
/// segmentation parameters selected for the syscall.
#[cfg(not(wasm_browser))]
#[derive(Clone, Copy)]
struct SendPlan<'a> {
    transmit: &'a Transmit<'a>,
    contents: &'a [u8],
    segment_size: Option<usize>,
    datagram_count: usize,
}

#[cfg(not(wasm_browser))]
impl SendPlan<'_> {
    fn destination(&self) -> SocketAddr {
        self.transmit.destination
    }

    fn ecn(&self) -> Option<EcnCodepoint> {
        self.transmit.ecn
    }

    fn src_ip(&self) -> Option<IpAddr> {
        self.transmit.src_ip
    }

    #[cfg(any(apple, target_os = "linux", target_os = "android"))]
    fn single(self) -> Self {
        self.transmit.send_plan(1)
    }
}

/// Number of leading datagrams consumed by a send operation.
///
/// Compare this with [`Transmit::datagram_count`] to determine whether the whole transmit was
/// consumed. If it was not, pass it directly to [`Transmit::advance`] before retrying the
/// remainder.
#[must_use = "send progress must be handled by advancing or completing the transmit"]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SendCount(NonZeroUsize);

impl SendCount {
    /// Constructs a send count, or returns `None` if `value` is zero.
    pub fn new(value: usize) -> Option<Self> {
        Some(Self(NonZeroUsize::new(value)?))
    }

    /// Returns the number of consumed datagrams.
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl From<SendCount> for usize {
    fn from(value: SendCount) -> Self {
        value.get()
    }
}

impl PartialEq<usize> for SendCount {
    fn eq(&self, other: &usize) -> bool {
        self.get() == *other
    }
}

impl PartialOrd<usize> for SendCount {
    fn partial_cmp(&self, other: &usize) -> Option<std::cmp::Ordering> {
        self.get().partial_cmp(other)
    }
}

impl fmt::Display for SendCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

/// Asynchronous transport-layer errors reported by the operating system
///
/// On Linux and Android these are delivered via the socket error queue
/// (`MSG_ERRQUEUE`) and originate from ICMP messages.
///
/// These errors are out-of-band and do not correspond to a received packet.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct TransportError {
    /// Address associated with the error
    ///
    /// This is the remote peer or an intermediate network device that triggered the error.
    /// Returns `None` if the kernel cannot determine the source (e.g. `AF_UNSPEC`).
    pub addr: Option<SocketAddr>,
    /// Transport-layer error details
    pub payload: TransportErrorPayload,
    /// The raw error code from the underlying operating system
    pub raw_errno: i32,
}

impl TransportError {
    /// Returns the recommended MTU for packet-too-big errors
    pub fn mtu(&self) -> Option<u32> {
        match self.payload {
            TransportErrorPayload::TooBig { mtu } => Some(mtu),
            _ => None,
        }
    }
}

/// Transport-layer error details reported by the kernel
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum TransportErrorPayload {
    /// Destination host or port is unreachable
    Unreachable,
    /// Packet exceeds path MTU
    TooBig {
        /// Recommended Maximum Transmission Unit
        mtu: u32,
    },
    /// Other transport-layer or kernel-reported error
    Other,
}

/// Returns true if the given I/O error corresponds to a message size error
///
/// Useful, for example, after invoking [`io::Error::last_os_error()`]
/// to check if the last OS error was a message size error
/// (EMSGSIZE on Unix, WSAEMSGSIZE on Windows).
///
/// Note: EMSGSIZE's value is not standardized across OSes (90 on Linux,
/// 40 on macOS/iOS/BSD; on Windows, `io::Error::raw_os_error()` returns
/// the Winsock error WSAEMSGSIZE (10040) via `GetLastError()`, which is
/// distinct from the MSVCRT `errno.h` EMSGSIZE value of 115, which is
/// never actually populated by socket operations).
pub fn is_msg_size_err(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        err.raw_os_error() == Some(WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Log at most 1 IO error per minute
#[cfg(not(wasm_browser))]
const IO_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
#[cfg(all(not(wasm_browser), any(feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    plan: &SendPlan<'_>,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisend lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        log::warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, ecn: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            plan.destination(),
            plan.src_ip(),
            plan.ecn(),
            plan.contents.len(),
            plan.segment_size
        );
    }
}

// No-op
#[cfg(not(any(wasm_browser, feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(_: &Mutex<Instant>, _: impl core::fmt::Debug, _: &SendPlan<'_>) {}

/// A borrowed UDP socket
///
/// On Unix, constructible via `From<T: AsFd>`. On Windows, constructible via `From<T:
/// AsSocket>`.
// Wrapper around socket2 to avoid making it a public dependency and incurring stability risk
#[cfg(not(wasm_browser))]
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn send_plan_uses_effective_segment_size() {
        assert_eq!(
            make_transmit(&[0u8; 10], Some(15))
                .send_plan(usize::MAX)
                .segment_size,
            None,
            "segment_size > content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(10))
                .send_plan(usize::MAX)
                .segment_size,
            None,
            "segment_size == content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], None)
                .send_plan(usize::MAX)
                .segment_size,
            None,
            "no segment_size should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(5))
                .send_plan(usize::MAX)
                .segment_size,
            Some(5),
            "segment_size < content_len should yield effective segment_size"
        );
    }

    #[test]
    fn datagram_count_and_advance() {
        let contents = [0u8; 11];
        let mut transmit = make_transmit(&contents, Some(5));

        assert!(SendCount::new(0).is_none());

        assert_eq!(transmit.datagram_count(), 3);
        let sent = SendCount::new(1).unwrap();
        assert_eq!(sent, 1);
        assert_eq!(sent.get(), 1);
        transmit.advance(sent);
        assert_eq!(transmit.contents.len(), 6);
        assert_eq!(transmit.datagram_count(), 2);
        transmit.advance(1usize);
        assert_eq!(transmit.contents.len(), 1);
        assert_eq!(transmit.datagram_count(), 1);
        transmit.advance(1usize);
        assert!(transmit.contents.is_empty());

        assert_eq!(make_transmit(&[], None).datagram_count(), 1);
        assert_eq!(make_transmit(&contents, None).datagram_count(), 1);
        assert_eq!(make_transmit(&contents, Some(20)).datagram_count(), 1);
    }

    #[test]
    fn send_plan_is_infallible_for_degenerate_limits_and_segment_sizes() {
        let contents = [0u8; 11];

        for segment_size in [None, Some(0)] {
            let transmit = make_transmit(&contents, segment_size);
            let plan = transmit.send_plan(0);

            assert_eq!(plan.contents, contents);
            assert_eq!(plan.datagram_count, 1);
            assert_eq!(plan.segment_size, None);
        }
    }

    #[test]
    fn send_plan_preserves_a_datagram_prefix() {
        let contents = [0u8; 11];
        let transmit = make_transmit(&contents, Some(5));

        let prefix = transmit.send_plan(2);
        assert_eq!(prefix.contents.len(), 10);
        assert_eq!(prefix.datagram_count, 2);
        assert_eq!(prefix.segment_size, Some(5));
        assert_eq!(prefix.destination(), transmit.destination);
        assert_eq!(prefix.ecn(), transmit.ecn);
        assert_eq!(prefix.src_ip(), transmit.src_ip);

        let complete = transmit.send_plan(3);
        assert_eq!(complete.contents.len(), 11);
        assert_eq!(complete.datagram_count, 3);
        assert_eq!(complete.segment_size, Some(5));

        let single = prefix.single();
        assert_eq!(single.contents.len(), 5);
        assert_eq!(single.datagram_count, 1);
        assert_eq!(single.segment_size, None);
    }

    fn make_transmit(contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
        Transmit {
            destination: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1)),
            ecn: None,
            contents,
            segment_size,
            src_ip: None,
        }
    }
}
