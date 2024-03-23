use std::{hash::Hasher, time::Duration};

use rand::{Rng, RngCore};

use crate::shared::ConnectionId;
use crate::MAX_CID_SIZE;

/// Generates connection IDs for incoming connections
pub trait ConnectionIdGenerator: Send + Sync {
    /// Generates a new CID
    ///
    /// Connection IDs MUST NOT contain any information that can be used by
    /// an external observer (that is, one that does not cooperate with the
    /// issuer) to correlate them with other connection IDs for the same
    /// connection. They MUST have high entropy, e.g. due to encrypted data
    /// or cryptographic-grade random data.
    fn generate_cid(&mut self) -> ConnectionId;

    /// Quickly determine whether `cid` could have been generated by this generator
    ///
    /// False positives are permitted, but increase the cost of handling invalid packets.
    fn validate(&self, _cid: &ConnectionId) -> Result<(), InvalidCid> {
        Ok(())
    }

    /// Returns the length of a CID for connections created by this generator
    fn cid_len(&self) -> usize;
    /// Returns the lifetime of generated Connection IDs
    ///
    /// Connection IDs will be retired after the returned `Duration`, if any. Assumed to be constant.
    fn cid_lifetime(&self) -> Option<Duration>;
}

/// The connection ID was not recognized by the [`ConnectionIdGenerator`]
#[derive(Debug, Copy, Clone)]
pub struct InvalidCid;

/// Generates purely random connection IDs of a specified length
///
/// Random CIDs can be smaller than those produced by [`HashedConnectionIdGenerator`], but cannot be
/// usefully [`validate`](ConnectionIdGenerator::validate)d.
#[derive(Debug, Clone, Copy)]
pub struct RandomConnectionIdGenerator {
    cid_len: usize,
    lifetime: Option<Duration>,
}

impl Default for RandomConnectionIdGenerator {
    fn default() -> Self {
        Self {
            cid_len: 8,
            lifetime: None,
        }
    }
}

impl RandomConnectionIdGenerator {
    /// Initialize Random CID generator with a fixed CID length
    ///
    /// The given length must be less than or equal to MAX_CID_SIZE.
    pub fn new(cid_len: usize) -> Self {
        debug_assert!(cid_len <= MAX_CID_SIZE);
        Self {
            cid_len,
            ..Self::default()
        }
    }

    /// Set the lifetime of CIDs created by this generator
    pub fn set_lifetime(&mut self, d: Duration) -> &mut Self {
        self.lifetime = Some(d);
        self
    }
}

impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes_arr = [0; MAX_CID_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes_arr[..self.cid_len]);

        ConnectionId::new(&bytes_arr[..self.cid_len])
    }

    /// Provide the length of dst_cid in short header packet
    fn cid_len(&self) -> usize {
        self.cid_len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        self.lifetime
    }
}

/// Generates 8-byte connection IDs that can be efficiently
/// [`validate`](ConnectionIdGenerator::validate)d
///
/// This generator uses a non-cryptographic hash and can therefore still be spoofed, but nonetheless
/// helps prevents Quinn from responding to non-QUIC packets at very low cost.
pub struct HashedConnectionIdGenerator {
    key: u64,
    lifetime: Option<Duration>,
}

impl HashedConnectionIdGenerator {
    /// Create a generator with a random key
    pub fn new() -> Self {
        Self::from_key(rand::thread_rng().gen())
    }

    /// Create a generator with a specific key
    ///
    /// Allows [`validate`](ConnectionIdGenerator::validate) to recognize a consistent set of
    /// connection IDs across restarts
    pub fn from_key(key: u64) -> Self {
        Self {
            key,
            lifetime: None,
        }
    }

    /// Set the lifetime of CIDs created by this generator
    pub fn set_lifetime(&mut self, d: Duration) -> &mut Self {
        self.lifetime = Some(d);
        self
    }
}

#[cfg(feature = "ring")]
impl Default for HashedConnectionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionIdGenerator for HashedConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes_arr = [0; NONCE_LEN + SIGNATURE_LEN];
        rand::thread_rng().fill_bytes(&mut bytes_arr[..NONCE_LEN]);
        let mut hasher = rustc_hash::FxHasher::default();
        hasher.write_u64(self.key);
        hasher.write(&bytes_arr[..NONCE_LEN]);
        bytes_arr[NONCE_LEN..].copy_from_slice(&hasher.finish().to_le_bytes()[..SIGNATURE_LEN]);
        ConnectionId::new(&bytes_arr)
    }

    fn validate(&self, cid: &ConnectionId) -> Result<(), InvalidCid> {
        let (nonce, signature) = cid.split_at(NONCE_LEN);
        let mut hasher = rustc_hash::FxHasher::default();
        hasher.write_u64(self.key);
        hasher.write(nonce);
        let expected = hasher.finish().to_le_bytes();
        match expected[..SIGNATURE_LEN] == signature[..] {
            true => Ok(()),
            false => Err(InvalidCid),
        }
    }

    fn cid_len(&self) -> usize {
        NONCE_LEN + SIGNATURE_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        self.lifetime
    }
}

const NONCE_LEN: usize = 3; // Good for more than 16 million connections
const SIGNATURE_LEN: usize = 8 - NONCE_LEN; // 8-byte total CID length

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ring")]
    fn validate_keyed_cid() {
        let mut generator = HashedConnectionIdGenerator::new();
        let cid = generator.generate_cid();
        generator.validate(&cid).unwrap();
    }
}
