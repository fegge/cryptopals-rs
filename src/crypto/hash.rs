use std::fmt;
use std::convert::AsRef;
use std::num::Wrapping;
use std::convert::TryInto;


type W32 = Wrapping<u32>;

trait WrappingExt {
    type ByteArray: Copy;

    fn from_be_bytes(bytes: &[u8]) -> Self;
    
    fn to_be_bytes(&self) -> Self::ByteArray;

    fn left_rotate(&mut self, n: u32) -> Self;
}

impl WrappingExt for W32 {
    type ByteArray = [u8; 4];

    #[inline(always)]
    fn from_be_bytes(bytes: &[u8]) -> Self {
        Wrapping(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    #[inline(always)]
    fn to_be_bytes(&self) -> Self::ByteArray {
        self.0.to_be_bytes()
    }

    #[inline(always)]
    fn left_rotate(&mut self, n: u32) -> Self {
        Wrapping(self.0.rotate_left(n))
    }
}

#[derive(Debug, PartialEq)]
pub struct MessageDigest(Vec<u8>);

impl MessageDigest {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
 
    pub fn to_str(&self) -> String {
        hex::encode(&self.0)
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for MessageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.to_str())
    }
}

pub trait HashFunction where Self: Sized {
    /// The output size.
    const DIGEST_SIZE: usize;

    fn new() -> Self;

    /// Hash the given buffer. Returns `self`.
    fn update(&mut self, buffer: &[u8]) -> &mut Self;

    /// Should return a `MessageDigest` of length `Self::DIGEST_SIZE`.
    fn finalize(&mut self) -> MessageDigest;

    /// Returns the digest of the given buffer.
    fn digest<B: AsRef<[u8]>>(buffer: B) -> MessageDigest {
        Self::new()
            .update(buffer.as_ref())
            .finalize()
    }
}

pub trait Mac where Self: Sized {
    /// The output size.
    const TAG_SIZE: usize;

    fn new(key: &[u8]) -> Self;

    /// Hash the given buffer. Returns `self`.
    fn update(&mut self, buffer: &[u8]) -> &mut Self;

    /// Should return a `MessageTag` of length `Self::TAG_SIZE`.
    fn finalize(&mut self) -> MessageDigest;

    fn digest<K: AsRef<[u8]>, B: AsRef<[u8]>>(key: K, buffer: B) -> MessageDigest {
        Self::new(key.as_ref())
            .update(buffer.as_ref())
            .finalize()
    }
}

pub mod sha {
    use std::cmp;
    use std::num::Wrapping;
    use std::convert::TryInto;

    use super::{W32, WrappingExt, HashFunction, MessageDigest};

    /// A byte oriented implementation of the SHA-1 hash function.
    pub struct Sha1 {
        state: [W32; 5],
        chunk: [u8; 64],
        chunk_size: usize,
        message_size: usize,
    }
    
    impl Sha1 {
        const CHUNK_SIZE: usize = 64;
        const NOF_ROUNDS: usize = 80;

        pub fn from_state(state: &[u32; 5]) -> Self {
            let state = [
                Wrapping(state[0]),
                Wrapping(state[1]),
                Wrapping(state[2]),
                Wrapping(state[3]),
                Wrapping(state[4]),
            ];
            Self { 
                state,
                chunk: [0; Sha1::CHUNK_SIZE],
                chunk_size: 0,
                message_size: 0
            }
        }

        #[inline(always)]
        fn choose(x: W32, y: W32, z: W32) -> W32 {
            (x & y) | (!x & z)
        }

        #[inline(always)]
        fn parity(x: W32, y: W32, z: W32) -> W32 {
            x ^ y ^ z
        }

        #[inline(always)]
        fn majority(x: W32, y: W32, z: W32) -> W32 {
            (x & y) | (x & z) | (y & z) 
        }
        
        #[inline(always)]
        fn process_state(
            mut a: W32,
            mut b: W32,
            mut c: W32,
            mut d: W32,
            mut e: W32,
            k: W32,
            words: &[W32; 20],
            f: impl Fn(W32, W32, W32) -> W32
            ) -> (W32, W32, W32, W32, W32) {
            for word in words {
                let temp = a.left_rotate(5) + f(b, c, d) + e + k + word;
                e = d;
                d = c;
                c = b.left_rotate(30);
                b = a;
                a = temp; 
            }
            (a, b, c, d, e)
        }
    
        fn process_chunk(state: &mut [W32; 5], chunk: &[u8]) {
            let mut words: [W32; Sha1::NOF_ROUNDS] = [Wrapping(0); Sha1::NOF_ROUNDS];
            for i in 0..16 {
                words[i] = W32::from_be_bytes(&chunk[4 * i .. 4 * i + 4]);
            }
            for i in 16..Sha1::NOF_ROUNDS {
                words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).left_rotate(1);
            }
            let a = state[0];
            let b = state[1];
            let c = state[2];
            let d = state[3];
            let e = state[4];

            let (a, b, c, d, e) = Sha1::process_state(
                a, b, c, d, e, Wrapping(0x5a82_7999), words[0 ..20].try_into().unwrap(), Sha1::choose
            );
            let (a, b, c, d, e) = Sha1::process_state(
                a, b, c, d, e, Wrapping(0x6ed9_eba1), words[20..40].try_into().unwrap(), Sha1::parity
            );
            let (a, b, c, d, e) = Sha1::process_state(
                a, b, c, d, e, Wrapping(0x8f1b_bcdc), words[40..60].try_into().unwrap(), Sha1::majority
            );
            let (a, b, c, d, e) = Sha1::process_state(
                a, b, c, d, e, Wrapping(0xca62_c1d6), words[60..80].try_into().unwrap(), Sha1::parity
            );

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }
    }

    impl HashFunction for Sha1 {
        const DIGEST_SIZE: usize = 20;

        fn new() -> Self {
            Self::from_state(&[
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ])
        }

        fn update(&mut self, buffer: &[u8]) -> &mut Self {
            let mut buffer_offset = 0;

            // Handle cached partial chunk.
            if self.chunk_size > 0 {
                let copy_size = cmp::min(Sha1::CHUNK_SIZE - self.chunk_size, buffer.len());
                self.chunk[self.chunk_size .. self.chunk_size + copy_size].copy_from_slice(&buffer[..copy_size]);
                self.chunk_size += copy_size;
                buffer_offset = copy_size;
            }
            if self.chunk_size == Sha1::CHUNK_SIZE {
                Sha1::process_chunk(&mut self.state, &self.chunk.clone());
                self.chunk_size = 0;
            }
            
            // Process input buffer, one chunk at a time.
            for chunk in buffer[buffer_offset..].chunks_exact(Sha1::CHUNK_SIZE) {
                Sha1::process_chunk(&mut self.state, &chunk);
                buffer_offset += Sha1::CHUNK_SIZE;
            }
            
            // Cache remaining partial chunk.
            if buffer_offset < buffer.len() {
                let copy_size = buffer.len() - buffer_offset;
                self.chunk[..copy_size].copy_from_slice(&buffer[buffer_offset..]);
                self.chunk_size = copy_size;
            }

            self.message_size += buffer.len();
            self
        }

        fn finalize(&mut self) -> MessageDigest {
            // Append padding and total message size (int bits) to the end of the input, ensuring
            // that the total input size is 0 modulo 64.
            let reduced_size = self.message_size % Sha1::CHUNK_SIZE;
            
            // Ensure that we have enough space for the first 0x80 byte and the message size.
            let padding_size = if (reduced_size + 9) < Sha1::CHUNK_SIZE { 
                Sha1::CHUNK_SIZE - reduced_size
            } else { 
                2 * Sha1::CHUNK_SIZE - reduced_size
            };
            let mut padding = vec![0; padding_size];
            padding[0] = 0x80;
            padding[padding_size - 8 ..].copy_from_slice(&(8 * self.message_size as u64).to_be_bytes());
            
            self.update(&padding);
            assert!(self.chunk_size == 0);
        
            // Produce the final hash value by concatenating the state (as big endian integers).
            let mut digest = vec![0; Self::DIGEST_SIZE];
            for (i, word) in self.state.iter().enumerate() {
                digest[4 * i .. 4 * i + 4].copy_from_slice(&word.to_be_bytes());
            }
            MessageDigest(digest)
        }
    }

    impl Default for Sha1 {
        fn default() -> Sha1 {
            Sha1::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::HashFunction;
        use super::Sha1;
        
        #[test]
        fn known_output() {
            let digest = Sha1::digest("The quick brown fox jumps over the lazy dog");
            assert_eq!(digest.to_str(), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        }
        
        #[test]
        fn chunked_update() {
            let mut hash = Sha1::new();
            for _ in 0..256 {
                hash.update(b"abc");
            }
            let digest = hash.finalize();
            assert_eq!(digest.to_str(), "87f34c2186611148979f61f0b340360f815a27a2");
        }
    }
}

pub mod mac {
    use super::{HashFunction, Mac, MessageDigest};

    pub struct NaiveMac<H: HashFunction> {
        hash: H
    }

    /// A Hash-based Mac which is vulnerable to length extension attacks.
    impl<H: HashFunction> Mac for NaiveMac<H> {
        /// The output size.
        const TAG_SIZE: usize = H::DIGEST_SIZE;

        fn new(key: &[u8]) -> Self {
            let mut hash: H = H::new();
            hash.update(&key);
            Self { hash }
        }

        /// Hash the given buffer. Returns `self`.
        fn update(&mut self, buffer: &[u8]) -> &mut Self {
            self.hash.update(buffer);
            self
        }

        /// Should return a `MessageTag` of length `Self::TAG_SIZE`.
        fn finalize(&mut self) -> MessageDigest {
            self.hash.finalize()
        }
    }
}

// Re-export `Sha1` and `NaiveMac`.
pub use sha::Sha1;
pub use mac::NaiveMac;

pub type Sha1NaiveMac = NaiveMac<Sha1>;
