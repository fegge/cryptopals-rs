/// A random number generator trait.
pub trait RandomGenerator {
    fn next_u8(&mut self) -> u8;

    fn next_u16(&mut self) -> u16;
    
    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;
}

/// A seedable random number generator trait.
pub trait SeedableGenerator: RandomGenerator {
    type Seed;

    fn new(seed: Self::Seed) -> Self;

    fn seed(&mut self, seed: Self::Seed);
}

/// Return a random instance of `Self`.
pub trait Random {
    fn random() -> Self;
}

#[macro_export]
macro_rules! random_vec {
    ($size:expr) => {
        (0..$size).map(|_| { rand::random() }).collect::<Vec<u8>>()
    }
}

pub mod mersenne_twister {
    use rand;
    use rand::Rng;

    use std::fmt;
    use std::cmp::PartialEq;
    use std::num::Wrapping;

    use super::{Random, RandomGenerator, SeedableGenerator};
    
    /// Standard 32-bit Mersenne twister.
    pub struct Mt19337 {
        state: [Wrapping<u32>; 624],
        index: usize
    }

    impl Mt19337 {
        const SIZE: usize = 624;
        const SEED_MULT: Wrapping<u32> = Wrapping(0x6c07_8965);
        const UPPER_MASK: Wrapping<u32> = Wrapping(0x8000_0000);
        const LOWER_MASK: Wrapping<u32> = Wrapping(0x7fff_ffff);
        const FIRST_MASK: Wrapping<u32> = Wrapping(0x9d2c_5680);
        const SECOND_MASK: Wrapping<u32> = Wrapping(0xefc6_0000);
        const TWIST_CONST: Wrapping<u32> = Wrapping(0x9908_b0df);

        pub fn from_state(state: [u32; Self::SIZE], index: usize) -> Self {
            let mut wrapping_state = [Wrapping(0); Self::SIZE];
            for i in 0..Self::SIZE {
                wrapping_state[i] = Wrapping(state[i]);
            }
            Mt19337 {
                state: wrapping_state,
                index
            }
        }
        
        fn twist(&mut self) {
            let k = Mt19337::SIZE - 1;
            let m = 227;
            let n = Mt19337::SIZE - m;
            for i in 0..m {
                let x = (self.state[i] & Mt19337::UPPER_MASK) | (self.state[i + 1] & Mt19337::LOWER_MASK);
                self.state[i] = self.state[n + i] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
            }
            for i in n..Mt19337::SIZE - 1 {
                let x = (self.state[i] & Mt19337::UPPER_MASK) | (self.state[i + 1] & Mt19337::LOWER_MASK);
                self.state[i] = self.state[i - n] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
            }
            let x = (self.state[k] & Mt19337::UPPER_MASK) | (self.state[0] & Mt19337::LOWER_MASK);
            self.state[k] = self.state[n - 1] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
            self.index = 0;
        }
    }

    impl Random for Mt19337 {
        fn random() -> Self {
            Self::new(rand::thread_rng().gen())
        }
    }

    impl RandomGenerator for Mt19337 {
        fn next_u8(&mut self) -> u8 {
            (self.next_u32() & 0xff) as u8
        }
        
        fn next_u16(&mut self) -> u16 {
            (self.next_u32() & 0xffff) as u16
        }

        fn next_u32(&mut self) -> u32 {
            if self.index >= Mt19337::SIZE {
                self.twist();
            }
            let mut x = self.state[self.index];

            x ^=  x >> 11;
            x ^= (x <<  7) & Mt19337::FIRST_MASK;
            x ^= (x << 15) & Mt19337::SECOND_MASK;
            x ^=  x >> 18;

            self.index += 1;
            x.0
        }

        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) ^ (self.next_u32() as u64)
        }
    }

    impl SeedableGenerator for Mt19337 {
        type Seed = u32;

        fn new(seed: u32) -> Self {
            let mut result = Self {
                state: [Wrapping(0); Mt19337::SIZE],
                index: 0
            };
            result.seed(seed);
            result
        }

        fn seed(&mut self, seed: u32) {
            self.state[0] = Wrapping(seed);
            for i in 1..Mt19337::SIZE {
                let x = self.state[i - 1] ^ (self.state[i - 1] >> 30);
                self.state[i] = Mt19337::SEED_MULT * x + Wrapping(i as u32);
            }
            self.twist();
        }
    }

    impl fmt::Debug for Mt19337 {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            writeln!(formatter, "Mt19337 {{")?;
            writeln!(formatter, "    {:?},", self.state.iter().map(|x| x.0).collect::<Vec<u32>>())?;
            writeln!(formatter, "    {}", self.index)?;
            writeln!(formatter, "}}")
        }
    }

    impl PartialEq for Mt19337 {
        fn eq(&self, other: &Self) -> bool {
            // Two Mt19337 instances are equal if the indices and internal state arrays are equal.
            self.index == other.index && self.state.iter().zip(other.state.iter()).all(|(x, y)| x == y)
        }
    }

    impl Iterator for Mt19337 {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            Some(self.next_u8())
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::crypto::symmetric::cipher_modes::StreamCipherMode;
        use super::super::{RandomGenerator, SeedableGenerator};
        use super::Mt19337;
        
        const PLAINTEXT: [u8; 8] = [0; 8];
        const CIPHERTEXT: [u8; 8] = [0x25, 0xeb, 0x8c, 0x48, 0xff, 0x89, 0xcb, 0x85];
        

        #[test]
        fn known_output() {
            let mut random = Mt19337::new(1);
            let output = [
                0x6ac1f425, 0xff4780eb, 0xb8672f8c, 0xeebc1448, 
                0x00077EFF, 0x20CCC389, 0x4D65aacb, 0xffc11E85
            ];
            for i in 0..output.len() {
                assert_eq!(random.next_u32(), output[i]);
            }
        }

        #[test]
        fn encrypt_buffer() {
            let mut random = Mt19337::new(1);
            assert_eq!(random.encrypt_buffer(&PLAINTEXT).unwrap(), &CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_buffer() {
            let mut random = Mt19337::new(1);
            assert_eq!(random.decrypt_buffer(&CIPHERTEXT).unwrap(), &PLAINTEXT);
        }
    }
}

pub use mersenne_twister::Mt19337;
