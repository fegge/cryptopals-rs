use std::string::FromUtf8Error;

use crate::crypto::symmetric;

#[derive(Debug)]
pub enum Error {
    RecoveryError,
    DecodingError,
}

impl std::convert::From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Self {
        Error::DecodingError
    }
}

impl std::convert::From<symmetric::Error> for Error {
    fn from(_: symmetric::Error) -> Self {
        Error::RecoveryError
    }
}

pub mod single_byte_xor {
    use super::Error;

    use crate::dist;
    use crate::math::optimization::Minimize;
    use crate::math::statistics::Distribution;
    
    // English lowercase monogram statistics.
    pub fn get_monogram_statistics() -> Distribution<u8> {
        dist!(
            b'a' => 0.065_173_8,
            b'b' => 0.012_424_8,
            b'c' => 0.021_733_9,
            b'd' => 0.034_983_5,
            b'e' => 0.104_144_2,
            b'f' => 0.019_788_1,
            b'g' => 0.015_861_0,
            b'h' => 0.049_288_8,
            b'i' => 0.055_809_4,
            b'j' => 0.000_903_3,
            b'k' => 0.005_052_9,
            b'l' => 0.033_149_0,
            b'm' => 0.020_212_4,
            b'n' => 0.056_451_3,
            b'o' => 0.059_630_2,
            b'p' => 0.013_764_5,
            b'q' => 0.000_860_6,
            b'r' => 0.049_756_3,
            b's' => 0.051_576_0,
            b't' => 0.072_935_7,
            b'u' => 0.022_513_4,
            b'v' => 0.008_290_3,
            b'w' => 0.017_127_2,
            b'x' => 0.001_369_2,
            b'y' => 0.014_598_4,
            b'x' => 0.000_783_6,
            b' ' => 0.191_818_2
        )
    }

    pub fn decrypt_ciphertext(key: u8, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.iter().map(|byte| key ^ byte).collect::<Vec<u8>>()
    }

    pub fn score_plaintext(plaintext: &[u8], distribution: &Distribution<u8>) -> f64 {
        plaintext
            .iter()
            .collect::<Distribution<u8>>()
            .distance_from(distribution)
    }
    
    pub fn recover_plaintext(ciphertext: &[u8]) -> Result<String, Error> {
        let distribution = get_monogram_statistics();
        let result = (0..=255)
            .map(|key|
                decrypt_ciphertext(key, &ciphertext)
            )
            .minimize(|plaintext|
                // We should really convert the plaintext to lowercase before scoring, but YOLO.
                score_plaintext(&plaintext, &distribution)
            );
       
        Ok(String::from_utf8(result.0)?)
    }
}

pub mod detect_single_byte_xor {
    use super::{single_byte_xor, Error};
    use crate::math::optimization::Minimize;
    use crate::math::statistics::Distribution;

    fn score_ciphertext(ciphertext: &[u8])  -> f64 {
        ciphertext
            .iter()
            .collect::<Distribution<u8>>()
            .entropy()
    }

    pub fn recover_plaintext(ciphertexts: &[Vec<u8>]) -> Result<String, Error> {
        let result = ciphertexts
            .iter()
            .minimize(|ciphertext|
                score_ciphertext(ciphertext)
            );
        single_byte_xor::recover_plaintext(result.0)
    }
}

pub mod repeating_key_xor {
    use super::{single_byte_xor, Error};
    
    use crate::math::optimization::Minimize;
    use crate::math::statistics::Distribution;
    
    use crate::crypto::symmetric;
    use symmetric::{RepeatingKeyXor, StreamCipherMode};

    fn hamming_distance(lhs: &[u8], rhs: &[u8]) -> u32 {
        lhs.iter().zip(rhs)
            .fold(0, |sum, (x, y)| sum + (x ^ y).count_ones())
    }

    /// Returns the average hamming distance per byte for the given key size.
    fn score_key_size(key_size: usize, ciphertext: &[u8]) -> f64 {
        let mut sum = 0;
        let mut total = 0;
        for (i, lhs) in ciphertext.chunks(key_size).enumerate() {
            for (j, rhs) in ciphertext.chunks(key_size).enumerate() {
                if i < j {
                    sum += hamming_distance(lhs, rhs);
                    total += 1;
                }
            }
        }
        (sum as f64) / ((total * key_size) as f64)
    }

    fn recover_key_byte(ciphertext: &[u8], distribution: &Distribution<u8>) -> u8 {
        (0..=255).minimize(|&key|
            single_byte_xor::decrypt_ciphertext(key, ciphertext)
                .iter()
                .collect::<Distribution<u8>>()
                .distance_from(distribution)
            ).0
    }

    pub fn recover_plaintext(ciphertext: &[u8]) -> Result<String, Error> {
        let key_size = (1..40).minimize(|&key_size|
            score_key_size(key_size, ciphertext)
        ).0;

        let mut key = Vec::new();
        let distribution = single_byte_xor::get_monogram_statistics();
        for offset in 0..key_size {
            let bytes: Vec<u8> = ciphertext
                .iter()
                .skip(offset)
                .step_by(key_size)
                .cloned()
                .collect();
            key.push(recover_key_byte(&bytes, &distribution));
        }
        let plaintext = RepeatingKeyXor::new(&key).decrypt_buffer(ciphertext)?;
        Ok(String::from_utf8(plaintext)?)
    }
}

pub mod fixed_nonce_ctr {

    pub mod using_substitutions {
    }

    pub mod using_statistics {
        use super::super::{repeating_key_xor, Error};
        use crate::math::optimization::Minimize;

        pub fn recover_plaintexts(ciphertexts: &[Vec<u8>]) -> Result<Vec<String>, Error> {
            // Compute the minimum length M and concatenate the corresponding prefixes.
            let length = ciphertexts.iter().minimize(|buffer|
                buffer.len() 
            ).1;
            let ciphertext = ciphertexts
                .iter()
                .map(|buffer| &buffer[..length])
                .collect::<Vec<&[u8]>>()
                .concat();

            // Recover the plaintext which is encrypted using a repeationg key of length M.
            let plaintext = repeating_key_xor::recover_plaintext(&ciphertext)?;
            
            // Split the resulting plaintext into chunks of length M and return the result.
            plaintext
                .as_bytes()
                .chunks(length)
                .map(|buffer| 
                     String::from_utf8(buffer.to_owned()).map_err(Error::from)
                )
                .collect()
        }
    }
}
