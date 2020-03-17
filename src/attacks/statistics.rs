pub mod single_byte_xor {
    use std::string::FromUtf8Error;

    use crate::dist;
    use crate::math::optimization::Minimize;
    use crate::math::statistics::Distribution;
    
    #[derive(Debug)]
    pub enum Error {
        RecoveryError,
        DecodingError
    }

    impl std::convert::From<FromUtf8Error> for Error {
        fn from(_: FromUtf8Error) -> Self {
            Error::DecodingError
        }
    }

    // English lowercase monogram statistics.
    fn get_monogram_statistics() -> Distribution<u8> {
        dist!(
            b'a' => 8.167,
            b'b' => 1.492,
            b'c' => 2.202,
            b'd' => 4.253,
            b'e' => 12.702,
            b'f' => 2.228,
            b'g' => 2.015,
            b'h' => 6.094,
            b'i' => 6.966,
            b'j' => 0.153,
            b'k' => 1.292,
            b'l' => 4.025,
            b'm' => 2.406,
            b'n' => 6.749,
            b'o' => 7.507,
            b'p' => 1.929,
            b'q' => 0.095,
            b'r' => 5.987,
            b's' => 6.327,
            b't' => 9.356,
            b'u' => 2.758,
            b'v' => 0.978,
            b'w' => 2.560,
            b'x' => 0.150, 
            b'y' => 1.994,
            b'z' => 0.077
        )
    }

    fn decrypt(key: u8, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.iter().map(|byte| key ^ byte).collect::<Vec<u8>>()
    }

    fn score(plaintext: &[u8], distribution: &Distribution<u8>) -> f64 {
        plaintext
            .iter()
            .collect::<Distribution<u8>>()
            .distance_from(distribution)
    }
    
    pub fn recover_plaintext(ciphertext: &[u8]) -> Result<String, Error> {
        let distribution = get_monogram_statistics();
        let result = (0..=255)
            .map(|key|
                decrypt(key, &ciphertext)
            )
            .minimize(|plaintext|
                // We should really convert the plaintext to lowercase before scoring, but YOLO.
                score(&plaintext, &distribution)
            );
       
        Ok(String::from_utf8(result.0)?)
    }
}

pub mod detect_single_byte_xor {
    use super::single_byte_xor;
    use single_byte_xor::Error;
    use crate::math::optimization::Minimize;
    use crate::math::statistics::Distribution;

    fn score(ciphertext: &[u8]) -> f64 {
        ciphertext
            .iter()
            .collect::<Distribution<u8>>()
            .entropy()
    }

    pub fn recover_plaintext(ciphertexts: &[Vec<u8>]) -> Result<String, Error> {
        let result = ciphertexts
            .iter()
            .minimize(|ciphertext|
                score(ciphertext)
            );
        single_byte_xor::recover_plaintext(result.0)
    }
}
