pub mod ecb_cbc_detection {
    use rand;
    use rand::Rng;

    use crate::crypto::symmetric;

    use symmetric::padding_modes::{PaddingMode, Pkcs7};
    use symmetric::cipher_modes::{CipherMode, Ecb, Cbc};
    use symmetric::ciphers::{Cipher, Aes128};
    use symmetric::Error;

    type Aes128Ecb = Ecb<Aes128, Pkcs7>;
    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Mode {
        Ecb,
        Cbc
    }

    pub struct Oracle { 
        cipher_mode: Option<Mode>
    }

    impl Oracle {
        pub fn new() -> Self {
            Self {
                cipher_mode: None
            }
        }

        fn flip_coin() -> bool {
            rand::thread_rng().gen_bool(0.5)
        }

        fn get_ecb_mode() -> Result<Aes128Ecb, Error> {
            let key: Vec<u8> = (0..Aes128::KEY_SIZE).map(|_| { rand::random() }).collect();
            Aes128Ecb::new(&key)
        }

        fn get_cbc_mode() -> Result<Aes128Cbc, Error> {
            let key: Vec<u8> = (0..Aes128::KEY_SIZE).map(|_| { rand::random() }).collect();
            let iv: Vec<u8> = (0..Aes128::BLOCK_SIZE).map(|_| { rand::random() }).collect();
            Aes128Cbc::new(&key, &iv)
        }

        fn pad_buffer(buffer: &[u8]) -> Vec<u8> {
            // Ensure there is enough space for the random prefix, random suffix and PKCS7 padding.
            let maximum_size = 10 + buffer.len() + 10 + Aes128::BLOCK_SIZE;
            let mut padded_buffer = Vec::with_capacity(maximum_size);

            let prefix_size = rand::thread_rng().gen_range(5, 11);
            for _ in 0..prefix_size {
                padded_buffer.push(rand::random());    
            }
            padded_buffer.extend(buffer);

            let suffix_size = rand::thread_rng().gen_range(5, 11);
            for _ in 0..suffix_size {
                padded_buffer.push(rand::random());    
            }
            padded_buffer
        }

        pub fn encrypt_buffer(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
            // Encrypts the padded buffer inplace to avoid allocating a second vector for the result.
            let mut output_buffer = Self::pad_buffer(&buffer);
            let output_size = output_buffer.len();
            let padding_size = Pkcs7::min_padding_size(Aes128::BLOCK_SIZE, output_size);
            output_buffer.resize(output_size + padding_size, 0);

            if Self::flip_coin() {
                let mut cipher_mode = Self::get_ecb_mode()?;
                cipher_mode.encrypt_inplace(&mut output_buffer, output_size)?;
                self.cipher_mode = Some(Mode::Ecb);
            } else {
                let mut cipher_mode = Self::get_cbc_mode()?;
                cipher_mode.encrypt_inplace(&mut output_buffer, output_size)?;
                self.cipher_mode = Some(Mode::Cbc);
            }
            Ok(output_buffer)
        }

        pub fn cipher_mode(&self) -> Option<Mode> { self.cipher_mode }
    }

    impl Default for Oracle {
        fn default() -> Self {
            Self::new()
        }
    }
}
