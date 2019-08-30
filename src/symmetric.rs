#[derive(Debug, PartialEq)]
pub enum Error {
    PaddingError,
    CipherError,
}


pub mod ciphers {
    use super::Error;
    use crate::openssl;
    use crate::openssl::aes;

    pub type Key = [u8];

    pub trait Cipher: Sized {
        fn new(raw_key: &Key) -> Result<Self, Error>;

        fn key_size() -> usize;

        fn block_size() -> usize;

        fn encrypt_block<'a>(&self, input_block: &[u8], output_block: &'a mut [u8]) -> Result<&'a [u8], Error>; 

        fn decrypt_block<'a>(&self, input_block: &[u8], output_block: &'a mut [u8]) -> Result<&'a [u8], Error>; 
    }

    pub struct Aes128 {
        encrypt_key: aes::AES_KEY,
        decrypt_key: aes::AES_KEY
    }
    
    impl From<openssl::Error> for Error {
        fn from(_: openssl::Error) -> Self {
            Error::CipherError
        }
    }

    impl Cipher for Aes128 {
        fn new(raw_key: &Key) -> Result<Self, Error> {
            if raw_key.len() != Self::key_size() {
                return Err(Error::CipherError)
            }
            let encrypt_key = aes::AES_KEY::new_encrypt_key(raw_key)?;
            let decrypt_key = aes::AES_KEY::new_decrypt_key(raw_key)?;
            
            Ok(Aes128 {
                encrypt_key,
                decrypt_key
            })
        }

        fn key_size() -> usize {
            return aes::AES_KEY_SIZE;
        }

        fn block_size() -> usize {
            return aes::AES_BLOCK_SIZE;
        }

        fn encrypt_block<'a>(&self, input_block: &[u8], output_block: &'a mut [u8]) -> Result<&'a [u8], Error> {
            aes::encrypt_block(&input_block, output_block, &self.encrypt_key);
            Ok(output_block)
        }

        fn decrypt_block<'a>(&self, input_block: &[u8], output_block: &'a mut [u8]) -> Result<&'a [u8], Error> {
            aes::decrypt_block(&input_block, output_block, &self.decrypt_key);
            Ok(output_block)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const RAW_KEY: [u8; 16] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const PLAINTEXT: [u8; 16] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const CIPHERTEXT: [u8; 16] = [
            0xbd, 0xe3, 0x5d, 0x23,
            0x5d, 0x45, 0x12, 0xcb,
            0x58, 0x31, 0xdc, 0x7a,
            0x81, 0xbf, 0x57, 0x2d
        ];

        #[test]
        fn key_test() {
            assert!(Aes128::new(&[0; 16]).is_ok());
            assert!(Aes128::new(&[0; 32]).is_err());
        }


        #[test]
        fn encrypt_test() {
            let aes = Aes128::new(&RAW_KEY).unwrap();

            let mut ciphertext = [0; 16];
            aes.encrypt_block(&PLAINTEXT, &mut ciphertext);

            println!("{:x?}", ciphertext);
            // assert_eq!(ciphertext, CIPHERTEXT);
        }
    
        // #[test]
        fn decrypt_test() {
        }
    }
}


pub mod padding_modes {
    use super::Error;

    pub trait PaddingMode {
        fn new(block_size: usize) -> Self;

        fn pad_buffer(&self, buffer: &mut Vec<u8>) -> Result<usize, Error>;
        
        fn unpad_buffer(&self, buffer: &mut Vec<u8>) -> Result<usize, Error>;
    }

    pub struct Pkcs7 {
        block_size: usize
    }

    impl PaddingMode for Pkcs7 {
        fn new(block_size: usize) -> Self {
            Self { block_size }
        }
        
        fn pad_buffer(&self, buffer: &mut Vec<u8>) -> Result<usize, Error> {
            let padding_size = self.block_size - (buffer.len() % self.block_size);
            if padding_size > 255 {
                return Err(Error::PaddingError);
            }
            buffer.resize(buffer.len() + padding_size, padding_size as u8);
            Ok(padding_size)
        }

        fn unpad_buffer(&self, buffer: &mut Vec<u8>) -> Result<usize, Error> {
            if let Some(&last_byte) = buffer.last() {
                let padding_size = last_byte as usize;
                if padding_size > buffer.len() {
                    return Err(Error::PaddingError);
                }
                buffer.truncate(padding_size);
                return Ok(padding_size);   
            }
            Err(Error::PaddingError)
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::symmetric::Error;
        use super::{PaddingMode, Pkcs7};
        
        #[test]
        fn length_test() {
            let pkcs7 = Pkcs7::new(8);
            let mut buffer = vec![4, 5, 6, 7];

            let result = pkcs7.pad_buffer(&mut buffer);
            assert_eq!(result, Ok(4));
            assert_eq!(buffer.len(), 8);

            let result = pkcs7.unpad_buffer(&mut buffer);
            assert_eq!(result, Ok(4));
            assert_eq!(buffer.len(), 4);

            let mut buffer = Vec::new();

            let result = pkcs7.pad_buffer(&mut buffer);
            assert_eq!(result, Ok(8));
            assert_eq!(buffer.len(), 8);
        }

        #[test]
        fn invalid_test() {
            let pkcs7 = Pkcs7::new(8);
            let mut buffer = vec![4, 5, 6, 7];
            
            let result = pkcs7.unpad_buffer(&mut buffer);
            assert_eq!(result, Err(Error::PaddingError));
        }

        #[test]
        fn value_test() {
            let pkcs7 = Pkcs7::new(20);
            let mut buffer = "YELLOW SUBMARINE".as_bytes().to_owned();
            
            let result = pkcs7.pad_buffer(&mut buffer);
            assert_eq!(result, Ok(4));
            assert_eq!(buffer, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_owned());
        }
    }
}


pub mod cipher_modes {
    use super::Error;
    use super::ciphers::{Cipher, Key};
    use super::padding_modes::PaddingMode;
    
    pub type Iv = [u8];

    pub trait CipherMode<C: Cipher, P: PaddingMode>: Sized {
        fn new(key: &Key, iv: &Iv) -> Result<Self, Error>; 
        
        fn encrypt_buffer<'a>(&mut self, input_buffer: &[u8], output_buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;

        fn decrypt_buffer<'a>(&mut self, input_buffer: &[u8], output_buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;
    }

    pub struct Cbc<C: Cipher, P: PaddingMode> {
        cipher: C,
        padding: P,
        iv: Vec<u8>
    }

    impl<C: Cipher, P: PaddingMode> Cbc<C, P> {
        fn xor_blocks<'a>(lhs: &'a mut [u8], rhs: &[u8]) -> &'a [u8] {
            lhs.iter_mut().zip(rhs).for_each(|(x, y)| {
                *x ^= y;
            });
            lhs
        }
    }

    impl<C: Cipher, P: PaddingMode> CipherMode<C, P> for Cbc<C, P> {
        fn new(key: &Key, iv: &Iv) -> Result<Self, Error> {
            if iv.len() != C::block_size() {
                return Err(Error::CipherError)
            }
            Ok(Self { 
                cipher: C::new(&key)?, 
                padding: P::new(C::block_size()),
                iv: iv.to_owned(),
            })
        }
        
        fn encrypt_buffer<'a>(&mut self, input_buffer: &[u8], output_buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            self.padding.pad_buffer(buffer)?;
            for mut block in buffer.chunks_mut(C::block_size()) {
                Self::xor_blocks(&mut block, &self.iv);
                
                self.cipher.encrypt_block(&mut block, &mut block) {
                    return Err(error) 
                }
                self.iv = block.to_owned();
            }
            Ok(buffer)
        }

        fn decrypt_buffer<'a>(&mut self, input_buffer: &[u8], output_buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            for mut block in buffer.chunks_mut(C::block_size()) {
                let iv = block.to_owned();
                match self.cipher.decrypt_block(&mut block, &mut block) {
                    Ok(_) => { 
                        Self::xor_blocks(&mut block, &self.iv); 
                        self.iv = iv;
                    }
                    Err(error) => { return Err(error) }
                }
            }
            self.padding.unpad_buffer(buffer)?;
            Ok(buffer)
        }
    }
}

