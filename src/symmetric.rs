pub use aes;

#[derive(Debug, PartialEq)]
pub enum Error {
    PaddingError,
    CipherError
}


pub mod ciphers {
    use super::Error;

    pub type Key = Vec<u8>;

    pub trait Cipher {
        fn new(key: &Vec<u8>) -> Self;

        fn block_size() -> usize;

        fn encrypt_block(&self, block: &mut [u8]) -> Result<&[u8], Error>; 

        fn decrypt_block(&self, block: &mut [u8]) -> Result<&[u8], Error>; 
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
}

pub mod cipher_modes {
    use super::Error;
    use super::ciphers::{Cipher, Key};
    use super::padding_modes::PaddingMode;
    
    pub type Iv = Vec<u8>;

    pub trait CipherMode {
        fn new(key: &Key, iv: &Iv) -> Self;
        
        fn encrypt_buffer<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error>;

        fn decrypt_buffer<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error>;
    }

    pub struct Cbc<C: Cipher, P: PaddingMode> {
        cipher: C,
        padding: P,
        iv: Iv
    }

    impl<C: Cipher, P: PaddingMode> Cbc<C, P> {
        fn xor_blocks<'a>(lhs: &'a mut [u8], rhs: &[u8]) -> &'a [u8] {
            lhs.iter_mut().zip(rhs).for_each(|(x, y)| {
                *x ^= y;
            });
            lhs
        }
    }

    impl<C: Cipher, P: PaddingMode> CipherMode for Cbc<C, P> {
        fn new(key: &Vec<u8>, iv: &Vec<u8>) -> Self {
            Self { 
                cipher: C::new(&key), 
                padding: P::new(C::block_size()),
                iv: iv.clone(),
            }
        }
        
        fn encrypt_buffer<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error> {
            self.padding.pad_buffer(buffer)?;
            for mut block in buffer.chunks_mut(C::block_size()) {
                Self::xor_blocks(&mut block, &self.iv);
                if let Err(error) = self.cipher.encrypt_block(block) {
                    return Err(error) 
                }
                self.iv = block.to_owned();
            }
            Ok(buffer)
        }

        fn decrypt_buffer<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error> {
            for mut block in buffer.chunks_mut(C::block_size()) {
                let iv = block.to_owned();
                match self.cipher.decrypt_block(&mut block) {
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

#[cfg(test)]
mod tests {

    mod padding {
        use crate::symmetric::Error;
        use crate::symmetric::padding_modes::{PaddingMode, Pkcs7};
        
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
