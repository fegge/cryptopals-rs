#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    PaddingError,
    CipherError,
}


pub mod ciphers {
    use super::Error;
    use crate::crypto::openssl;
    use crate::crypto::openssl::aes;

    pub type Key = [u8];

    pub trait Cipher: Sized {
        const KEY_SIZE: usize;
        const BLOCK_SIZE: usize;

        fn new(raw_key: &Key) -> Result<Self, Error>;

        // TODO: encrypt_block should take a block of size Self::BLOCK_SIZE.
        fn encrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error>; 

        // TODO: decrypt_block should take a block of size Self::BLOCK_SIZE.
        fn decrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error>; 
    }
    
    impl From<openssl::Error> for Error {
        fn from(_: openssl::Error) -> Self {
            Error::CipherError
        }
    }

    pub struct Aes128 {
        encrypt_key: aes::AES_KEY,
        decrypt_key: aes::AES_KEY
    }
    
    impl Cipher for Aes128 {
        const KEY_SIZE: usize = 16;
        const BLOCK_SIZE: usize = aes::AES_BLOCK_SIZE;
        
        fn new(raw_key: &Key) -> Result<Self, Error> {
            if raw_key.len() != Self::KEY_SIZE {
                return Err(Error::CipherError)
            }
            let encrypt_key = aes::AES_KEY::new_encrypt_key(raw_key)?;
            let decrypt_key = aes::AES_KEY::new_decrypt_key(raw_key)?;
            
            Ok(Aes128 {
                encrypt_key,
                decrypt_key
            })
        }

        // TODO: encrypt_block should take a block of size Self::BLOCK_SIZE.
        fn encrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error> { 
            aes::encrypt_block(block, &self.encrypt_key);
            Ok(block)
        }

        // TODO: decrypt_block should take a block of size Self::BLOCK_SIZE.
        fn decrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error> {
            aes::decrypt_block(block, &self.decrypt_key);
            Ok(block)
        }
    }

    pub struct Aes256 {
        encrypt_key: aes::AES_KEY,
        decrypt_key: aes::AES_KEY
    }
    
    impl Cipher for Aes256 {
        const KEY_SIZE: usize = 32;
        const BLOCK_SIZE: usize = aes::AES_BLOCK_SIZE;
        
        fn new(raw_key: &Key) -> Result<Self, Error> {
            if raw_key.len() != Self::KEY_SIZE {
                return Err(Error::CipherError)
            }
            let encrypt_key = aes::AES_KEY::new_encrypt_key(raw_key)?;
            let decrypt_key = aes::AES_KEY::new_decrypt_key(raw_key)?;
            
            Ok(Aes256 {
                encrypt_key,
                decrypt_key
            })
        }

        // TODO: encrypt_block should take a block of size Self::BLOCK_SIZE.
        fn encrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error> { 
            aes::encrypt_block(block, &self.encrypt_key);
            Ok(block)
        }

        // TODO: decrypt_block should take a block of size Self::BLOCK_SIZE.
        fn decrypt_block<'a>(&self, block: &'a mut [u8]) -> Result<&'a [u8], Error> {
            aes::decrypt_block(block, &self.decrypt_key);
            Ok(block)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const RAW_KEY_128: [u8; Aes128::KEY_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const PLAINTEXT_128: [u8; Aes128::BLOCK_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const CIPHERTEXT_128: [u8; Aes128::BLOCK_SIZE] = [
            0xf0, 0xf7, 0x98, 0x06, 
            0xed, 0xd2, 0xed, 0x54, 
            0x9d, 0x0a, 0x8b, 0xfe, 
            0x5e, 0x56, 0xdc, 0xbd
        ];

        const RAW_KEY_256: [u8; Aes256::KEY_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
            0xc0, 0xfe, 0xfe, 0x04,
            0xc0, 0xfe, 0xfe, 0x05,
            0xc0, 0xfe, 0xfe, 0x06,
            0xc0, 0xfe, 0xfe, 0x07,
        ];
        
        const PLAINTEXT_256: [u8; Aes256::BLOCK_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const CIPHERTEXT_256: [u8; Aes256::BLOCK_SIZE] = [
            0xbd, 0xe3, 0x5d, 0x23,
            0x5d, 0x45, 0x12, 0xcb,
            0x58, 0x31, 0xdc, 0x7a,
            0x81, 0xbf, 0x57, 0x2d
        ];

        #[test]
        fn key_aes_128() {
            assert!(Aes128::new(&[0; Aes128::KEY_SIZE]).is_ok());
            assert!(Aes128::new(&[0; Aes128::KEY_SIZE + 1]).is_err());
        }

        #[test]
        fn encrypt_aes_128() {
            let aes = Aes128::new(&RAW_KEY_128).unwrap();

            let mut block = PLAINTEXT_128.clone();
            assert!(aes.encrypt_block(&mut block).is_ok());

            assert_eq!(block, CIPHERTEXT_128);
        }
    
        #[test]
        fn decrypt_aes_128() {
            let aes = Aes128::new(&RAW_KEY_128).unwrap();

            let mut block = CIPHERTEXT_128.clone();
            assert!(aes.decrypt_block(&mut block).is_ok());

            assert_eq!(block, PLAINTEXT_128);
        }
        
        #[test]
        fn key_aes_256() {
            assert!(Aes256::new(&[0; Aes256::KEY_SIZE]).is_ok());
            assert!(Aes256::new(&[0; Aes256::KEY_SIZE + 1]).is_err());
        }

        #[test]
        fn encrypt_aes_256() {
            let aes = Aes256::new(&RAW_KEY_256).unwrap();

            let mut block = PLAINTEXT_256.clone();
            assert!(aes.encrypt_block(&mut block).is_ok());

            assert_eq!(block, CIPHERTEXT_256);
        }
    
        #[test]
        fn decrypt_aes_256() {
            let aes = Aes256::new(&RAW_KEY_256).unwrap();

            let mut block = CIPHERTEXT_256.clone();
            assert!(aes.decrypt_block(&mut block).is_ok());

            assert_eq!(block, PLAINTEXT_256);
        }
    }
}


pub mod padding_modes {
    use super::Error;

    pub trait PaddingMode {
        fn new(block_size: usize) -> Self;

        fn pad_buffer<'a>(&self, buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error>;
        
        fn unpad_buffer<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;
    }

    pub struct Pkcs7 {}

    impl Pkcs7 {
        fn set_bytes(buffer: &mut [u8], value: u8) {
            for byte in buffer { *byte = value; }
        }
    }

    impl PaddingMode for Pkcs7 {
        fn new(_: usize) -> Self {
            Self {}
        }
        
        fn pad_buffer<'a>(&self, buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            if buffer.len() <= size || buffer.len() > size + 255 {
                return Err(Error::PaddingError);
            }
            let padding_size = buffer.len() - size;
            Pkcs7::set_bytes(&mut buffer[size..], padding_size as u8);
            Ok(buffer)
        }

        fn unpad_buffer<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            if let Some(&last_byte) = buffer.last() {
                let padding_size = last_byte as usize;
                if padding_size > buffer.len() {
                    return Err(Error::PaddingError);
                }
                let buffer: &'a [u8] = &buffer[..(buffer.len() - padding_size)];
                return Ok(buffer);
            }
            Err(Error::PaddingError)
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::crypto::symmetric::Error;
        use super::{PaddingMode, Pkcs7};
        
        #[test]
        fn valid_padding() {
            let pkcs7 = Pkcs7::new(8);
            let mut buffer: [u8; 8] = [4, 5, 6, 7, 0, 0, 0, 0];

            let result = pkcs7.pad_buffer(&mut buffer, 4);
            assert!(result.is_ok());
            assert_eq!(buffer[4..], [4; 4]);

            let result = pkcs7.unpad_buffer(&mut buffer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), [4, 5, 6, 7]);

            let mut buffer = [0; 8];

            let result = pkcs7.pad_buffer(&mut buffer, 0);
            assert!(result.is_ok());
            assert_eq!(buffer, [8; 8]);
        }

        #[test]
        fn invalid_padding() {
            let pkcs7 = Pkcs7::new(8);
            let mut buffer: [u8; 4] = [4, 5, 6, 7];
            
            let result = pkcs7.unpad_buffer(&mut buffer);
            assert_eq!(result, Err(Error::PaddingError));
        }

        #[test]
        fn known_output() {
            let pkcs7 = Pkcs7::new(20);
            let mut buffer: Vec<u8> = Vec::with_capacity(20);
            buffer.extend("YELLOW SUBMARINE".as_bytes());
            buffer.resize(20, 0);

            let result = pkcs7.pad_buffer(&mut buffer, 16);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
        }
    }
}


pub mod cipher_modes {
    use super::Error;
    use super::ciphers::{Cipher, Key};
    use super::padding_modes::PaddingMode;
    
    pub type Iv = [u8];

    pub trait CipherMode<C: Cipher, P: PaddingMode>: Sized {
        fn encrypt_buffer<'a>(&mut self, buffer: &'a mut [u8], end: usize) -> Result<&'a [u8], Error>;

        fn decrypt_buffer<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;
    }

    pub struct Ecb<C: Cipher, P: PaddingMode> {
        cipher: C,
        padding: P
    }

    impl<C: Cipher, P: PaddingMode> Ecb<C, P> {
        pub fn new(key: &Key) -> Result<Self, Error> {
            Ok(Self { 
                cipher: C::new(&key)?, 
                padding: P::new(C::BLOCK_SIZE)
            })
        }
    }

    impl<C: Cipher, P: PaddingMode> CipherMode<C, P> for Ecb<C, P> {
        fn encrypt_buffer<'a>(&mut self, mut buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            self.padding.pad_buffer(&mut buffer, size)?;
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                self.cipher.encrypt_block(&mut block)?;
            }
            Ok(buffer)
        }

        fn decrypt_buffer<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                self.cipher.decrypt_block(&mut block)?;
            }
            self.padding.unpad_buffer(buffer)
        }
    }

    pub struct Cbc<C: Cipher, P: PaddingMode> {
        cipher: C,
        padding: P,
        iv: Vec<u8>
    }

    impl<C: Cipher, P: PaddingMode> Cbc<C, P> {
        pub fn new(key: &Key, iv: &Iv) -> Result<Self, Error> {
            if iv.len() != C::BLOCK_SIZE {
                return Err(Error::CipherError)
            }
            Ok(Self { 
                cipher: C::new(&key)?, 
                padding: P::new(C::BLOCK_SIZE),
                iv: iv.to_owned(),
            })
        }
        
        fn xor_blocks<'a>(lhs: &'a mut [u8], rhs: &[u8]) -> &'a [u8] {
            lhs.iter_mut().zip(rhs).for_each(|(x, y)| {
                *x ^= y;
            });
            lhs
        }
    }

    impl<C: Cipher, P: PaddingMode> CipherMode<C, P> for Cbc<C, P> {
        fn encrypt_buffer<'a>(&mut self, mut buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            self.padding.pad_buffer(&mut buffer, size)?;
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                Self::xor_blocks(&mut block, &self.iv);
                self.cipher.encrypt_block(&mut block)?;
                self.iv = block.to_owned();
            }
            Ok(buffer)
        }

        fn decrypt_buffer<'a>(&mut self, mut buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            for mut block in (&mut buffer).chunks_mut(C::BLOCK_SIZE) {
                let next_iv = block.to_owned();
                match self.cipher.decrypt_block(&mut block) {
                    Ok(_) => { 
                        Self::xor_blocks(&mut block, &self.iv); 
                        self.iv = next_iv;
                    }
                    Err(error) => { return Err(error) }
                }
            }
            self.padding.unpad_buffer(buffer)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::symmetric::padding_modes::Pkcs7;
        use crate::crypto::symmetric::ciphers::{Cipher, Aes128};

        type Aes128Ecb = Ecb<Aes128, Pkcs7>;
        type Aes128Cbc = Cbc<Aes128, Pkcs7>;

        const RAW_KEY: [u8; Aes128::KEY_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];

        const RAW_IV: [u8; Aes128::BLOCK_SIZE] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
        ];
        
        const PLAINTEXT: [u8; 19] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
            0xc0, 0xfe, 0xfe
        ];

        const ECB_CIPHERTEXT: [u8; 2 * Aes128::BLOCK_SIZE] = [
            0xf0, 0xf7, 0x98, 0x06,
            0xed, 0xd2, 0xed, 0x54,
            0x9d, 0x0a, 0x8b, 0xfe,
            0x5e, 0x56, 0xdc, 0xbd,
            0x47, 0xf6, 0x43, 0xd1,
            0x3c, 0xcc, 0x0a, 0xa5,
            0xc3, 0x5b, 0x0d, 0xcf,
            0xde, 0xfc, 0xf3, 0x8f
        ];

        const CBC_CIPHERTEXT: [u8; 2 * Aes128::BLOCK_SIZE] = [
            0x10, 0xce, 0x66, 0xaf,
            0x7a, 0x70, 0x51, 0x01,
            0x19, 0xa2, 0x27, 0x95,
            0x3a, 0x14, 0x71, 0x4d,
            0x83, 0xbc, 0xd0, 0x4d,
            0xfc, 0x8a, 0xc3, 0xca,
            0x6d, 0x08, 0x12, 0xb8,
            0x69, 0x90, 0x8f, 0xec
        ];

        #[test]
        fn encrypt_ecb_mode() {
            let cipher = Aes128Ecb::new(&RAW_KEY);
            
            assert!(cipher.is_ok());
            let mut cipher = cipher.unwrap();
            
            let mut buffer = Vec::with_capacity(2 * Aes128::BLOCK_SIZE);
            buffer.extend(&PLAINTEXT);
            buffer.resize(2 * Aes128::BLOCK_SIZE, 0);
            let result = cipher.encrypt_buffer(&mut buffer, PLAINTEXT.len());
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ECB_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_ecb_mode() {
            let cipher = Aes128Ecb::new(&RAW_KEY);
            
            assert!(cipher.is_ok());
            let mut cipher = cipher.unwrap();
            
            let mut buffer = ECB_CIPHERTEXT.clone();
            let result = cipher.decrypt_buffer(&mut buffer);
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), PLAINTEXT);
        }
        
        #[test]
        fn encrypt_cbc_mode() {
            let cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV);
            
            assert!(cipher.is_ok());
            let mut cipher = cipher.unwrap();
            
            let mut buffer = Vec::with_capacity(2 * Aes128::BLOCK_SIZE);
            buffer.extend(&PLAINTEXT);
            buffer.resize(2 * Aes128::BLOCK_SIZE, 0);
            let result = cipher.encrypt_buffer(&mut buffer, PLAINTEXT.len());
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), CBC_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_cbc_mode() {
            let cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV);
            
            assert!(cipher.is_ok());
            let mut cipher = cipher.unwrap();
            
            let mut buffer = CBC_CIPHERTEXT.clone();
            let result = cipher.decrypt_buffer(&mut buffer);
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), PLAINTEXT);
        }
    }
}

