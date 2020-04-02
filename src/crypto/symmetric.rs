use std::string::FromUtf8Error;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    DecodingError,
    PaddingError,
    CipherError,
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Self {
        Error::DecodingError
    }
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

        // TODO: encrypt_mut should take a block of size Self::BLOCK_SIZE.
        fn encrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8]; 

        // TODO: decrypt_mut should take a block of size Self::BLOCK_SIZE.
        fn decrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8]; 
        
        // TODO: encrypt_block should take a block of size Self::BLOCK_SIZE.
        fn encrypt_block(&self, block: &[u8]) -> Vec<u8> {
            let mut block = block.to_owned();
            self.encrypt_mut(&mut block);
            block
        }

        // TODO: decrypt_block should take a block of size Self::BLOCK_SIZE.
        fn decrypt_block(&self, block: &[u8]) -> Vec<u8> {
            let mut block = block.to_owned();
            self.decrypt_mut(&mut block);
            block
        }
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

        fn encrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8] { 
            aes::encrypt_mut(block, &self.encrypt_key);
            block
        }

        fn decrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8] {
            aes::decrypt_mut(block, &self.decrypt_key);
            block
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
        fn encrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8] { 
            aes::encrypt_mut(block, &self.encrypt_key);
            block
        }

        // TODO: decrypt_block should take a block of size Self::BLOCK_SIZE.
        fn decrypt_mut<'a>(&self, block: &'a mut [u8]) -> &'a [u8] {
            aes::decrypt_mut(block, &self.decrypt_key);
            block
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

            aes.encrypt_mut(&mut block);
            assert_eq!(block, CIPHERTEXT_128);
            assert_eq!(aes.encrypt_block(&PLAINTEXT_128), CIPHERTEXT_128);
        }
    
        #[test]
        fn decrypt_aes_128() {
            let aes = Aes128::new(&RAW_KEY_128).unwrap();
            let mut block = CIPHERTEXT_128.clone();

            aes.decrypt_mut(&mut block);
            assert_eq!(block, PLAINTEXT_128);
            assert_eq!(aes.decrypt_block(&CIPHERTEXT_128), PLAINTEXT_128);
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
            
            aes.encrypt_mut(&mut block);
            assert_eq!(block, CIPHERTEXT_256);
            assert_eq!(aes.encrypt_block(&PLAINTEXT_256), CIPHERTEXT_256);
        }
    
        #[test]
        fn decrypt_aes_256() {
            let aes = Aes256::new(&RAW_KEY_256).unwrap();
            let mut block = CIPHERTEXT_256.clone();
            
            aes.decrypt_mut(&mut block);
            assert_eq!(block, PLAINTEXT_256);
            assert_eq!(aes.decrypt_block(&CIPHERTEXT_256), PLAINTEXT_256);
        }
    }
}

pub use ciphers::{
    Cipher, 
    Aes128, 
    Aes256
};

pub mod padding_modes {
    use super::Error;

    pub trait PaddingMode {
        fn new(block_size: usize) -> Self;
        
        fn min_padding_size(block_size: usize, buffer_size: usize) -> usize {
            block_size - (buffer_size % block_size)
        }

        fn block_size(&self) -> usize;

        fn pad_mut<'a>(&self, buffer: &'a mut [u8], end: usize) -> Result<&'a [u8], Error>;
        
        fn unpad_mut(&self, buffer: &[u8]) -> Result<usize, Error>;

        fn pad_buffer<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error> {
            let buffer_size = buffer.len();
            buffer.resize(buffer_size + Self::min_padding_size(self.block_size(), buffer_size), 0);
            self.pad_mut(buffer, buffer_size)?;
            Ok(buffer)
        }
        
        fn unpad_buffer<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a Vec<u8>, Error> {
            let buffer_size = self.unpad_mut(buffer)?;
            buffer.truncate(buffer_size);
            Ok(buffer)
        }
    }

    pub struct Pkcs7 {
        block_size: usize
    }

    impl Pkcs7 {
        fn set_bytes(buffer: &mut [u8], value: u8) {
            for byte in buffer { *byte = value; }
        }

        fn validate_padding(buffer: &[u8], padding_size: usize) -> bool {
            0 < padding_size && padding_size <= buffer.len() && buffer
                .iter()
                .rev()
                .take(padding_size)
                .all(|byte| *byte as usize == padding_size)
        }
    }

    impl PaddingMode for Pkcs7 {
        fn new(block_size: usize) -> Self {
            Self { block_size }
        }

        fn block_size(&self) -> usize { self.block_size }
        
        fn pad_mut<'a>(&self, buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            if buffer.len() <= size || buffer.len() > size + 255 {
                return Err(Error::PaddingError);
            }
            let padding_size = buffer.len() - size;
            Pkcs7::set_bytes(&mut buffer[size..], padding_size as u8);
            Ok(buffer)
        }

        fn unpad_mut(&self, buffer: &[u8]) -> Result<usize, Error> {
            if let Some(&last_byte) = buffer.last() {
                let padding_size = last_byte as usize;
                if !Pkcs7::validate_padding(buffer, padding_size) {
                    return Err(Error::PaddingError);
                }
                return Ok(buffer.len() - padding_size);
            }
            Err(Error::PaddingError)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{PaddingMode, Pkcs7};
       
        #[test]
        fn padding_size() {
            assert_eq!(Pkcs7::min_padding_size(8, 5), 3);
            assert_eq!(Pkcs7::min_padding_size(8, 8), 8);
        }

        #[test]
        fn valid_padding() {
            let pkcs7 = Pkcs7::new(8);

            let mut buffer: [u8; 8] = [4, 5, 6, 7, 8, 0, 0, 0];
            let result = pkcs7.pad_mut(&mut buffer, 5);
            assert!(result.is_ok());
            assert_eq!(buffer[5..], [3; 3]);

            let result = pkcs7.unpad_mut(&buffer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 5);

            let mut buffer = [0; 8];
            let result = pkcs7.pad_mut(&mut buffer, 0);
            assert!(result.is_ok());
            assert_eq!(buffer, [8; 8]);

            let mut buffer = vec![4, 5, 6, 7, 8];
            let result = pkcs7.pad_buffer(&mut buffer);
            assert!(result.is_ok());
            assert_eq!(buffer[5..], [3; 3]);
            
            let result = pkcs7.unpad_buffer(&mut buffer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), &vec![4u8, 5u8, 6u8, 7u8, 8u8]);
            assert_eq!(buffer, vec![4, 5, 6, 7, 8]);
        }

        #[test]
        fn invalid_padding() {
            let pkcs7 = Pkcs7::new(8);
            let mut buffer: [u8; 4] = [1, 2, 3, 4];
            
            let result = pkcs7.pad_mut(&mut buffer, 4);
            assert!(result.is_err());

            let result = pkcs7.unpad_mut(&mut buffer);
            assert!(result.is_err());

            let result = pkcs7.unpad_mut(&mut [3, 2, 1, 0]);
            assert!(result.is_err());
        }
    }
}

pub use padding_modes::{
    PaddingMode,
    Pkcs7
};

pub mod cipher_modes {
    use rand;
    use rand::Rng;

    use super::Error;
    use super::ciphers::{Cipher, Key};
    use super::padding_modes::PaddingMode;

    use crate::crypto::random::Random;

    pub type Iv = [u8];
    pub type Nonce = [u8];

    /// Block cipher mode trait.
    pub trait BlockCipherMode<C: Cipher, P: PaddingMode>: Sized {

        /// Pad and encrypt a mutable buffer in-place. Returns a reference to the buffer.
        fn encrypt_mut<'a>(&mut self, buffer: &'a mut [u8], end: usize) -> Result<&'a [u8], Error>;

        /// Decrypt a mutable buffer in-place. Returns the buffer size after unpadding.
        fn decrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<usize, Error>;
        
        fn encrypt_buffer(&mut self, input_buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let padding_size = P::min_padding_size(C::BLOCK_SIZE, input_buffer.len());
            let mut output_buffer = Vec::with_capacity(input_buffer.len() + padding_size);
            output_buffer.extend_from_slice(input_buffer);
            output_buffer.resize(input_buffer.len() + padding_size, 0);
            self.encrypt_mut(&mut output_buffer, input_buffer.len())?;
            Ok(output_buffer)
        }

        fn decrypt_buffer(&mut self, input_buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let mut output_buffer = input_buffer.to_vec();
            let output_size = self.decrypt_mut(&mut output_buffer)?;
            output_buffer.truncate(output_size);
            Ok(output_buffer)
        }

        fn encrypt_str(&mut self, input_str: &str) -> Result<Vec<u8>, Error> {
            self.encrypt_buffer(input_str.as_bytes())
        }

        fn decrypt_str(&mut self, input_buffer: &[u8]) -> Result<String, Error> {
            let output_buffer = self.decrypt_buffer(input_buffer)?;
            String::from_utf8(output_buffer).map_err(Error::from)
        }
    }
    
    /// Generic ECB-mode type.
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

    impl<C: Cipher, P: PaddingMode> Random for Ecb<C, P> {
        fn random() -> Self {
            let key: Vec<u8> = (0..C::KEY_SIZE).map(|_| { rand::random() }).collect();
            // It is safe to call unwrap here since `new` only returns an error if the 
            // key is of the wrong size.
            Self::new(&key).unwrap()
        }
    }

    impl<C: Cipher, P: PaddingMode> BlockCipherMode<C, P> for Ecb<C, P> {
        fn encrypt_mut<'a>(&mut self, buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            assert_eq!(buffer.len() % C::BLOCK_SIZE, 0);
            self.padding.pad_mut(buffer, size)?;
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                self.cipher.encrypt_mut(&mut block);
            }
            Ok(buffer)
        }

        fn decrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<usize, Error> {
            assert_eq!(buffer.len() % C::BLOCK_SIZE, 0);
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                self.cipher.decrypt_mut(&mut block);
            }
            self.padding.unpad_mut(buffer)
        }
    }

    /// Generic CBC-mode type.
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
        
        fn xor_mut<'a>(lhs: &'a mut [u8], rhs: &[u8]) -> &'a [u8] {
            lhs.iter_mut().zip(rhs).for_each(|(x, y)| *x ^= y);
            lhs
        }
    }

    impl<C: Cipher, P: PaddingMode> Random for Cbc<C, P> {
        fn random() -> Self {
            let key: Vec<u8> = (0..C::KEY_SIZE).map(|_| { rand::random() }).collect();
            let iv: Vec<u8> = (0..C::BLOCK_SIZE).map(|_| { rand::random() }).collect();
            // It is safe to call unwrap here since `new` only returns an error if the 
            // key or iv is of the wrong size.
            Self::new(&key, &iv).unwrap()
        }
    }

    impl<C: Cipher, P: PaddingMode> BlockCipherMode<C, P> for Cbc<C, P> {
        fn encrypt_mut<'a>(&mut self, buffer: &'a mut [u8], size: usize) -> Result<&'a [u8], Error> {
            assert_eq!(buffer.len() % C::BLOCK_SIZE, 0);
            self.padding.pad_mut(buffer, size)?;
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                Self::xor_mut(&mut block, &self.iv);
                self.cipher.encrypt_mut(&mut block);
                self.iv = block.to_owned();
            }
            Ok(buffer)
        }

        fn decrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<usize, Error> {
            assert_eq!(buffer.len() % C::BLOCK_SIZE, 0);
            for mut block in buffer.chunks_mut(C::BLOCK_SIZE) {
                let next_iv = block.to_owned();
                self.cipher.decrypt_mut(&mut block);
                Self::xor_mut(&mut block, &self.iv); 
                self.iv = next_iv;
            }
            self.padding.unpad_mut(buffer)
        }
    }

    /// Stream cipher mode trait.
    pub trait StreamCipherMode: Sized + Iterator<Item=u8> {
        /// Encrypt a mutable buffer in-place.
        fn encrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;

        /// Decrypt a mutable buffer in-place.
        fn decrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error>;
        
        fn encrypt_buffer(&mut self, input_buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let mut output_buffer = input_buffer.to_vec();
            self.encrypt_mut(&mut output_buffer)?;
            Ok(output_buffer)
        }

        fn decrypt_buffer(&mut self, input_buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let mut output_buffer = input_buffer.to_vec();
            self.decrypt_mut(&mut output_buffer)?;
            Ok(output_buffer)
        }

        fn encrypt_str(&mut self, input_str: &str) -> Result<Vec<u8>, Error> {
            self.encrypt_buffer(input_str.as_bytes())
        }

        fn decrypt_str(&mut self, input_buffer: &[u8]) -> Result<String, Error> {
            let output_buffer = self.decrypt_buffer(input_buffer)?;
            String::from_utf8(output_buffer).map_err(Error::from)
        }
    }
    
    /// Generic implementation of `StreamCipherMode` for implementaions of `Iterator<Item=u8>`.
    impl<I: Iterator<Item=u8>> StreamCipherMode for I {
        fn encrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            for (x, y) in buffer.iter_mut().zip(self) {
                *x ^= y;
            }
            Ok(buffer)
        }

        fn decrypt_mut<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
            self.encrypt_mut(buffer)
        }
    }

    /// Generic CTR-mode type.
    pub struct Ctr<C: Cipher> {
        cipher: C,
        nonce: Vec<u8>,
        counter: Vec<u8>,
        key: Vec<u8>,
        offset: usize
    }

    impl<C: Cipher> Ctr<C> {
        pub fn new(key: &Key, nonce: &Nonce) -> Result<Self, Error> {
            if nonce.len() != C::BLOCK_SIZE / 2 {
                return Err(Error::CipherError)
            }
            Ok(Self { 
                cipher: C::new(&key)?,
                nonce: nonce.to_owned(),
                counter: vec![0; C::BLOCK_SIZE / 2],
                key: Vec::new(),
                offset: C::BLOCK_SIZE
            })
        }
        
        fn update_counter(&mut self) {
            for i in 0..self.counter.len() {
                let (result, overflow) = self.counter[i].overflowing_add(1);
                self.counter[i] = result;
                if !overflow { break }
            }
        }

        fn update_key(&mut self) {
            self.key = [&self.nonce[..], &self.counter[..]].concat();
            self.cipher.encrypt_mut(&mut self.key);
            self.update_counter();
        }
    }

    impl<C: Cipher> Random for Ctr<C> {
        fn random() -> Self {
            let key: Vec<u8> = (0..C::KEY_SIZE).map(|_| { rand::random() }).collect();
            let nonce: Vec<u8> = (0..(C::BLOCK_SIZE / 2)).map(|_| { rand::random() }).collect();
            // It is safe to call unwrap here since `new` only returns an error if the key or nonce
            // is of the wrong size.
            Self::new(&key, &nonce).unwrap()
        }
    }
    
    impl<C: Cipher> Iterator for Ctr<C> {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            if self.offset >= C::BLOCK_SIZE {
                self.update_key();
                self.offset = 0;
            }
            let offset = self.offset;
            self.offset += 1;
            Some(self.key[offset])
        }
    }

    /// Repeating key XOR cipher.
    pub struct RepeatingKeyXor {
        key: Vec<u8>,
        offset: usize
    }

    impl RepeatingKeyXor {
        pub fn new(key: &[u8]) -> Self {
            Self { key: key.to_owned(), offset: 0 }
        }
    }

    impl Random for RepeatingKeyXor {
        fn random() -> Self {
            let key_size = rand::thread_rng().gen_range(2, 32);
            let key: Vec<u8> = (0..key_size).map(|_| { rand::random() }).collect();
            Self { key, offset: 0 }
        }
    }

    impl Iterator for RepeatingKeyXor {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            if self.offset >= self.key.len() {
                self.offset = 0;
            }
            let offset = self.offset;
            self.offset += 1;
            Some(self.key[offset])
        }
    }

    #[cfg(test)]
    mod tests {
        use std::convert::TryInto;

        use super::*;
        use crate::crypto::symmetric::padding_modes::Pkcs7;
        use crate::crypto::symmetric::ciphers::{Cipher, Aes128};

        type Aes128Ecb = Ecb<Aes128, Pkcs7>;
        type Aes128Cbc = Cbc<Aes128, Pkcs7>;
        type Aes128Ctr = Ctr<Aes128>;

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
        
        const RAW_NONCE: [u8; Aes128::BLOCK_SIZE / 2] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
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
        
        const CTR_CIPHERTEXT: [u8; 19] = [
            0x0b, 0xb2, 0x54, 0x7f,
            0xd6, 0xdc, 0xa2, 0xcf,
            0xb6, 0x2d, 0xb0, 0xca,
            0x74, 0xa9, 0x5a, 0xed,
            0xde, 0x08, 0xd4,
        ];

        const REPEATING_KEY_CIPHERTEXT: [u8; 19] = [
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
 
        #[test]
        fn encrypt_ecb_mode() {
            let mut cipher = Aes128Ecb::new(&RAW_KEY).unwrap();
            let mut buffer = Vec::with_capacity(2 * Aes128::BLOCK_SIZE);
            buffer.extend(&PLAINTEXT);
            buffer.resize(2 * Aes128::BLOCK_SIZE, 0);
            let result = cipher.encrypt_mut(&mut buffer, PLAINTEXT.len());
            assert_eq!(result.unwrap(), ECB_CIPHERTEXT);

            let buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &ECB_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_ecb_mode() {
            let mut cipher = Aes128Ecb::new(&RAW_KEY).unwrap();
            let mut buffer = ECB_CIPHERTEXT.clone();
            let result = cipher.decrypt_mut(&mut buffer);
            assert_eq!(buffer[..result.unwrap()], PLAINTEXT);
            
            let buffer = ECB_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &PLAINTEXT);
        }
        
        #[test]
        fn encrypt_cbc_mode() {
            let mut cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV).unwrap();
            let mut buffer = Vec::with_capacity(2 * Aes128::BLOCK_SIZE);
            buffer.extend(&PLAINTEXT);
            buffer.resize(2 * Aes128::BLOCK_SIZE, 0);
            let result = cipher.encrypt_mut(&mut buffer, PLAINTEXT.len());
            assert_eq!(result.unwrap(), CBC_CIPHERTEXT);

            let mut cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV).unwrap();
            let buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &CBC_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_cbc_mode() {
            let mut cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV).unwrap();
            let mut buffer = CBC_CIPHERTEXT.clone();
            let result = cipher.decrypt_mut(&mut buffer);
            assert_eq!(buffer[..result.unwrap()], PLAINTEXT);
            
            let mut cipher = Aes128Cbc::new(&RAW_KEY, &RAW_IV).unwrap();
            let buffer = CBC_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &PLAINTEXT);
        }

        #[test]
        fn generate_counter() {
            let mut cipher = Aes128Ctr::new(&RAW_KEY, &RAW_NONCE).unwrap();
            for value in 0..=256 {
                let counter = &cipher.counter[..];
                let result = u64::from_le_bytes(counter.try_into().unwrap());
                assert_eq!(result, value as u64);
                cipher.update_counter();
            }
        }
        
        #[test]
        fn encrypt_ctr_mode() {
            let mut cipher = Aes128Ctr::new(&RAW_KEY, &RAW_NONCE).unwrap();
            let mut buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_mut(&mut buffer);
            assert_eq!(result.unwrap(), CTR_CIPHERTEXT);

            let mut cipher = Aes128Ctr::new(&RAW_KEY, &RAW_NONCE).unwrap();
            let buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &CTR_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_ctr_mode() {
            let mut cipher = Aes128Ctr::new(&RAW_KEY, &RAW_NONCE).unwrap();
            let mut buffer = CTR_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_mut(&mut buffer);
            assert_eq!(result.unwrap(), PLAINTEXT);
            
            let mut cipher = Aes128Ctr::new(&RAW_KEY, &RAW_NONCE).unwrap();
            let buffer = CTR_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &PLAINTEXT);
        }

        #[test] 
        fn encrypt_repeating_key() {
            let mut cipher = RepeatingKeyXor::new(&RAW_KEY);
            let mut buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_mut(&mut buffer);
            assert_eq!(result.unwrap(), REPEATING_KEY_CIPHERTEXT);
            
            let mut cipher = RepeatingKeyXor::new(&RAW_KEY);
            let buffer = PLAINTEXT.to_owned();
            let result = cipher.encrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &REPEATING_KEY_CIPHERTEXT);
        }
        
        #[test]
        fn decrypt_repeating_key() {
            let mut cipher = RepeatingKeyXor::new(&RAW_KEY);
            let mut buffer = REPEATING_KEY_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_mut(&mut buffer);
            assert_eq!(result.unwrap(), PLAINTEXT);
            
            let mut cipher = RepeatingKeyXor::new(&RAW_KEY);
            let buffer = REPEATING_KEY_CIPHERTEXT.to_owned();
            let result = cipher.decrypt_buffer(&buffer);
            assert_eq!(&result.unwrap(), &PLAINTEXT);
        }
    }
}

pub use cipher_modes::{
    BlockCipherMode,
    StreamCipherMode,
    RepeatingKeyXor,
    Ecb,
    Cbc,
    Ctr
};

pub type Aes128Ecb = Ecb<Aes128, Pkcs7>;
pub type Aes256Ecb = Ecb<Aes256, Pkcs7>;

pub type Aes128Cbc = Cbc<Aes128, Pkcs7>;
pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub type Aes128Ctr = Ctr<Aes128>;
pub type Aes256Ctr = Ctr<Aes256>;
