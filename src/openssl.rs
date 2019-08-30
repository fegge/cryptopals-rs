
#[derive(Debug)]
pub enum Error {
    InvalidKeySize 
}


pub mod aes {
    use libc::{c_int, c_uchar};
    use super::Error;

    const AES_MAX_NR: usize = 14;
    pub const AES_KEY_SIZE: usize = 16;
    pub const AES_BLOCK_SIZE: usize = 16;

    #[repr(C)]
    pub struct AES_KEY {
        rd_key: [u32; 4 *(AES_MAX_NR + 1)],
        rounds: i32,    
    }

    #[link(name = "crypto")]
    extern "C" {
        #[must_use]
        fn AES_set_encrypt_key(user_key: *const c_uchar, bits: c_int, key: *mut AES_KEY) -> c_int;

        #[must_use]
        fn AES_set_decrypt_key (user_key: *const c_uchar, bits: c_int, key: *mut AES_KEY) -> c_int;
    
        fn AES_encrypt(input: *const c_uchar, output: *mut c_uchar, key: *const AES_KEY);
        
        fn AES_decrypt(input: *const c_uchar, output: *mut c_uchar, key: *const AES_KEY);
    }
    
    impl Default for AES_KEY {
        fn default() -> Self {
            Self {
                rd_key: [0; 4 * (AES_MAX_NR + 1)],
                rounds: 0
            }
            
        }
    }

    impl AES_KEY {
        pub fn new_encrypt_key(raw_key: &[u8]) -> Result<Self, Error> {
            let key_size = 8 * raw_key.len() as c_int;
            let mut encrypt_key = Default::default();
            let error_code = unsafe {
                AES_set_encrypt_key(raw_key.as_ptr(), key_size, &mut encrypt_key)
            };
            if error_code != 0 {
                return Err(Error::InvalidKeySize);
            }
            Ok(encrypt_key)
        }
        
        pub fn new_decrypt_key(raw_key: &[u8]) -> Result<Self, Error> {
            let key_size = 8 * raw_key.len() as c_int;
            if key_size != 128 && key_size != 192 && key_size != 256 {
                return Err(Error::InvalidKeySize)
            }
            let mut decrypt_key = Default::default();
            let error_code = unsafe {
                AES_set_decrypt_key(raw_key.as_ptr(), key_size, &mut decrypt_key)
            };
            if error_code != 0 {
                return Err(Error::InvalidKeySize);
            }
            Ok(decrypt_key)
        }
    }
   
    pub fn encrypt_block<'a>(input_block: &[u8], output_block: &'a mut [u8], key: &AES_KEY) -> &'a [u8] {
        unsafe {
            AES_encrypt(input_block.as_ptr(), output_block.as_mut_ptr(), key);
        }
        output_block
    }

    pub fn decrypt_block<'a>(input_block: &[u8], output_block: &'a mut [u8], key: &AES_KEY) -> &'a [u8] {
        unsafe {
            AES_decrypt(input_block.as_ptr(), output_block.as_mut_ptr(), key);
        }
        output_block
    }
    
    #[cfg(test)]
    mod tests {
        use super::*;

        const RAW_KEY: [u8; 32] = [
            0xc0, 0xfe, 0xfe, 0x00,
            0xc0, 0xfe, 0xfe, 0x01,
            0xc0, 0xfe, 0xfe, 0x02,
            0xc0, 0xfe, 0xfe, 0x03,
            0xc0, 0xfe, 0xfe, 0x04,
            0xc0, 0xfe, 0xfe, 0x05,
            0xc0, 0xfe, 0xfe, 0x06,
            0xc0, 0xfe, 0xfe, 0x07
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
            let encrypt_key = AES_KEY::new_encrypt_key(&RAW_KEY);
            assert!(encrypt_key.is_ok());
            
            let encrypt_key = encrypt_key.unwrap();
            for &word in encrypt_key.rd_key.iter() {
                assert_ne!(word, 0);
            }
            assert_eq!(encrypt_key.rounds, 14);
            
            let decrypt_key = AES_KEY::new_decrypt_key(&RAW_KEY);
            assert!(decrypt_key.is_ok());

            let decrypt_key = decrypt_key.unwrap();
            for &word in decrypt_key.rd_key.iter() {
                assert_ne!(word, 0);
            }
            assert_eq!(encrypt_key.rounds, 14);
        }
    
        #[test]
        fn encrypt_test() {
            let key = AES_KEY::new_encrypt_key(&RAW_KEY).unwrap();
            let mut ciphertext = [0; AES_BLOCK_SIZE];
            encrypt_block(&PLAINTEXT, &mut ciphertext, &key);
            assert_eq!(ciphertext, CIPHERTEXT);
        }
    
        #[test]
        fn decrypt_test() {
            let key = AES_KEY::new_decrypt_key(&RAW_KEY).unwrap();
            let mut plaintext = [0; AES_BLOCK_SIZE];
            decrypt_block(&CIPHERTEXT, &mut plaintext, &key);
            assert_eq!(plaintext, PLAINTEXT);
        }
    }
}

