pub mod ecb_cbc_detection {
    use rand;
    use rand::Rng;

    use crate::crypto::random::Random;

    use crate::crypto::symmetric::{
        BlockCipherMode,
        PaddingMode,
        Aes128Ecb,
        Aes128Cbc,
        Cipher,
        Aes128,
        Pkcs7,
        Error,
    };

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

        fn get_ecb_mode() -> Aes128Ecb {
            Aes128Ecb::random()
        }

        fn get_cbc_mode() -> Aes128Cbc {
            Aes128Cbc::random()
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
                let mut cipher_mode = Self::get_ecb_mode();
                cipher_mode.encrypt_mut(&mut output_buffer, output_size)?;
                self.cipher_mode = Some(Mode::Ecb);
            } else {
                let mut cipher_mode = Self::get_cbc_mode();
                cipher_mode.encrypt_mut(&mut output_buffer, output_size)?;
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

pub mod simple_ecb_decryption {
    use rand;
    use rand::Rng;

    use crate::crypto::symmetric::{
        BlockCipherMode,
        PaddingMode,
        Aes128Ecb,
        Cipher,
        Aes128,
        Pkcs7,
        Error,
    };
    use crate::random_vec;
    use crate::crypto::random::Random;

    pub struct Oracle {
        cipher: Aes128Ecb,
        random_data: Vec<u8>,
        pub unknown_data: Vec<u8>,
    }

    impl Oracle {
        pub fn new(with_random_data: bool) -> Result<Self, Error> {
            let cipher = Aes128Ecb::random();
            
            let random_size = if with_random_data { 
                rand::thread_rng().gen_range(0, Aes128::BLOCK_SIZE) 
            } else { 
                0 
            };
            let random_data: Vec<u8> = random_vec!(random_size);

            let unknown_data = include_str!("../../data/set_2/problem_12.txt").replace("\n", "");
            let unknown_data = base64::decode(&unknown_data).unwrap();
            
            Ok(Oracle { cipher, random_data, unknown_data })
        }
        
        fn build_plaintext(&self, known_data: &[u8]) -> Vec<u8> {
            // Ensure there is enough space for the random prefix, unknown suffix and PKCS7 padding.
            let maximum_size = 
                self.random_data.len() + 
                known_data.len() + 
                self.unknown_data.len() + 
                Aes128::BLOCK_SIZE;
            let mut plaintext = Vec::with_capacity(maximum_size);
            
            plaintext.extend(&self.random_data);
            plaintext.extend(known_data);
            plaintext.extend(&self.unknown_data);

            plaintext
        }

        pub fn encrypt_buffer(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let mut output_buffer = self.build_plaintext(&buffer);
            let output_size = output_buffer.len();
            let padding_size = Pkcs7::min_padding_size(Aes128::BLOCK_SIZE, output_size);
            output_buffer.resize(output_size + padding_size, 0);
            self.cipher.encrypt_mut(&mut output_buffer, output_size)?;

            Ok(output_buffer)
        }
    }

}

pub mod ecb_cut_and_paste {
    use std::str::FromStr;
    
    use crate::crypto::random;
    use random::Random;

    use crate::crypto::symmetric;
    use symmetric::{BlockCipherMode, Aes128Ecb};

    #[derive(Debug)]
    pub enum Error {
        EncodingError,
        DecodingError,
        CipherError,
    }

    impl From<std::num::ParseIntError> for Error {
        fn from(_: std::num::ParseIntError) -> Self {
            Error::DecodingError
        }
    }
    
    impl From<symmetric::Error> for Error {
        fn from(_: symmetric::Error) -> Self {
            Error::CipherError
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum Role {
        User,
        Admin
    }

    impl ToString for Role {
        fn to_string(&self) -> String {
            match self {
                Role::User => String::from("user"),
                Role::Admin => String::from("admin"),
            }
        }
    }

    impl FromStr for Role {
        type Err = Error;

        fn from_str(role: &str) -> Result<Self, Self::Err> {
            match role {
                "user" => Ok(Role::User),
                "admin" => Ok(Role::Admin),
                _ => Err(Error::DecodingError)
            }
        }
    }

    pub struct Profile {
        pub email: String,
        pub uid: u64,
        pub role: Role
    }

    impl ToString for Profile {
        fn to_string(&self) -> String {
            vec![
                format!("email={}", self.email.replace("=", "%3D").replace("&", "%26")),
                format!("uid={}", self.uid),
                format!("role={}", self.role.to_string())
            ].join("&")
        }
    }

    impl FromStr for Profile {
        type Err = Error;

        fn from_str(param_str: &str) -> Result<Self, Self::Err> {
            let mut email = None;
            let mut uid = None;
            let mut role = None;
            for param in param_str.split('&') {
                let mut tokens = param.split('=');
                match (tokens.next(), tokens.next()) {
                    (Some("email"), Some(value)) => email = Some(value.to_owned()),
                    (Some("uid"), Some(value)) => uid = Some(value.parse()?),
                    (Some("role"), Some(value)) => role = Some(value.parse()?),
                    _ => return Err(Error::DecodingError)
                };
            }
            if let (Some(email), Some(uid), Some(role)) = (email, uid, role) {
                Ok(Profile { email, uid, role })
            } else {
                Err(Error::DecodingError)
            }
        }
    }

    pub struct Oracle {
        cipher: Aes128Ecb
    }

    impl Oracle {
        pub fn get_profile_for(&mut self, email: &str) -> Result<Vec<u8>, Error> {
            let profile = Profile { email: email.to_owned(), uid: 10, role: Role::User };
            self.cipher.encrypt_str(&profile.to_string()[..]).map_err(Error::from)
        }

        pub fn get_role_from(&mut self, input_buffer: &[u8]) -> Result<Role, Error> {
            let param_str = self.cipher
                .decrypt_str(input_buffer)
                .map_err(Error::from)?;
            Ok(Profile::from_str(&param_str)?.role)
        }
    }

    impl Random for Oracle {
        fn random() -> Self {
            Oracle { cipher: Aes128Ecb::random() }
        }
    }
}

pub mod cbc_bitflipping_attacks {
    use crate::crypto::symmetric::{
        BlockCipherMode,
        Aes128Cbc,
        Error,
    };
    use crate::crypto::random::Random;
   
    pub struct Oracle {
        cipher: Aes128Cbc
    }

    impl Oracle {
        pub fn encrypt_user_data(&mut self, user_data: &str) -> Result<Vec<u8>, Error> {
            let comment_1 = "comment1=cooking%20MCs";
            let comment_2 = "comment2=%20like%20a%20pound%20of%20bacon"; 
           
            let param_str = format!(
                "{};userdata={};{}",
                comment_1,
                user_data.replace(";", "%3B").replace("=", "%3D"),
                comment_2
            );
            self.cipher.encrypt_str(&param_str)
        }

        pub fn is_admin_user(&mut self, input_buffer: &[u8]) -> Result<bool, Error> {
            // Note: We cannot use `CipherMode::decrypt_str` here since that would reject any
            // buffer which didn't decode to valid UTF-8, which in turn would prevent the attack
            // we are trying to implement.
            let target_buffer = b"admin=true";
            let param_buffer = self.cipher.decrypt_buffer(input_buffer)?;
            for param_slice in param_buffer.split(|&x| x as char == ';') {
                if param_slice == target_buffer {
                    return Ok(true)
                }
            }
            Ok(false)
        }
    }

    impl Random for Oracle {
        fn random() -> Self {
            Oracle { cipher: Aes128Cbc::random() }
        }
    }
}

pub mod cbc_padding_oracle {
    use crate::crypto::symmetric::{
        BlockCipherMode,
        Aes128Cbc,
        Aes128,
        Cipher,
        Error,
    };
    use crate::random_vec;
    use crate::crypto::random::Random;

    use base64;
    use rand;
    use rand::seq::SliceRandom;

    pub struct Oracle {
        cipher: Aes128Cbc,
        iv: Vec<u8>,
    }

    impl Oracle {
        /// This method encrypts a random string with a random key and IV, and returns the
        /// encrypted buffer prefixed by the IV. (This is just for convenience since we need
        /// to concatenate the two buffers before we start the attack anyway.)
        pub fn get_encrypted_buffer(&mut self) -> Result<Vec<u8>, Error> {
            // It is safe to call unwrap here since the file is non-empty.
            let random_str = include_str!("../../data/set_3/problem_17.txt")
                .split('\n')
                .collect::<Vec<&str>>()
                .choose(&mut rand::thread_rng())
                .unwrap()
                .to_owned();
            let random_buffer = base64::decode(random_str)
                .unwrap();

            self.cipher
                .encrypt_buffer(&random_buffer)
                .map(|buffer| [&self.iv[..], &buffer[..]].concat())
        }

        pub fn verify_padding(&mut self, buffer: &[u8]) -> bool {
            // The only error returned by Aes128Cbc::decrypt_buffer is Error::PaddingError.
            self.cipher.decrypt_buffer(buffer).is_ok()
        }
    }

    impl Random for Oracle {
        fn random() -> Self {
            let key = random_vec!(Aes128::KEY_SIZE); 
            let iv = random_vec!(Aes128::BLOCK_SIZE);
            // It is okay to unwrap here since the key size is known.
            Oracle { cipher: Aes128Cbc::new(&key, &iv).unwrap(), iv }
        }
    }
}


pub mod random_access_read_write {
    use crate::crypto::symmetric::{
        Error,
        Aes128Ctr,
        StreamCipherMode,
        SeekableStreamCipherMode,
    };
    use crate::crypto::random::Random;

    pub struct Oracle {
        cipher: Aes128Ctr
    }

    impl Oracle {
        pub fn encrypt_buffer(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
            self.cipher.seek(0);
            self.cipher.encrypt_buffer(buffer)
        }

        pub fn edit_buffer(
            &mut self, 
            encrypted_buffer: &mut [u8], 
            offset: usize, 
            plaintext_buffer: &[u8]
        ) -> Result<(), Error> {
            let begin = offset;
            let end = offset + plaintext_buffer.len();
            self.cipher.seek(begin);
            
            encrypted_buffer[begin..end].copy_from_slice(plaintext_buffer);
            self.cipher.encrypt_mut(&mut encrypted_buffer[begin..end])?;
            Ok(())
        }
    }

    impl Random for Oracle {
        fn random() -> Self {
            Oracle { cipher: Aes128Ctr::random() }
        }
    }
}
