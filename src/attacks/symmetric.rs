pub mod ecb_cbc_detection {
    use crate::{crypto, oracles};

    use crypto::symmetric::Error;
    use crypto::symmetric::ciphers::{Cipher, Aes128};
    use oracles::symmetric::ecb_cbc_detection::Mode;
   
    // By encrypting mutiple identical blocks, we can detect ECB mode
    // since the corresponding ciphertext blocks will also be identical.
    pub fn get_cipher_mode<Oracle>(mut encrypt_buffer: Oracle) -> Result<Mode, Error>
        where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error>
    {
        let known_data = [0; 3 * Aes128::BLOCK_SIZE];
        let result = encrypt_buffer(&known_data)?;

        let mut last_block = None;
        for this_block in result.chunks(Aes128::BLOCK_SIZE) {
            if last_block.is_some() && last_block.unwrap() == this_block {
                return Ok(Mode::Ecb);
            } 
            last_block = Some(this_block);
        }
        Ok(Mode::Cbc)
    }
}


pub mod simple_ecb_decryption {
    use crate::crypto::symmetric::Error;

    fn get_known_data(suffix_size: usize, block_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(block_size);
        result.resize(block_size - (suffix_size % block_size) - 1, 0);
        result
    }

    fn get_known_data_with_suffix(suffix: &[u8], block_size: usize) -> Vec<u8> {
        let mut result = get_known_data(suffix.len(), block_size);
        result.extend(suffix);
        result
    }

    pub fn get_block_size<Oracle>(mut encrypt_buffer: Oracle) -> Result<usize, Error> 
        where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> 
    {
        for block_size in 8..=256 {
            let result = encrypt_buffer(&vec![0; 2 * block_size])?;
            let mut blocks = result.chunks(block_size);
            if blocks.next() == blocks.next() {
                // Since the input is padded, the first block will always be Some(data).
                return Ok(block_size);
            }
        }
        Err(Error::CipherError)
    }

    pub fn get_unknown_data<Oracle>(mut encrypt_buffer: Oracle) -> Result<Vec<u8>, Error> 
        where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> 
    {
        let block_size = get_block_size(|buffer| encrypt_buffer(buffer))?;
        
        let mut unknown_data = Vec::new();
        loop {
            let mut known_data = get_known_data(unknown_data.len(), block_size);
            let target_data = encrypt_buffer(&known_data)?;
            
            known_data = get_known_data_with_suffix(&unknown_data, block_size);
            let mut last_byte = 0;
            known_data.push(last_byte);
            let mut test_data = encrypt_buffer(&known_data)?;
            
            let begin = block_size * (unknown_data.len() / block_size);
            let end = begin + block_size;
            while test_data[begin..end] != target_data[begin..end] {           
                if last_byte == 255 {
                    // Note that this is not an error state. This will in fact
                    // happen when we are trying to recover the padding bytes
                    // since these change depending on the size of the message.
                    unknown_data.pop();
                    return Ok(unknown_data);
                }
                last_byte += 1;
                *known_data.last_mut().unwrap() = last_byte;
                test_data = encrypt_buffer(&known_data)?;
            }
            unknown_data.push(last_byte);
        }
    }
}


pub mod ecb_cut_and_paste {
        use std::iter::repeat;

        use crate::oracles;
        use oracles::symmetric::ecb_cut_and_paste::Error;

        use crate::crypto;
        use crypto::symmetric::ciphers::{Cipher, Aes128};
        use crypto::symmetric::padding_modes::{PaddingMode, Pkcs7};

        // Encrypting the profile corresponding to the first email address
        // yields (email=...) (admin\x11 ... \x11) (...) where the second
        // contains the string "admin" followed by a valid PKCS7 padding.
        fn get_admin_string() -> String {
            // The length of the first block ("email=" + padding) must be 16.
            let padding_size = Pkcs7::min_padding_size(Aes128::BLOCK_SIZE, "email=".len());
            let padding_string = repeat(" ").take(padding_size).collect::<String>();
            
            // The length of the second block ("admin" + padding) must be 16.
            let padding_size = Pkcs7::min_padding_size(Aes128::BLOCK_SIZE, "admin".len());
            let padding_bytes = repeat(padding_size as u8).take(padding_size).collect::<Vec<u8>>();
            format!("{}admin{}@bar.com", padding_string, std::str::from_utf8(&padding_bytes).unwrap())
        }

        // Encrypting the profile corresponding to the second email address
        // yields (email=...) (...role=) (...). Thus if we replace the third
        // with the second block from above, we get a valid parameter string
        // corresponding to a profile with admin privileges.
        fn get_email_string() -> String {
            // The length of the email plus '&uid=10&role=' must be and even multiple of 16.
            "admin@cryp.to".to_string()
        }
    
        pub fn get_admin_profile<Oracle>(mut get_profile_for: Oracle) -> Result<Vec<u8>, Error>
            where Oracle : FnMut(&str) -> Result<Vec<u8>, Error> {
            let admin_bytes = get_profile_for(&get_admin_string())?
                .chunks(Aes128::BLOCK_SIZE)
                .skip(1)
                .next()
                .ok_or(Error::CipherError)?
                .to_owned();
            let mut profile_bytes: Vec<u8> = get_profile_for(&get_email_string())?;
            profile_bytes.splice(2 * Aes128::BLOCK_SIZE.., admin_bytes.iter().cloned());
            Ok(profile_bytes)
    }
}


pub mod harder_ecb_decryption {
    use crate::crypto::symmetric::Error;
    use crate::crypto::symmetric::padding_modes::{PaddingMode, Pkcs7};

    use super::simple_ecb_decryption;

    // A proxy object wrapping the encrypt_buffer oracle.
    struct Proxy<Oracle> where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> {
        prefix_size: usize,
        padding_size: usize,
        original_encrypt_buffer: Box<Oracle>,
    }

    impl<Oracle> Proxy<Oracle> where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> {
        fn new(mut encrypt_buffer: Oracle) -> Result<Self, Error> {
            let block_size = Proxy::get_block_size(|buffer| encrypt_buffer(buffer))?;
            let prefix_size = Proxy::get_prefix_size(|buffer| encrypt_buffer(buffer))?;
            let padding_size = Pkcs7::min_padding_size(block_size, prefix_size);
            Ok(Proxy { 
                prefix_size, 
                padding_size, 
                original_encrypt_buffer: Box::new(encrypt_buffer),
            })
        }

        // Since the output size is always k * (block size) for some k, we can
        // compute the block size as (k + 1) * (block size) - k * (block size).
        fn get_block_size(mut encrypt_buffer: Oracle) -> Result<usize, Error> {
            let output_size = encrypt_buffer(&[])?.len();
            for input_size in 8..=256 {
                let block_size = encrypt_buffer(&vec![0; 2 * input_size])?.len() - output_size;
                if block_size > 0 { return Ok(block_size) }
            }
            Err(Error::CipherError)
        }

        // If two consecutive encrypted blocks are equal, the size of the known
        // data must be (prefix size) % (block size) + k * (block size) for k > 1.
        fn get_prefix_size(mut encrypt_buffer: Oracle) -> Result<usize, Error> {
            let block_size = Proxy::get_block_size(|buffer| encrypt_buffer(buffer))?;
            for known_size in 1..=256 {
                let result = encrypt_buffer(&vec![0; known_size])?;
                let blocks: Vec<&[u8]> = result.chunks(block_size).collect();
                for i in 0 .. blocks.len() - 1 {
                    if blocks[i] == blocks[i + 1] {
                        let padding_size = known_size % block_size;
                        return Ok(i * block_size - padding_size);
                    }
                }
            }
            Err(Error::CipherError)
        }

        pub fn encrypt_buffer(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
            let padded_size = self.padding_size +  buffer.len();
            let mut padded_buffer = Vec::with_capacity(padded_size);
            padded_buffer.extend(vec![0; self.padding_size]);
            padded_buffer.extend(buffer);

            let prefix_size = self.prefix_size + self.padding_size;
            let result = (self.original_encrypt_buffer)(&padded_buffer);
            Ok(result?[prefix_size..].to_vec())
        }
    }

    pub fn get_unknown_data<Oracle>(encrypt_buffer: Oracle) -> Result<Vec<u8>, Error>
        where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> {
        let mut proxy = Proxy::new(encrypt_buffer)?;
        simple_ecb_decryption::get_unknown_data(|buffer| proxy.encrypt_buffer(buffer))
    }
}

