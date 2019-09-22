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
    use crate::crypto::symmetric::ciphers::{Cipher, Aes128};

    fn get_known_data(size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(Aes128::BLOCK_SIZE);
        result.resize(Aes128::BLOCK_SIZE - (size % Aes128::BLOCK_SIZE) - 1, 0);
        result
    }

    fn get_known_data_with_suffix(suffix: &[u8]) -> Vec<u8> {
        let mut result = get_known_data(suffix.len());
        result.extend(suffix);
        result
    }

    pub fn get_unknown_data<Oracle>(unknown_size: usize, mut encrypt_buffer: Oracle)
        -> Result<Vec<u8>, Error> where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error>
    {
        let mut unknown_data = Vec::new();
        while unknown_data.len() < unknown_size {
            let mut known_data = get_known_data(unknown_data.len());
            let target_data = encrypt_buffer(&known_data)?;
            
            known_data = get_known_data_with_suffix(&unknown_data);
            let mut last_byte = 0;
            known_data.push(last_byte);
            let mut test_data = encrypt_buffer(&known_data)?;
            
            let begin = Aes128::BLOCK_SIZE * (unknown_data.len() / Aes128::BLOCK_SIZE);
            let end = begin + Aes128::BLOCK_SIZE;
            while test_data[begin..end] != target_data[begin..end] {           
                if last_byte == 255 {
                    // Note that this is not an error state. This will in fact
                    // happen when we are trying to recover the padding bytes
                    // since these change depending on the size of the message.
                    return Ok(unknown_data);
                }
                last_byte += 1;
                *known_data.last_mut().unwrap() = last_byte;
                test_data = encrypt_buffer(&known_data)?;
            }
            unknown_data.push(last_byte);
        }
        Ok(unknown_data)
    }
}
