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

    pub fn get_unknown_data<Oracle>(unknown_size: usize, mut encrypt_buffer: Oracle) -> Result<Vec<u8>, Error> 
        where Oracle: FnMut(&[u8]) -> Result<Vec<u8>, Error> 
    {
        println!("{:?}", get_block_size(|buffer| encrypt_buffer(buffer)));
        let block_size = get_block_size(|buffer| encrypt_buffer(buffer))?;
        
        let mut unknown_data = Vec::new();
        while unknown_data.len() < unknown_size {
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
