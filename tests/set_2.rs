mod set_2 {

    mod problem_9 {
        use cryptopals::crypto;
        
        use crypto::symmetric::padding_modes::{PaddingMode, Pkcs7};

        #[test]
        fn solution() {
            let pkcs7 = Pkcs7::new(20);
            let mut buffer: Vec<u8> = "YELLOW SUBMARINE".as_bytes().to_owned(); 

            let result = pkcs7.pad_buffer(&mut buffer);
            assert!(result.is_ok());
            assert_eq!(buffer, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_owned());
        }
    }

    mod problem_10 {
        use cryptopals::crypto;
        
        use crypto::symmetric::padding_modes::Pkcs7;
        use crypto::symmetric::cipher_modes::{CipherMode, Cbc};
        use crypto::symmetric::ciphers::{Cipher, Aes128};

        type Aes128Cbc = Cbc<Aes128, Pkcs7>;
        
        #[test]
        fn solution() {
           let key = "YELLOW SUBMARINE".as_bytes();
           let iv = [0; Aes128::BLOCK_SIZE];
           let mut cipher = Aes128Cbc::new(key, &iv).unwrap();

           let buffer = include_bytes!("../data/set_2/problem_10.bin").to_owned();
           let result = cipher.decrypt_buffer(&buffer);
           assert!(result.is_ok()); 
            
           let buffer = result.unwrap();
           let string = std::str::from_utf8(&buffer);
           assert!(string.is_ok());

           // Prints the lyrics for 'Play that funky music'.
           // println!("{}", string.unwrap());
       }
    }

    mod problem_11 {
        use cryptopals::crypto::symmetric::ciphers::{Cipher, Aes128};
        use cryptopals::oracles::symmetric::ecb_cbc_detection::{Mode, Oracle};

        #[test]
        fn solution() {
            let mut oracle: Oracle = Default::default(); 
            let known_data = [0; 3 * Aes128::BLOCK_SIZE];
            for _ in 0..100 {
                let result = oracle.encrypt_buffer(&known_data);
                assert!(result.is_ok());

                let mut cipher_mode = Mode::CbcMode;
                let mut last_block = None;
                // By encrypting mutiple identical blocks, we can detect ECB mode
                // since the corresponding ciphertext blocks will also be identical.
                for this_block in result.unwrap().chunks(Aes128::BLOCK_SIZE) {
                    if last_block.is_some() && last_block.unwrap() == this_block {
                        cipher_mode = Mode::EcbMode;
                        break;
                    } else {
                        last_block = Some(this_block);
                    }
                }
                assert_eq!(cipher_mode, oracle.cipher_mode().unwrap()); 
            }
        }
    }
}
