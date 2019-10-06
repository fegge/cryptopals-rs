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
        use base64;
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

           let buffer = include_str!("../data/set_2/problem_10.txt").replace("\n", "");
           let buffer = base64::decode(&buffer).unwrap().to_owned();

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
        use cryptopals::{oracles, attacks};
        use oracles::symmetric::ecb_cbc_detection::Oracle;
        use attacks::symmetric::ecb_cbc_detection::get_cipher_mode;

        #[test]
        fn solution() {
            let mut oracle: Oracle = Default::default(); 
            for _ in 0..100 {
                let result = get_cipher_mode(|buffer| oracle.encrypt_buffer(buffer)); 
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), oracle.cipher_mode().unwrap()); 
            }
        }
    }

    mod problem_12 {
        use cryptopals::{oracles, attacks};
        use oracles::symmetric::simple_ecb_decryption::Oracle;
        use attacks::symmetric::simple_ecb_decryption::get_unknown_data;

        #[test]
        fn solution() {
            let mut oracle: Oracle = Oracle::new().unwrap();
            let result = get_unknown_data(
                |buffer| { oracle.encrypt_buffer(buffer) }
            ); 
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), oracle.unknown_data); 
        }
    }

    mod problem_13 {
        use maplit::{convert_args, hashmap};

        use std::collections::HashMap;

        use cryptopals::http;
        use http::request::{FromParamStr, ToParamStr};
        
        #[test]
        fn solution() {
            let profile: HashMap<String, String> = convert_args!(hashmap!(
                "email" => "foo@bar.com",
                "uid" => "10",
                "role" => "user",
            ));
            let result = HashMap::from_param_str(&profile.to_param_str());
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), profile);
        }
    }
}
