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
        use cryptopals::crypto::symmetric::{
            BlockCipherMode, Aes128Cbc, 
            Cipher, Aes128
        };
        
        #[test]
        fn solution() {
           let key = "YELLOW SUBMARINE".as_bytes();
           let iv = [0; Aes128::BLOCK_SIZE];
           let mut cipher = Aes128Cbc::new(key, &iv).unwrap();

           let buffer = include_str!("../data/set_2/problem_10.txt").replace("\n", "");
           let buffer = base64::decode(&buffer).unwrap().to_owned();

           // This decodes the plaintext as UTF-8.
           let result = cipher.decrypt_str(&buffer);
           assert!(result.is_ok()); 
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
            let mut oracle: Oracle = Oracle::new(false).unwrap();
            let result = get_unknown_data(
                |buffer| { oracle.encrypt_buffer(buffer) }
            ); 
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), oracle.unknown_data); 
        }
    }

    mod problem_13 {
        use cryptopals::{oracles, attacks};
        use oracles::symmetric::ecb_cut_and_paste::{Role, Oracle};
        use attacks::symmetric::ecb_cut_and_paste::get_admin_profile;

        #[test]
        fn solution() {
            let mut oracle = Oracle::random().unwrap();
            let profile = get_admin_profile(|email| oracle.get_profile_for(email)).unwrap();
            
            assert_eq!(oracle.get_role_from(&profile).unwrap(), Role::Admin);
        }
    }

    mod problem_14 {
        use cryptopals::{oracles, attacks};
        use oracles::symmetric::simple_ecb_decryption::Oracle;
        use attacks::symmetric::harder_ecb_decryption::get_unknown_data;
    
        #[test]
        fn solution() {
            for _ in 0..10 {
                let mut oracle = Oracle::new(true).unwrap();
                let result = get_unknown_data(
                    |buffer| { oracle.encrypt_buffer(buffer) }
                ); 
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), oracle.unknown_data); 
            }    
        }
    }

    mod problem_15 {
        use cryptopals::crypto::symmetric::{
            PaddingMode, Pkcs7,
            Cipher, Aes128
        };

        #[test]
        fn solution() {
            let pkcs7 = Pkcs7::new(Aes128::BLOCK_SIZE);

            let mut valid_input = "ICE ICE BABY\x04\x04\x04\x04".as_bytes().to_vec();
            assert!(pkcs7.unpad_buffer(&mut valid_input).is_ok());

            let mut invalid_input = "ICE ICE BABY\x05\x05\x05\x05".as_bytes().to_vec();
            assert!(pkcs7.unpad_buffer(&mut invalid_input).is_err());
            
            let mut invalid_input = "ICE ICE BABY\x01\x02\x03\x04".as_bytes().to_vec();
            assert!(pkcs7.unpad_buffer(&mut invalid_input).is_err());
        }
    }

    mod problem_16 {
        use cryptopals::{oracles, attacks};
        use oracles::symmetric::cbc_bitflipping_attacks::Oracle;
        use attacks::symmetric::cbc_bitflipping_attacks::get_admin_profile;
    
        #[test]
        fn solution() {
            let mut oracle = Oracle::random().unwrap();
            // We assume that we know the size of the prefix. Alternatively, we could 
            // guess the size of the prefix and query the oracle once for verification.
            let comment_1 = "comment1=cooking%20MCs";
            let result = get_admin_profile(
                comment_1.len(), 
                &mut |buffer| { oracle.encrypt_user_data(buffer) }
            );
            assert!(result.is_ok());
            assert_eq!(oracle.is_admin_user(&result.unwrap()), Ok(true));
        }
    }
}
