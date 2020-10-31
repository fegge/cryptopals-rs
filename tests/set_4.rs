mod set_4 {

    mod problem_25 {
        use cryptopals::crypto::random::Random;
        use cryptopals::oracles::symmetric::random_access_read_write::Oracle;
        

        #[test]
        fn solution() {
            let plaintext = include_str!("../data/set_4/problem_25.txt")
                .as_bytes();
        
            let mut oracle = Oracle::random();
            let ciphertext = oracle.encrypt_buffer(&plaintext).unwrap();

            // Replacing the entire ciphertext with zeroes will return the keystream.
            let mut keystream = ciphertext.clone();
            oracle.edit_buffer(&mut keystream,0, &vec![0; ciphertext.len()]).unwrap();

            let result: Vec<u8> = ciphertext
                .iter()
                .zip(keystream.iter())
                .map(|(c, k)| c ^ k)
                .collect();
            assert_eq!(result, plaintext);
        }
    }

    mod problem_26 {
        use cryptopals::{oracles, attacks, crypto};
        use oracles::symmetric::ctr_bitflipping_attacks::Oracle;
        use attacks::symmetric::ctr_bitflipping_attacks::get_admin_profile;
        use crypto::random::Random;
    
        #[test]
        fn solution() {
            let mut oracle = Oracle::random();
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

    mod problem_27 {
        use cryptopals::crypto::random::Random;
        use cryptopals::oracles::symmetric::cbc_with_key_as_iv::Oracle;
        use cryptopals::attacks::symmetric::cbc_with_key_as_iv::get_key;
        
        #[test]
        fn solution() {
            let mut sender = Oracle::random();
            let mut receiver = sender.clone();

            let key = get_key(
                &mut |string| { sender.encrypt_str(string) },
                &mut |buffer| { receiver.decrypt_str(buffer) }
            );
            assert!(sender.verify_key(&key.unwrap()), true);
        }
    }

    mod problem_28 {
        use cryptopals::crypto::hash::{Mac, Sha1NaiveMac};

        #[test]
        fn solution() {
            let first_mac = Sha1NaiveMac::digest(
                "This is the first key",
                "This is the first message"
            );
            let second_mac = Sha1NaiveMac::digest(
                "This is the second key",
                "This is the second message"
            );
            assert_ne!(first_mac, second_mac);
        }
    }
}
