mod set_3 {

    mod problem_17 {
        use cryptopals::{oracles, attacks, crypto};
        use oracles::symmetric::cbc_padding_oracle::Oracle;
        use attacks::symmetric::cbc_padding_oracle::get_plaintext_buffer;
        use crypto::random::Random;

        #[test]
        fn solution() {
            let mut oracle = Oracle::random();
            let buffer = oracle.get_encrypted_buffer().unwrap();
            let result = get_plaintext_buffer(
                &buffer,
                &mut |buffer| oracle.verify_padding(buffer)
            );

            // Check that the result is correct by attempting to decode the buffer as UTF-8.
            assert!(String::from_utf8(result.unwrap()).is_ok());
        }
    }

    mod problem_18 {
        use base64;
        
        use cryptopals::crypto::symmetric::{Aes128Ctr, StreamCipherMode};

        const INPUT: &str = 
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

        #[test]
        fn solution() {
            let mut cipher = Aes128Ctr::new(b"YELLOW SUBMARINE", &[0; 8]).unwrap();
            let input = base64::decode(INPUT).unwrap().to_owned();
            
            // This decodes the plaintext as UTF-8.
            let result = cipher.decrypt_str(&input);
            assert!(result.is_ok());
        }
    }

    mod problem_20 {
        use cryptopals::crypto::symmetric::{
            StreamCipherMode,
            Aes128Ctr,
            Cipher,
            Aes128,
            Error
        };
        use cryptopals::random_vec;

        use cryptopals::attacks::statistics;
        use statistics::fixed_nonce_ctr::using_statistics;

        pub fn get_ciphertexts() -> Result<Vec<Vec<u8>>, Error> {
            // It is safe to call unwrap here since each line is valid base64.
            let mut buffers = include_str!("../data/set_3/problem_19.txt")
                .split('\n')
                .map(|string| base64::decode(&string).unwrap())
                .collect::<Vec<Vec<u8>>>();

            let key = random_vec!(Aes128::KEY_SIZE);
            let nonce = random_vec!(Aes128::BLOCK_SIZE / 2);
            for buffer in buffers.iter_mut() {
                Aes128Ctr::new(&key, &nonce)?.encrypt_mut(buffer)?;
            }
            Ok(buffers)
        }

        #[test]
        fn solution() {
            let ciphertexts = get_ciphertexts().unwrap();
            
            // This decodes the plaintext as UTF-8.
            let result = using_statistics::recover_plaintexts(&ciphertexts);
            assert!(result.is_ok());
        }
        
    }

    mod problem_21 {
        
        use cryptopals::crypto;
        use crypto::random::{
            SeedableGenerator, 
            RandomGenerator, 
            Mt19337
        };

        #[test]
        fn solution() {
            let mut random = Mt19337::new(1);
            let output = [
                0x6ac1f425, 0xff4780eb, 0xb8672f8c, 0xeebc1448, 
                0x00077EFF, 0x20CCC389, 0x4D65aacb, 0xffc11E85
            ];
            for i in 0..output.len() {
                assert_eq!(random.next_u32(), output[i]);
            }
        }
    }

    mod problem_22 {
        use rand;
        use rand::Rng;

        use std::time::{Duration, SystemTime};
        
        use cryptopals::crypto;
        use crypto::random::{
            SeedableGenerator, 
            RandomGenerator, 
            Mt19337
        };
        
        use cryptopals::attacks;
        use attacks::random::mersenne_twister::{
            recover_timestamp_from, 
            MAXIMUM_DELTA,
            Error
        };

        fn get_unix_time() -> Result<u64, Error> {
            // Simulate the passage of [0, MAXIMUM_DELTA) seconds.
            let delta = Duration::from_secs(rand::thread_rng().gen_range(0, MAXIMUM_DELTA));
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.checked_sub(delta) {
                Some(duration) => { Ok(duration.as_secs()) }
                None => { Err(Error::UnixTimeError) }
            } 
        }

        #[test]
        fn solution() {
            let seed = get_unix_time().unwrap();
            let output = Mt19337::new(seed as u32).next_u32();
            let result = recover_timestamp_from(output);
            assert_eq!(result.unwrap(), seed); 
        }
    }

    mod problem_23 {
        use cryptopals::crypto;
        use crypto::random::{Random, Mt19337, RandomGenerator};
        
        use cryptopals::attacks::random::mersenne_twister::recover_state_from;

        #[test]
        fn solution() {
            let mut random = Mt19337::random();
            let mut state = [0; 624];
            for i in 0..624 {
                state[i] = recover_state_from(random.next_u32()).unwrap();
            }
            assert_eq!(random, Mt19337::from_state(state, 624));
        }
    }

    mod problem_24 {
        use rand;
        use rand::Rng;
        use std::iter;

        use cryptopals::crypto;
        use crypto::random::{Mt19337, SeedableGenerator};
        use crypto::symmetric::cipher_modes::StreamCipherMode;

        use cryptopals::attacks::random::mersenne_twister::recover_key_from;

        #[test]
        fn solution() {
            let key = rand::thread_rng().gen::<u16>();
            let mut random = Mt19337::new(key as u32);
            let input = iter::repeat(b'A').take(14).collect::<Vec<u8>>();
            let output = random.encrypt_buffer(&input).unwrap();
            let result = recover_key_from(&input, &output);
            assert_eq!(result.unwrap(), key);
        }
    }
}
