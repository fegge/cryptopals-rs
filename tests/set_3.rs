mod set_3 {

    mod problem_18 {
        use base64;
        
        use cryptopals::crypto::symmetric::{Aes128Ctr, StreamCipherMode};

        const INPUT: &str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

        #[test]
        fn solution() {
            let mut cipher = Aes128Ctr::new(b"YELLOW SUBMARINE", &[0; 8]).unwrap();
            let input = base64::decode(INPUT).unwrap().to_owned();
            
            // This decodes the plaintext as UTF-8.
            let result = cipher.decrypt_str(&input);
            assert!(result.is_ok());
        }
    }

    mod problem_22 {
        use rand;
        use rand::Rng;

        use std::time::{Duration, SystemTime};
        
        use cryptopals::crypto;
        use crypto::random::{RandomGenerator, SeedableGenerator};
        use crypto::random::mersenne_twister::Mt19337;
        
        use cryptopals::attacks;
        use attacks::random::mersenne_twister::{recover_timestamp_from, Error, MAXIMUM_DELTA};

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
        use crypto::random::RandomGenerator;
        use crypto::random::mersenne_twister::Mt19337;
        
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
        use crypto::random::SeedableGenerator;
        use crypto::random::mersenne_twister::Mt19337;
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
