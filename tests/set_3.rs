mod set_3 {

    mod problem_22 {
        use rand;
        use rand::Rng;

        use std::time::{Duration, SystemTime};
        
        use cryptopals::crypto;
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
            for _ in 0..100 {
                let seed = get_unix_time().unwrap();
                let output = Mt19337::new(seed as u32).next_u32();
                let result = recover_timestamp_from(output);
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), seed); 
            }
        }
    }
}
