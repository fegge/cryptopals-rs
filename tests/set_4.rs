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
            println!("{:?}", result);
            assert_eq!(result, plaintext);
        }
    }

}
