mod set_1 {
    
    mod problem_1 {
        use hex;
        use base64;

        #[test]
        fn solution() {
            let hex_str = 
                "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d".to_owned();
            let base64_str = base64::encode(&hex::decode(hex_str).unwrap());
            assert_eq!(
                base64_str,
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            );
        }
    }

    mod problem_2 {
        use hex;

        #[test]
        fn solution() {
            let lhs = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
            let rhs = hex::decode("686974207468652062756c6c277320657965").unwrap();
            let result: Vec<u8> = lhs.iter()
                .zip(rhs.iter())
                .map(|(x, y)| x ^ y)
                .collect();
            assert_eq!(hex::encode(result), "746865206b696420646f6e277420706c6179");
        }
    }

    mod problem_3 {
        use hex;
        use cryptopals::attacks::statistics::single_byte_xor;

        #[test]
        fn solution() {
            let ciphertext = hex::decode(
                "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            ).unwrap();
            
            let result = single_byte_xor::recover_plaintext(&ciphertext);
            assert_eq!(result.unwrap(), "Cooking MC's like a pound of bacon");
        }
    }
    
    mod problem_4 {
        use hex;
        use cryptopals::attacks::statistics::detect_single_byte_xor;

        #[test]
        fn solution() {
            let ciphertexts: Vec<Vec<u8>> = include_str!("../data/set_1/problem_4.txt")
                .split('\n')
                .map(|string| hex::decode(string).unwrap())
                .collect();
            
            let result = detect_single_byte_xor::recover_plaintext(&ciphertexts);
            assert_eq!(result.unwrap(), "Now that the party is jumping\n");
        }
    }

    mod problem_5 {
        use hex;
        use cryptopals::crypto::symmetric::{StreamCipherMode, Xor};
        
        #[test]
        fn solution() {
            let ciphertext = hex::decode(
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                 a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            ).unwrap();
            let result = Xor::new("ICE".as_bytes()) .decrypt_str(&ciphertext);

            assert_eq!(
                result.unwrap(), 
                "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            );
        }
    }

    mod problem_6 {
        use base64;
        use cryptopals::attacks::statistics::repeating_key_xor;

        #[test]
        fn solution() {
            let ciphertext = base64::decode(
                &include_str!("../data/set_1/problem_6.txt").replace("\n", "")
            ).unwrap();
            
            repeating_key_xor::recover_plaintext(&ciphertext);
        }
    }
}
