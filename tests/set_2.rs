pub mod set_2 {
    use cryptopals::crypto::symmetric;

    use symmetric::padding_modes::{PaddingMode, Pkcs7};
    use symmetric::cipher_modes::{CipherMode, Cbc};
    use symmetric::ciphers::{Cipher, Aes128};

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    #[test]
    fn problem_9() {
        let pkcs7 = Pkcs7::new(20);
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.extend("YELLOW SUBMARINE".as_bytes());
        buffer.resize(20, 0);

        let result = pkcs7.pad_buffer(&mut buffer, 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
    }

    #[test]
    fn problem_10() {
        let mut buffer = include_bytes!("../data/set_2/problem_10.bin").to_owned();
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = [0; Aes128::BLOCK_SIZE];
        let mut cipher = Aes128Cbc::new(key, &iv).unwrap();

        let result = cipher.decrypt_buffer(&mut buffer[..]);
        assert!(result.is_ok());

        let string = std::str::from_utf8(result.unwrap());
        assert!(string.is_ok());

        println!("{}", string.unwrap());
    }
}
