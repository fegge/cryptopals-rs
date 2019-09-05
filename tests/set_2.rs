pub mod set_2 {
    use cryptopals::crypto::symmetric::padding_modes::{PaddingMode, Pkcs7};
    
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
}
