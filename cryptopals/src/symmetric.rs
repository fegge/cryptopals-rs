pub mod aes {
    pub struct Aes128 {
    }

    impl Aes128 {
    }
}


pub mod padding {
    pub struct Pkcs7 {
        block_size: usize
    }

    impl Pkcs7 {
        pub fn new(block_size: usize) -> Pkcs7 {
            Pkcs7 { block_size }
        }

        pub fn add_padding<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a Vec<u8> {
            let padding_size = self.block_size - (buffer.len() % self.block_size);
            buffer.resize(buffer.len() + padding_size, padding_size as u8);
            buffer
        }

        pub fn remove_padding<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a Vec<u8> {
            if let Some(&padding_size) = buffer.last() {
                buffer.truncate(buffer.len() - padding_size as usize);
            }
            buffer
        }
    }
}

pub mod mode {
    pub struct Cbc {
        
        iv: Vec<u8>
    }
}

#[cfg(test)]
mod tests {

    mod padding {
        use crate::symmetric::padding;

        #[test]
        fn length_test() {
            let pkcs7 = padding::Pkcs7::new(8);
            let mut buffer = vec![4, 5, 6, 7];

            pkcs7.add_padding(&mut buffer);
            assert_eq!(buffer.len(), 8);

            pkcs7.remove_padding(&mut buffer);
            assert_eq!(buffer.len(), 4);

        }

        #[test]
        fn empty_test() {
            let pkcs7 = padding::Pkcs7::new(16);

            assert_eq!(pkcs7.add_padding(&mut Vec::new()).len(), 16);
            assert_eq!(pkcs7.remove_padding(&mut Vec::new()).len(), 0);
        }

        #[test]
        #[should_panic]
        fn panic_test() {
            let pkcs7 = padding::Pkcs7::new(8);
            let mut buffer = vec![4, 5, 6, 7];
            
            pkcs7.remove_padding(&mut buffer);
        }

        #[test]
        fn target_test() {
            let pkcs7 = padding::Pkcs7::new(20);
            let mut buffer = "YELLOW SUBMARINE".as_bytes().to_owned();
            
            pkcs7.add_padding(&mut buffer);
            assert_eq!(buffer, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_owned());
        }
    }
}
