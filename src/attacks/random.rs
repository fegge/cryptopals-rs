pub mod  mersenne_twister {
    use std::convert::{From, TryInto};
    use std::time::{SystemTime, SystemTimeError};

    use crate::crypto::symmetric;
    use symmetric::cipher_modes::StreamCipherMode;
    use crate::crypto::random::{RandomGenerator, SeedableGenerator};
    use crate::crypto::random::mersenne_twister::Mt19337;
    
    use crate::math::linear_algebra;
    use linear_algebra::{Matrix, Vector, GaussElimination};

    pub const MAXIMUM_DELTA: u64 = 1000;
    const FIRST_MASK: u32 = 0x9d2c_5680;
    const SECOND_MASK: u32 = 0xefc6_0000;

    #[derive(Debug)]
    pub enum Error {
        UnixTimeError,
        RecoveryError,
        CipherError
    }

    impl From<SystemTimeError> for Error {
        fn from(_: SystemTimeError) -> Self {
            Error::UnixTimeError
        }
    }

    impl From<symmetric::Error> for Error {
        fn from(_: symmetric::Error) -> Self {
            Error::CipherError
        }
    }
    
    impl From<linear_algebra::Error> for Error {
        fn from(_: linear_algebra::Error) -> Self {
            Error::RecoveryError
        }
    }

    fn get_unix_time() -> Result<u64, Error> {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(
            |duration| duration.as_secs()
        ).map_err(|error| error.into())
    }

    fn verify_u64_seed(seed: u64, output: u32) -> bool {
        Mt19337::new(seed as u32).next_u32() == output
    }

    pub fn recover_timestamp_from(output: u32) -> Result<u64, Error> {
        let now = get_unix_time()?;
        for delta in 0..(MAXIMUM_DELTA + 1) {
            if verify_u64_seed(now - delta, output) { return Ok(now - delta) }
        }
        return Err(Error::RecoveryError)
    }

    pub fn recover_state_from(output: u32) -> Result<u32, Error> {
        let rhs = Vector::from(output);
        let mut lhs = Matrix::diagonal(32);
        
        // x ^= x >> 11;
        lhs += &lhs >> 11;

        // x ^= (x << 7) & Mt19337::FIRST_MASK;
        lhs += (&lhs << 7) & Vector::from(FIRST_MASK);
        
        // x ^= (x << 15) & Mt19337::SECOND_MASK;
        lhs += (&lhs << 15) & Vector::from(SECOND_MASK);
        
        // x ^= x >> 18;
        lhs += &lhs >> 18;
        
        GaussElimination::new(lhs, rhs)
            .solve()
            .and_then(|solution| solution.try_into())
            .map_err(Error::from)
    }

    pub fn recover_key_from(input: &[u8], output: &[u8]) -> Result<u16, Error> {
        for key in 0..=0xffff {
            if Mt19337::new(key).encrypt_buffer(&input)? == output {
                return Ok(key as u16)
            }
        }
        Err(Error::RecoveryError)
    }
}
