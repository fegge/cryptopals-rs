pub mod  mersenne_twister {
    use std::time::{SystemTime, SystemTimeError};
    use crate::crypto::random::SeedableGenerator;
    use crate::crypto::random::mersenne_twister::Mt19337;
    
    use crate::math::linear_algebra;
    use linear_algebra::{Matrix, Vector, GaussElimination};

    pub const MAXIMUM_DELTA: u64 = 1000;
    const FIRST_MASK: u32 = 0x9d2c_5680;
    const SECOND_MASK: u32 = 0xefc6_0000;

    #[derive(Debug)]
    pub enum Error {
        UnixTimeError,
        RecoveryError
    }

    impl From<SystemTimeError> for Error {
        fn from(_: SystemTimeError) -> Self {
            Error::UnixTimeError
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
        let rhs = Vector::from_u32(output);
        let mut lhs = Matrix::diagonal(32);
        
        // x ^= x >> 11;
        lhs += &lhs >> 11;

        // x ^= (x << 7) & Mt19337::FIRST_MASK;
        lhs += (&lhs << 7) & Vector::from_u32(FIRST_MASK);
        
        // x ^= (x << 15) & Mt19337::SECOND_MASK;
        lhs += (&lhs << 15) & Vector::from_u32(SECOND_MASK);
        
        // x ^= x >> 18;
        lhs += &lhs >> 18;
        
        GaussElimination::new(lhs, rhs)
            .solve()
            .map_err(Error::from)
            .map(|solution| solution.to_u32())
    }
}
