pub mod  mersenne_twister {
    use std::time::{SystemTime, SystemTimeError};
    use crate::crypto::random::mersenne_twister::Mt19337;

    pub const MAXIMUM_DELTA: u64 = 1000;

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
}
