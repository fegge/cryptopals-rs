use std::iter::Iterator;
use std::cmp::PartialOrd;

/// `Minimize` trait which computes a local minimum for the given function.
pub trait Minimize<'a, F> {
    type Input;
    type Output;

    fn minimize(&'a mut self, function: F) -> (Self::Input, Self::Output)
        where F: Fn(&Self::Input) -> Self::Output;
}

/// Generic implementation of `Minimize` for implementations of `Iterator`.
///
/// # Note:
///
/// This implementation requires the `Input` to implement `Clone`, and
/// `Output` to implement `PartialOrd` and `Copy`.
///
/// # Panics:
///
/// This method panics if the iterator is empty.
impl<'a, In, Out, F, It> Minimize<'a, F> for It where It: Iterator<Item=In>,
    F: Fn(&In) -> Out,
    In: Clone,
    Out: PartialOrd + Copy
{
    type Input = In;
    type Output = Out;

    fn minimize(&'a mut self, function: F) -> (In, Out) {
        let mut result: (Option<In>, Option<Out>) = (None, None);
        for input in self {
            let output = function(&input);
            match result.1 {
                None => {
                    result = (Some(input), Some(output));
                },
                Some(minimum) => {
                    if output < minimum {
                        result = (Some(input), Some(output));
                    }
                }
            }
        }
        (result.0.unwrap(), result.1.unwrap())
    }
}

/// `Maximize` trait which computes a local maximum for the given function.
pub trait Maximize<'a, F> {
    type Input;
    type Output;

    fn maximize(&'a mut self, function: F) -> (Self::Input, Self::Output)
        where F: Fn(&Self::Input) -> Self::Output;
}

/// Generic implementation of `Maximize` for implementations of `Iterator`.
///
/// # Note:
///
/// This implementation requires the `Input` to implement `Clone`, and
/// `Output` to implement `PartialOrd` and `Copy`.
///
/// # Panics:
///
/// This method panics if the iterator is empty.
impl<'a, In, Out, F, It> Maximize<'a, F> for It where It: Iterator<Item=In>,
    F: Fn(&In) -> Out,
    In: Clone,
    Out: PartialOrd + Copy
{
    type Input = In;
    type Output = Out;

    fn maximize(&'a mut self, function: F) -> (In, Out) {
        let mut result: (Option<In>, Option<Out>) = (None, None);
        for input in self {
            let output = function(&input);
            match result.1 {
                None => {
                    result = (Some(input), Some(output));
                },
                Some(maximum) => {
                    if output > maximum {
                        result = (Some(input), Some(output));
                    }
                }
            }
        }
        (result.0.unwrap(), result.1.unwrap())
    }
}
mod tests {
    
    #[test]
    fn minimize_array() {
        use super::Minimize;

        let result = [1, 2, -1, -2, 3, -3]
            .iter()
            .map(|x| x)
            .minimize(|&x| (x * x + x) as f64);
        assert_eq!(result, (&-1, 0.0));
    }
    
    #[test]
    fn maximize_array() {
        use super::Maximize;

        let result = [1.0, 2.0, -1.0, -2.0, 3.0, -3.0]
            .iter()
            .map(|x| x)
            .maximize(|&x| (x * x + x) as u64);
        assert_eq!(result, (&3.0, 12));
    }
}
