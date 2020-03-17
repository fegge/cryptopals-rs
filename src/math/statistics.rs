use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::clone::Clone;
use std::hash::Hash;
use std::cmp::Eq;


/// A convenience type used for frequency counting.
pub struct Frequencies<T> {  
    pub sample_size: usize,
    counts: HashMap<T, usize>
}

impl<T> Frequencies<T> where T: Eq + Clone + Hash {
    pub fn new() -> Self {
        Frequencies { sample_size: 0, counts: HashMap::new() }
    }

    pub fn add(&mut self, value: &T) {
        *self.counts.entry(value.clone()).or_insert(0) += 1;
        self.sample_size += 1;
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<T, usize> {
        (&self).into_iter()
    }
}

impl<T> Default for Frequencies<T> where T: Eq + Clone + Hash {
    fn default() -> Self {
        Frequencies::new()
    }
}

impl<T> FromIterator<T> for Frequencies<T> where T: Eq + Clone + Hash {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
        let mut frequencies = Frequencies::new();

        for x in iter {
            frequencies.add(&x);
        }
        frequencies
    }
}

impl<'a, T: 'a> FromIterator<&'a T> for Frequencies<T> where T: Eq + Clone + Hash {
    fn from_iter<I: IntoIterator<Item=&'a T>>(iter: I) -> Self {
        let mut frequencies = Frequencies::new();

        for x in iter {
            frequencies.add(x);
        }
        frequencies
    }
}

impl<T> IntoIterator for Frequencies<T> {
    type Item = (T, usize);
    type IntoIter = std::collections::hash_map::IntoIter<T, usize>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.counts.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Frequencies<T> {
    type Item = (&'a T, &'a usize);
    type IntoIter = std::collections::hash_map::Iter<'a, T, usize>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.counts.iter()
    }
}

/// A discrete probability distribution.
pub struct Distribution<T> where T: Eq + Clone + Hash {
    pub support: HashSet<T>,
    probabilities: HashMap<T, f64>
}

impl<T> Distribution<T> where T: Eq + Clone + Hash {
    
    /// Creates a discrete probability distribution from a `HashMap` mapping `T`s to probabilities.
    ///
    /// # Note
    ///
    /// This method consumes the probability map to create the Distribution object.
    pub fn new(probabilities: HashMap<T, f64>) -> Self {
        let mut support = HashSet::new();
        for (value, &probability) in &probabilities {
            if probability > 0.0 { support.insert(value.clone()); }
        }
        Distribution { support, probabilities }
    }

    /// Returns the entropy of the distribution.
    pub fn entropy(&self) -> f64 {
        let mut result = 0.0;
        for probability in self.probabilities.values() {
            result -= probability * probability.log2();
        }
        result
    }

    /// Returns the probability of the given observation.
    pub fn probability_of(&self, value: &T) -> f64 {
        *self.probabilities.get(value).unwrap_or(&0.0)
    }

    /// Returns the total variation distance between the two discrete distributions.
    pub fn distance_from(&self, other: &Distribution<T>) -> f64 {
        let mut result = 0.0;
        for value in self.support.union(&other.support) {
            result += (self.probability_of(value) - other.probability_of(value)).abs();
        }
        0.5 * result
    }
}

/// Creates a discrete probability distribution from a set of frequencies.
///
/// # Note
///
/// This method consumes the set of frequencies to create the Distribution object.
impl<T> From<Frequencies<T>> for Distribution<T> where T: Eq + Clone + Hash {
    fn from(frequencies: Frequencies<T>) -> Self {
        let mut probabilities = HashMap::new();
        let sample_size = frequencies.sample_size as f64;
        for (value, frequency) in frequencies {
            let probability = (frequency as f64) / sample_size;
            probabilities.insert(value, probability);
        }
        Distribution::new(probabilities)
    }
}

/// Creates a discrete probability distribution from a set of frequencies.
impl<T> From<&Frequencies<T>> for Distribution<T> where T: Eq + Clone + Hash {
    fn from(frequencies: &Frequencies<T>) -> Self {
        let mut probabilities = HashMap::new();
        let sample_size = frequencies.sample_size as f64;
        for (value, frequency) in frequencies {
            let probability = (*frequency as f64) / sample_size;
            probabilities.insert(value.clone(), probability);
        }
        Distribution::new(probabilities)
    }
}

impl<T> FromIterator<T> for Distribution<T> where T: Eq + Clone + Hash {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
        Distribution::from(Frequencies::from_iter(iter))
    }
}

impl<'a, T: 'a> FromIterator<&'a T> for Distribution<T> where T: Eq + Clone + Hash {
    fn from_iter<I: IntoIterator<Item=&'a T>>(iter: I) -> Self {
        Distribution::from(Frequencies::from_iter(iter))
    }
}

#[macro_export]
macro_rules! dist {
    ( $( $value:expr => $probability:expr ),* ) => {{
        let mut probabilities = std::collections::HashMap::new();
        $( probabilities.insert($value, $probability); )*
        Distribution::new(probabilities)
    }};
}

mod tests {
   
    #[test]
    fn distribution_from_frequencies() {
        use super::*;

        let mut frequencies = Frequencies::new();
        for x in 0..16 {
            for _ in 0..x {
                frequencies.add(&x);
            }
        }
        let distribution = Distribution::from(frequencies);
        for x in 0..16 {
            assert_eq!(
                distribution.probability_of(&x), 
                (x as f64) * distribution.probability_of(&1));
        }
    }

    #[test]
    fn distribution_from_iterator() {
        use super::*;

        let mut observations = Vec::new();
        for x in 0..16 {
            for _ in 0..x {
                observations.push(x);
            }
        }
        let distribution: Distribution<i32> = observations.iter().collect();
        for x in 0..16 {
            assert_eq!(
                distribution.probability_of(&x), 
                (x as f64) * distribution.probability_of(&1));
        }
    }

    #[test]
    fn distribution_from_macro() { 
        use super::*;

        let distribution = dist!(
            "a" => 0.5,
            "b" => 0.5
        );
        assert_eq!(distribution.probability_of(&"a"), 0.5);
        assert_eq!(distribution.probability_of(&"b"), 0.5);
        assert_eq!(distribution.probability_of(&"c"), 0.0);
    }
}
