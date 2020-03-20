//! This module implements vectors, matrices, and Gauss elimination over
//! the two element field {0, 1}.

use rand;
use rand::Rng;
use std::{fmt, ops, convert};

#[derive(Debug)]
pub enum Error {
    ConversionError,
    InconsistentSystemError,
    UnderDeterminedSystemError,
}

/// A custom bit vector type.
#[derive(Clone, PartialEq)]
pub struct Vector {
    pub dimension: usize,
    limbs: Vec<u64>,
}

impl Vector {
    /// Returns a new vector of the given dimension.
    pub fn new(dimension: usize) -> Self {
        Self::zeroes(dimension)
    }

    /// Returns a new vector `(0, 0, ..., 0)` of the given dimension.
    pub fn zeroes(dimension: usize) -> Self {
        Self {
            dimension,
            limbs: vec![0; (dimension + 63) >> 6]
        }
    }

    /// Returns a new vector `(1, 1, ..., 1)` of the given dimension.
    pub fn ones(dimension: usize) -> Self {
        let mut result = Self {
            dimension,
            limbs: vec![0xffffffff_ffffffff; (dimension + 63) >> 6]
        };
        // Ensure that unused bits are always zero. Note: This is
        // required to ensure that the derived implementation of 
        // the PartialEq trait does what it should.
        let mask = (1 << (dimension & 63)) - 1;
        if let Some(x) = result.limbs.last_mut() {
            *x &= mask;
        }
        result
    }

    /// Returns a random vector of the given dimension.
    pub fn random(dimension: usize) -> Self {
        let mut result = Vector::zeroes(dimension);
        (0..dimension)
            .filter(|_| rand::thread_rng().gen::<bool>())
            .for_each(|i| result.set_element(i, 1));
        result
    }
    
    /// Gets the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if the `index` is larger than the dimension.
    #[inline]
    pub fn get_element(&self, index: usize) -> u8 {
        debug_assert!(index < self.dimension);
        ((self.limbs[index >> 6] >> (index & 63)) & 1) as u8
    }

    /// Sets the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if either index is larger than the dimension.
    #[inline]
    pub fn set_element(&mut self, index: usize, value: u8) {
        debug_assert!(index < self.dimension);
        let mask = 0xffffffff_ffffffff ^ (1 << (index & 63));
        let value = ((value & 1) as u64) << (index & 63);
        self.limbs[index >> 6] = (self.limbs[index >> 6] & mask) ^ value;
    }

    /// Swaps two elements of the vector.
    ///
    /// # Panics
    ///
    /// Panics if either index is larger than the dimension.
    #[inline]
    pub fn swap_elements(&mut self, first: usize, second: usize) {
        let first_element = self.get_element(first);
        let second_element = self.get_element(second);
        self.set_element(first, second_element);
        self.set_element(second, first_element);
    }

    /// Adds the `value` to the element at the given `index`.
    ///
    /// # Panics
    ///
    /// Panics if the `index` is larger than the dimension.
    pub fn add_to_element(&mut self, index: usize, value: u8) {
        self.set_element(index, self.get_element(index) ^ value);
    }
}

impl fmt::Debug for Vector {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for index in 0..self.dimension {
            write!(formatter, "{}", self.get_element(index))?
        }
        Ok(())
    }
}

impl fmt::Display for Vector {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "(")?;
        for index in 0..self.dimension {
            if index > 0 {
                write!(formatter, ", ")?
            }
            write!(formatter, "{}", self.get_element(index))?
        }
        write!(formatter, ")")
    }
}

/// Converts an `u8` into an 8-bit vector.
impl convert::From<u8> for Vector {
    fn from(value: u8) -> Vector {
        Self {
            dimension: 8,
            limbs: vec![value as u64]
        }
    }
}

/// Converts an `u16` into an 16-bit vector.
impl convert::From<u16> for Vector {
    fn from(value: u16) -> Vector {
        Self {
            dimension: 16,
            limbs: vec![value as u64]
        }
    }
}

/// Converts an `u32` into an 32-bit vector.
impl convert::From<u32> for Vector {
    fn from(value: u32) -> Vector {
        Self {
            dimension: 32,
            limbs: vec![value as u64]
        }
    }
}

/// Converts an `u64` into an 64-bit vector.
impl convert::From<u64> for Vector {
    fn from(value: u64) -> Vector {
        Self {
            dimension: 64,
            limbs: vec![value]
        }
    }
}

/// Converts an `u128` into an 128-bit vector.
impl convert::From<u128> for Vector {
    fn from(value: u128) -> Vector {
        Self {
            dimension: 128,
            limbs: vec![(value & 0xffffffff_ffffffff) as u64, (value >> 64) as u64]
        }
    }
}

/// Converts an 8-bit vector into an `u8`.
///
/// # Errors
///
/// Returns an error if `self.dimension != 8`.
impl convert::TryInto<u8> for Vector {
    type Error = Error;
    fn try_into(self) -> Result<u8, Error> {
        match self.dimension {
            8 => Ok(self.limbs[0] as u8),
            _ => Err(Error::ConversionError),
        }
    }
}

/// Converts a 16-bit vector into an `u16`.
///
/// # Errors
///
/// Returns an error if `self.dimension != 16`.
impl convert::TryInto<u16> for Vector {
    type Error = Error;
    fn try_into(self) -> Result<u16, Error> {
        match self.dimension {
            16 => Ok(self.limbs[0] as u16),
            _ => Err(Error::ConversionError),
        }
    }
}

/// Converts a 32-bit vector into an `u32`.
///
/// # Errors
///
/// Returns an error if `self.dimension != 32`.
impl convert::TryInto<u32> for Vector {
    type Error = Error;
    fn try_into(self) -> Result<u32, Error> {
        match self.dimension {
            32 => Ok(self.limbs[0] as u32),
            _ => Err(Error::ConversionError),
        }
    }
}

/// Converts a 64-bit vector into an `u64`.
///
/// # Errors
///
/// Returns an error if `self.dimension != 64`.
impl convert::TryInto<u64> for Vector {
    type Error = Error;
    fn try_into(self) -> Result<u64, Error> {
        match self.dimension {
            64 => Ok(self.limbs[0]),
            _ => Err(Error::ConversionError),
        }
    }
}

/// Converts a 128-bit vector into an `u128`.
///
/// # Errors
///
/// Returns an error if `self.dimension != 128`.
impl convert::TryInto<u128> for Vector {
    type Error = Error;
    fn try_into(self) -> Result<u128, Error> {
        match self.dimension {
            128 => Ok((self.limbs[0] as u128) | ((self.limbs[1] as u128) << 64)),
            _ => Err(Error::ConversionError),
        }
    }
}

/// Implements `v + w` for vectors `w` and `w`.
///
/// # Panics
///
/// The function will panic if `self.dimension != other.dimension`.
impl ops::Add<Vector> for Vector {
    type Output = Vector;
    
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: Vector) -> Vector {
        assert_eq!(self.dimension, other.dimension);
        Vector {
            dimension: self.dimension, 
            limbs: self.limbs.iter().zip(other.limbs.iter()).map( |(x, y)| x ^ y).collect()
        }
    }
}

/// Implements `v + w` for vector references `v` and `w`.
///
/// # Panics
///
/// The function will panic if `self.dimension != other.dimension`.
impl ops::Add<&Vector> for &Vector {
    type Output = Vector;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: &Vector) -> Vector {
        assert_eq!(self.dimension, other.dimension);
        Vector {
            dimension: self.dimension, 
            limbs: self.limbs.iter().zip(other.limbs.iter()).map( |(x, y)| *x ^ *y).collect()
        }
    }
}

/// Implements `v += w` for vectors `v` and `w`.
///
/// # Panics
///
/// The function will panic if `self.dimension != other.dimension`.
impl ops::AddAssign<Vector> for Vector {
    fn add_assign(&mut self, other: Vector) {
        assert_eq!(self.dimension, other.dimension);
        self.limbs.iter_mut().zip(other.limbs.iter()).for_each(|(x, y)| { *x ^= *y });
    }
}

/// Implements `v += w` for vectors `v` and `w`.
///
/// # Panics
///
/// The function will panic if `self.dimension != other.dimension`.
impl ops::AddAssign<&Vector> for Vector {
    fn add_assign(&mut self, other: &Vector) {
        assert_eq!(self.dimension, other.dimension);
        self.limbs.iter_mut().zip(other.limbs.iter()).for_each(|(x, y)| { *x ^= *y });
    }
}

/// A custom binary matrix type.
#[derive(Clone, PartialEq)]
pub struct Matrix {
    pub dimensions: (usize, usize),
    rows: Vec<Vector>
}

impl Matrix {
    /// Returns a new matrix with the given dimensions.
    pub fn new(rows: usize, columns: usize) -> Matrix {
        Matrix::zeroes(rows, columns)
    }

    /// Returns a new matrix with the given dimensions where each element is 0.
    pub fn zeroes(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::zeroes(columns); rows]
        }
    }
    
    /// Returns a new matrix with the given dimensions where each element is 1.
    pub fn ones(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::ones(columns); rows]
        }
    }
    
    /// Returns a new diagonal matrix with the given dimensions.
    pub fn diagonal(dimension: usize) -> Matrix {
        let mut result = Matrix::zeroes(dimension, dimension);
        (0..dimension).for_each(|i| result.set_element(i, i, 1));
        result
    }
    
    /// Returns a new diagonal matrix with the given dimensions.
    pub fn identity(dimension: usize) -> Matrix {
        Matrix::diagonal(dimension)
    }
    
    /// Returns a new random matrix with the given dimensions.
    pub fn random(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::random(columns); rows]
        }
    }
    
    /// Gets the element at `(row, column)`.
    ///
    /// # Panics
    ///
    /// Panics if either `row` or `column` is too large.
    pub fn get_element(&self, row: usize, column: usize) -> u8 {
        self.rows[row].get_element(column)
    }

    /// Sets the element at `(row, column)`.
    ///
    /// # Panics
    ///
    /// Panics if either `row` or `column` is too large.
    pub fn set_element(&mut self, row: usize, column: usize, value: u8) {
        self.rows[row].set_element(column, value);
    }

    /// Adds the given `value` to the element at `(row, column)`.
    ///
    /// # Panics
    ///
    /// Panics if either `row` or `column` is too large.
    pub fn add_to_element(&mut self, row: usize, column: usize, value: u8) {
        self.rows[row].add_to_element(column, value);
    }
    
    pub fn get_row(&self, row: usize) -> Vector {
        self.rows[row].clone()
    }

    pub fn set_row(&mut self, row: usize, value: Vector) {
        self.rows[row] = value;
    }


    /// Swaps the two rows of the matrix.
    ///
    /// # Panics
    ///
    /// Panics if either index is too large.
    pub fn swap_rows(&mut self, first: usize, second: usize) {
        self.rows.swap(first, second);
    }

    /// Adds the vector to the given row.
    ///
    /// # Panics
    ///
    /// Panics if row is too large, or if `self.dimensions.1 != value.dimension`.
    pub fn add_to_row(&mut self, row: usize, value: &Vector) {
        self.rows[row] += value;
    }
    
    fn get_left_delim(&self, row: usize) -> String {
        if row == 0 {
            String::from("/ ")
        } else if row == self.dimensions.0 - 1 {
            String::from("\\ ")
        } else {
            String::from("| ")
        }
    }

    fn get_right_delim(&self, row: usize) -> String {
        if row == 0 {
            String::from(" \\")
        } else if row == self.dimensions.0 - 1 {
            String::from(" /")
        } else {
            String::from(" |")
        }
    }
}

impl fmt::Debug for Matrix {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for row in &self.rows {
            writeln!(formatter, "| {:?} |", row)?;
        }
        Ok(())
    }
}

impl fmt::Display for Matrix {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.dimensions.0 {
            write!(formatter, "{}", self.get_left_delim(i))?;
            for j in 0..self.dimensions.1 {
                if j == 0 {
                } else {
                    write!(formatter, ", ")?;
                }
                write!(formatter, "{}", self.get_element(i, j))?
            }
            writeln!(formatter, "{}", self.get_right_delim(i))?;
        }
        Ok(())
    }
}

/// Implements `A + B` for matrices `A` and `B`.
///
/// # Panics
///
/// Panics if `self.dimensions != other.dimensions`.
impl ops::Add<Matrix> for Matrix {
    type Output = Matrix;

    fn add(self, other: Matrix) -> Matrix {
        assert_eq!(self.dimensions, other.dimensions);
        Matrix {
            dimensions: self.dimensions,
            rows: self.rows.iter().zip(other.rows.iter()).map( |(v, w)| v + w).collect()
        }
    }
}

/// Implements `A + B` for matrix references `A` and `B`.
///
/// # Panics
///
/// Panics if `self.dimensions != other.dimensions`.
impl ops::Add<&Matrix> for &Matrix {
    type Output = Matrix;

    fn add(self, other: &Matrix) -> Matrix {
        assert_eq!(self.dimensions, other.dimensions);
        Matrix {
            dimensions: self.dimensions,
            rows: self.rows.iter().zip(other.rows.iter()).map( |(v, w)| v + w).collect()
        }
    }
}

/// Implements `A += B` for matrices `A` and `B`.
///
/// # Panics
///
/// Panics if `self.dimensions != other.dimensions`.
impl ops::AddAssign<Matrix> for Matrix {
    fn add_assign(&mut self, other: Matrix) {
        assert_eq!(self.dimensions, other.dimensions);
        self.rows.iter_mut().zip(other.rows.iter()).for_each(|(v, w)| { *v += w });
    }
}

/// Implements `A += B` for matrix `A` and matrix reference `B`.
///
/// # Panics
///
/// Panics if `self.dimensions != other.dimensions`.
impl ops::AddAssign<&Matrix> for Matrix {
    fn add_assign(&mut self, other: &Matrix) {
        assert_eq!(self.dimensions, other.dimensions);
        self.rows.iter_mut().zip(other.rows.iter()).for_each(|(v, w)| { *v += w });
    }
}

/// Shifts each row down by rhs rows.
impl ops::Shl<usize> for Matrix {
    type Output = Matrix;

    fn shl(self, rhs: usize) -> Matrix {
        let rows = (0..self.dimensions.0).map(|i| {
            if i >= rhs {
                self.rows[i - rhs].clone()
            } else {
                Vector::zeroes(self.dimensions.1)
            }
        }).collect();
        Matrix {
            dimensions: self.dimensions,
            rows
        }
    }
}

/// Shifts each row down by `rhs` rows.
impl ops::Shl<usize> for &Matrix {
    type Output = Matrix;

    fn shl(self, rhs: usize) -> Matrix {
        let rows = (0..self.dimensions.0).map(|i| {
            if i >= rhs {
                self.rows[i - rhs].clone()
            } else {
                Vector::zeroes(self.dimensions.1)
            }
        }).collect();
        Matrix {
            dimensions: self.dimensions,
            rows
        }
    }
}

/// Shifts each row down by `rhs` rows.
impl ops::Shl<i32> for Matrix {
    type Output = Matrix;

    fn shl(self, rhs: i32) -> Matrix {
        self.shl(rhs as usize)
    }
}

/// Shifts each row down by `rhs` rows.
impl ops::Shl<i32> for &Matrix {
    type Output = Matrix;

    fn shl(self, rhs: i32) -> Matrix {
        self.shl(rhs as usize)
    }
}

/// Shifts each row down by `rhs` rows.
impl ops::Shl<u32> for Matrix {
    type Output = Matrix;

    fn shl(self, rhs: u32) -> Matrix {
        self.shl(rhs as usize)
    }
}

/// Shifts each row down by `rhs` rows.
impl ops::Shl<u32> for &Matrix {
    type Output = Matrix;

    fn shl(self, rhs: u32) -> Matrix {
        self.shl(rhs as usize)
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<usize> for Matrix {
    type Output = Matrix;

    fn shr(self, rhs: usize) -> Matrix {
        let rows = (0..self.dimensions.0).map(|i| {
            if i + rhs < self.dimensions.0 {
                self.rows[i + rhs].clone()
            } else {
                Vector::zeroes(self.dimensions.1)
            }
        }).collect();
        Matrix {
            dimensions: self.dimensions,
            rows
        }
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<usize> for &Matrix {
    type Output = Matrix;

    fn shr(self, rhs: usize) -> Matrix {
        let rows = (0..self.dimensions.0).map(|i| {
            if i + rhs < self.dimensions.0 {
                self.rows[i + rhs].clone()
            } else {
                Vector::zeroes(self.dimensions.1)
            }
        }).collect();
        Matrix {
            dimensions: self.dimensions,
            rows
        }
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<i32> for Matrix {
    type Output = Matrix;

    fn shr(self, rhs: i32) -> Matrix {
        self.shr(rhs as usize)
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<i32> for &Matrix {
    type Output = Matrix;

    fn shr(self, rhs: i32) -> Matrix {
        self.shr(rhs as usize)
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<u32> for Matrix {
    type Output = Matrix;

    fn shr(self, rhs: u32) -> Matrix {
        self.shr(rhs as usize)
    }
}

/// Shifts each row up by `rhs` rows.
impl ops::Shr<u32> for &Matrix {
    type Output = Matrix;

    fn shr(self, rhs: u32) -> Matrix {
        self.shr(rhs as usize)
    }
}

/// Creates a new matrix where row `i` is given by
///
///   - row `i` of self if element `i` of `rhs` is 1,
///   - `(0, 0, ..., 0)` otherwise.
impl ops::BitAnd<Vector> for Matrix {
    type Output = Matrix;

    fn bitand(self, rhs: Vector) -> Matrix {
        assert_eq!(self.dimensions.0, rhs.dimension);
        let rows = (0..self.dimensions.0)
            .map(|i| { if rhs.get_element(i) == 1 { 
                self.rows[i].clone() 
            } else { 
                Vector::zeroes(self.dimensions.0) 
            }})
            .collect();
        
        Matrix {
            dimensions: self.dimensions,
            rows
        }
    }
}

/// A linear equation solver implemented using Gauss elimination.
pub struct GaussElimination {
    lhs: Matrix,
    rhs: Vector
}

impl GaussElimination {
    /// Returns a new solver over the given matrix, with the given right-hand side.
    pub fn new(lhs: Matrix, rhs: Vector) -> Self {
        assert_eq!(lhs.dimensions.0, rhs.dimension);
        Self { lhs, rhs }
    }
    
    fn pivot(&mut self, column: usize) -> Result<(), Error> {
        for row in column..self.lhs.dimensions.0 {
            if self.lhs.get_element(row, column) != 0 {
                self.lhs.swap_rows(column, row);
                self.rhs.swap_elements(column, row);
                return Ok(())
            }
        }
        Err(Error::UnderDeterminedSystemError)
    }

    /// Solves the system and returns the unique solution, if it exists.
    /// (The solver does not currently handle under-determined systems.)
    pub fn solve(&mut self) -> Result<Vector, Error> {
        for column in 0..self.lhs.dimensions.1 {
            self.pivot(column)?;
            let current_row = self.lhs.get_row(column);
            let current_element = self.rhs.get_element(column);
            for row in 0..self.lhs.dimensions.0 {
                if row == column { 
                    continue; 
                } else if self.lhs.get_element(row, column) == 1 {
                    self.lhs.add_to_row(row, &current_row);
                    self.rhs.add_to_element(row, current_element);
                }
            }
        }
        // Verify that the system is consistent in the case when
        // the matrix lhs has more rows than columns.
        for row in self.lhs.dimensions.1..self.lhs.dimensions.0 {
            if self.rhs.get_element(row) != 0 {
                return Err(Error::InconsistentSystemError);
            }
        }
        Ok(self.rhs.clone())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::{From, TryInto};

    #[test]
    fn vector_creation() {
        let mut vector = Vector::new(123);
        assert_eq!(vector.dimension, 123);

        for i in 0..vector.dimension {
            if i % 2 == 1 { vector.set_element(i, 1); }
        }
        for i in 0..vector.dimension {
            assert_eq!(vector.get_element(i), (i % 2) as u8);
        }

        let zeroes = Vector::zeroes(100);
        for i in 0..zeroes.dimension {
            assert_eq!(zeroes.get_element(i), 0);
        }
        
        let ones = Vector::ones(101);
        for i in 0..ones.dimension {
            assert_eq!(ones.get_element(i), 1);
        }
    
        let vector = Vector::random(128);
        let value: u128 = vector.clone().try_into().unwrap();
        assert_eq!(Vector::from(value), vector);
    
        let vector = Vector::random(64);
        let value: u64 = vector.clone().try_into().unwrap();
        assert_eq!(Vector::from(value), vector);
    
        let vector = Vector::random(32);
        let value: u32 = vector.clone().try_into().unwrap();
        assert_eq!(Vector::from(value), vector);
    
        let vector = Vector::random(16);
        let value: u16 = vector.clone().try_into().unwrap();
        assert_eq!(Vector::from(value), vector);
    
        let vector = Vector::random(8);
        let value: u8 = vector.clone().try_into().unwrap();
        assert_eq!(Vector::from(value), vector);
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn invalid_vector_access() {
        let vector = Vector::new(255);
        vector.get_element(255);
    }
   
    #[test]
    fn vector_addition() {
        let mut lhs = Vector::zeroes(17);
        let mut rhs = Vector::zeroes(17);
        for i in 0..17 {
            if i % 2 == 0 { 
                lhs.set_element(i, 1); 
                assert_eq!(lhs.get_element(i), 1); 
                assert_eq!(rhs.get_element(i), 0); 
            } else {
                rhs.set_element(i, 1);
                assert_eq!(rhs.get_element(i), 1); 
                assert_eq!(lhs.get_element(i), 0); 
            }
        }
        assert_eq!(&lhs + &rhs, Vector::ones(17));
        assert_eq!(lhs.clone() + rhs.clone(), Vector::ones(17));
        
        let mut result = lhs;
        result += rhs;
        assert_eq!(result, Vector::ones(17));
    }

    #[test]
    fn matrix_creation() {
        let mut matrix = Matrix::new(25, 43);
        for (i, j) in (0..matrix.dimensions.0).zip(0..matrix.dimensions.1) {
            if (i + j) % 2 == 1 { matrix.set_element(i, j, 1)}
        }
        for (i, j) in (0..matrix.dimensions.0).zip(0..matrix.dimensions.1) {
            assert_eq!(matrix.get_element(i, j), (i + j) as u8 % 2);
        }

        let zeroes = Matrix::zeroes(32, 33);
        for (i, j) in (0..zeroes.dimensions.0).zip(0..zeroes.dimensions.1) {
            assert_eq!(zeroes.get_element(i, j), 0);
        }
        
        let ones = Matrix::ones(32, 33);
        for (i, j) in (0..ones.dimensions.0).zip(0..ones.dimensions.1) {
            assert_eq!(ones.get_element(i, j), 1);
        }
        
        let diagonal = Matrix::diagonal(32);
        for (i, j) in (0..diagonal.dimensions.0).zip(0..diagonal.dimensions.1) {
            if i == j {
                assert_eq!(diagonal.get_element(i, j), 1);
            } else {
                assert_eq!(diagonal.get_element(i, j), 0);
            }
        }
    }
    
    #[test]
    #[should_panic]
    fn invalid_matrix_access() {
        let matrix = Matrix::new(12, 34);
        matrix.get_element(12, 0);
    }
    
    #[test]
    fn matrix_addition() {
        let mut lhs = Matrix::zeroes(17, 17);
        let mut rhs = Matrix::zeroes(17, 17);
        for i in 0..lhs.dimensions.0 {
            for j in 0..lhs.dimensions.1 {
                if (i + j) % 2 == 0 { 
                    lhs.set_element(i, j, 1); 
                    assert_eq!(lhs.get_element(i, j), 1); 
                    assert_eq!(rhs.get_element(i, j), 0); 
                } else {
                    rhs.set_element(i, j, 1);
                    assert_eq!(lhs.get_element(i, j), 0); 
                    assert_eq!(rhs.get_element(i, j), 1); 
                }
            }
        }
        assert_eq!(&lhs + &rhs, Matrix::ones(17, 17));
        assert_eq!(lhs.clone() + rhs.clone(), Matrix::ones(17, 17));
        
        let mut result = lhs;
        result += rhs;
        assert_eq!(result, Matrix::ones(17, 17));
    }

    #[test]
    fn gauss_elimination() {
        for _ in 0..10 {
            let size = rand::thread_rng().gen_range(1, 256);
            let mut lhs = Matrix::diagonal(size);
            let mut rhs = Vector::random(size);
            let solution = rhs.clone();
            for i in 0..rhs.dimension {
                // Randomly add current row to other rows.
                for j in 0..rhs.dimension {
                    if i != j && rand::thread_rng().gen::<bool>() {
                        lhs.add_to_row(j, &lhs.get_row(i));
                        rhs.add_to_element(j, rhs.get_element(i))
                    }
                }
                // Swap current row with another random row.
                let j = rand::thread_rng().gen_range(0, i + 1);
                lhs.swap_rows(i, j);
                rhs.swap_elements(i, j);
            }
            
            let mut system = GaussElimination::new(lhs, rhs);
            let result = system.solve();

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), solution);
        }
    }
}
