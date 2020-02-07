use rand;
use rand::Rng;
use std::{fmt, ops};

#[derive(Debug)]
pub enum Error {
    InconsistentSystemError,
    UnderDeterminedSystemError,
}

// Custom bit vector type.
#[derive(Clone, PartialEq)]
pub struct Vector {
    pub dimension: usize,
    limbs: Vec<u64>,
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

impl Vector {
    // Returns a new vector of the given dimension.
    pub fn new(dimension: usize) -> Self {
        Self::zeroes(dimension)
    }

    // Returns a new vector (0, 0, ..., 0) of the given dimension.
    pub fn zeroes(dimension: usize) -> Self {
        Self {
            dimension,
            limbs: vec![0; (dimension + 63) >> 6]
        }
    }

    // Returns a new vector (1, 1, ..., 1) of the given dimension.
    pub fn ones(dimension: usize) -> Self {
        let mut result = Self {
            dimension,
            limbs: vec![0xffffffff_ffffffff; (dimension + 63) >> 6]
        };
        // Ensure that unused bits are always zero. Note: This is
        // required to ensure that the derived implementation of 
        // the PartialEq trait does what it should.
        let mask = (1 << (dimension & 63)) - 1;
        result.limbs.last_mut().map(|x| *x &= mask);
        result
    }

    pub fn random(dimension: usize) -> Self {
        let mut result = Vector::zeroes(dimension);
        (0..dimension)
            .filter(|_| rand::thread_rng().gen::<bool>())
            .for_each(|i| result.set_element(i, 1));
        result
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            dimension: 128,
            limbs: vec![(value & 0xffffffff_ffffffff) as u64, (value >> 64) as u64]
        }
    }

    pub fn to_u128(&self) -> u128 {
        assert!(self.dimension == 128);
        ((self.limbs[1] as u128) << 64) ^ (self.limbs[0] as u128)
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            dimension: 64,
            limbs: vec![value as u64]
        }
    }

    pub fn to_u64(&self) -> u64 {
        assert!(self.dimension == 64);
        self.limbs[0]
    }
    
    pub fn from_u32(value: u32) -> Self {
        Self {
            dimension: 32,
            limbs: vec![value as u64]
        }
    }
    
    pub fn to_u32(&self) -> u32 {
        assert!(self.dimension == 32);
        (self.limbs[0] & 0xffffffff) as u32
    }
    
    pub fn from_u16(value: u16) -> Self {
        Self {
            dimension: 16,
            limbs: vec![value as u64]
        }
    }
    
    pub fn to_u16(&self) -> u16 {
        assert!(self.dimension == 16);
        (self.limbs[0] & 0xffff) as u16
    }
    
    pub fn from_u8(value: u8) -> Self {
        Self {
            dimension: 8,
            limbs: vec![value as u64]
        }
    }
    
    pub fn to_u8(&self) -> u8 {
        assert!(self.dimension == 8);
        (self.limbs[0] & 0xff) as u8
    }
    
    // Vector::get_element will panic if index is too large.
    #[inline]
    pub fn get_element(&self, index: usize) -> u8 {
        debug_assert!(index < self.dimension);
        ((self.limbs[index >> 6] >> (index & 63)) & 1) as u8
    }

    // Vector::set_element will panic if index is too large.
    #[inline]
    pub fn set_element(&mut self, index: usize, value: u8) {
        debug_assert!(index < self.dimension);
        let mask = 0xffffffff_ffffffff ^ (1 << (index & 63));
        let value = ((value & 1) as u64) << (index & 63);
        self.limbs[index >> 6] = (self.limbs[index >> 6] & mask) ^ value;
    }

    #[inline]
    pub fn swap_elements(&mut self, first: usize, second: usize) {
        let first_element = self.get_element(first);
        let second_element = self.get_element(second);
        self.set_element(first, second_element);
        self.set_element(second, first_element);
    }

    pub fn add_to_element(&mut self, index: usize, value: u8) {
        self.set_element(index, self.get_element(index) ^ value);
    }
}

// Implements v + w for vectors w and w.
impl ops::Add<&Vector> for &Vector {
    type Output = Vector;

    fn add(self, other: &Vector) -> Vector {
        assert_eq!(self.dimension, other.dimension);
        Vector {
            dimension: self.dimension, 
            limbs: self.limbs.iter().zip(other.limbs.iter()).map( |(x, y)| x ^ y).collect()
        }
    }
}

// Implements v += w for vectors w and w.
impl ops::AddAssign<&Vector> for Vector {
    fn add_assign(&mut self, other: &Vector) {
        assert_eq!(self.dimension, other.dimension);
        self.limbs.iter_mut().zip(other.limbs.iter()).for_each(|(x, y)| { *x ^= *y });
    }
}

#[derive(Clone, PartialEq)]
pub struct Matrix {
    pub dimensions: (usize, usize),
    rows: Vec<Vector>
}

impl Matrix {
    // Returns a new matrix with the given dimensions.
    pub fn new(rows: usize, columns: usize) -> Matrix {
        Matrix::zeroes(rows, columns)
    }

    pub fn zeroes(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::zeroes(columns); rows]
        }
    }
    
    pub fn ones(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::ones(columns); rows]
        }
    }
    
    pub fn diagonal(rows: usize) -> Matrix {
        let mut result = Matrix::zeroes(rows, rows);
        (0..rows).for_each(|i| result.set_element(i, i, 1));
        result
    }
    
    pub fn random(rows: usize, columns: usize) -> Matrix {
        Matrix { 
            dimensions: (rows, columns),
            rows: vec![Vector::random(columns); rows]
        }
    }
    
    // Matrix::get_element will panic if either row or column is too large.
    pub fn get_element(&self, row: usize, column: usize) -> u8 {
        self.rows[row].get_element(column)
    }

    // Matrix::set_element will panic if either row or column is too large.
    pub fn set_element(&mut self, row: usize, column: usize, value: u8) {
        self.rows[row].set_element(column, value);
    }

    pub fn add_to_element(&mut self, row: usize, column: usize, value: u8) {
        self.rows[row].add_to_element(column, value);
    }
    
    pub fn get_row(&self, row: usize) -> Vector {
        self.rows[row].clone()
    }

    pub fn set_row(&mut self, row: usize, value: Vector) {
        self.rows[row] = value;
    }

    pub fn swap_rows(&mut self, first: usize, second: usize) {
        self.rows.swap(first, second);
    }

    pub fn add_to_row(&mut self, row: usize, value: &Vector) {
        self.rows[row] += value;
    }
    
    fn get_left_delim(&self, row: usize) -> String {
        if row == 0 {
            return String::from("/ ");
        } else if row == self.dimensions.0 - 1 {
            return String::from("\\ ");
        } else {
            return String::from("| ");
        }
    }

    fn get_right_delim(&self, row: usize) -> String {
        if row == 0 {
            return String::from(" \\");
        } else if row == self.dimensions.0 - 1 {
            return String::from(" /");
        } else {
            return String::from(" |");
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

// Implements A + B for matrices A and B.
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

// Implements A += B for matrices A and B.
impl ops::AddAssign<&Matrix> for Matrix {
    fn add_assign(&mut self, other: &Matrix) {
        assert_eq!(self.dimensions, other.dimensions);
        self.rows.iter_mut().zip(other.rows.iter()).for_each(|(v, w)| { *v += w });
    }
}

pub struct GaussElimination {
    lhs: Matrix,
    rhs: Vector
}

impl GaussElimination {
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
        assert_eq!(Vector::from_u128(vector.to_u128()), vector);
    
        let vector = Vector::random(64);
        assert_eq!(Vector::from_u64(vector.to_u64()), vector);
    
        let vector = Vector::random(32);
        assert_eq!(Vector::from_u32(vector.to_u32()), vector);
    
        let vector = Vector::random(16);
        assert_eq!(Vector::from_u16(vector.to_u16()), vector);
    
        let vector = Vector::random(8);
        assert_eq!(Vector::from_u8(vector.to_u8()), vector);
    }

    #[test]
    #[should_panic]
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
        
        let mut result = lhs;
        result += &rhs;
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
        
        let mut result = lhs;
        result += &rhs;
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
