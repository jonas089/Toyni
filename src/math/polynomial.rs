//! Polynomial operations for the Stark proving system.
//!
//! This module provides a basic implementation of polynomial arithmetic operations
//! required for the Stark proving system. It includes operations like addition,
//! multiplication, division, and evaluation over finite fields.
//!
//! The implementation is optimized for use in the Stark proving system, where
//! polynomials are used to represent execution traces and constraints.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;

#[derive(Debug, Clone)]
/// Represents a polynomial with finite field coefficients.
///
/// The polynomial is stored as a vector of coefficients, where the index represents
/// the power of x. For example, [1, 2, 3] represents 3x² + 2x + 1.
///
/// # Invariants
///
/// * The coefficients vector should not have trailing zeros
/// * All coefficients should be valid field elements
pub struct Polynomial {
    /// The coefficients of the polynomial, stored in ascending order of power.
    pub coefficients: Vec<Fr>,
}

impl Polynomial {
    /// Creates a new polynomial from a vector of coefficients.
    ///
    /// # Arguments
    ///
    /// * `coefficients` - Vector of coefficients in ascending order of power
    ///
    /// # Returns
    ///
    /// A new polynomial with the given coefficients
    ///
    /// # Details
    ///
    /// Trailing zeros are removed from the coefficients vector to maintain
    /// the invariant that there are no trailing zeros.
    pub fn new(coefficients: Vec<Fr>) -> Self {
        // Remove trailing zeros
        let mut coeffs = coefficients;
        while coeffs.last().map_or(false, |&x| x.is_zero()) {
            coeffs.pop();
        }
        Polynomial {
            coefficients: coeffs,
        }
    }

    /// Returns the degree of the polynomial.
    ///
    /// The degree is the highest power of x with a non-zero coefficient.
    /// For the zero polynomial, the degree is 0.
    ///
    /// # Returns
    ///
    /// The degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.coefficients.is_empty() {
            0
        } else {
            self.coefficients.len() - 1
        }
    }

    /// Returns the leading coefficient of the polynomial.
    ///
    /// The leading coefficient is the coefficient of the highest power term.
    /// For the zero polynomial, returns 0.
    ///
    /// # Returns
    ///
    /// The leading coefficient
    pub fn leading_coefficient(&self) -> Fr {
        self.coefficients.last().copied().unwrap_or(Fr::zero())
    }

    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|c| c.is_zero())
    }

    pub fn zero() -> Self {
        Self::new(vec![Fr::zero()])
    }

    /// Divides this polynomial by another polynomial using long division.
    ///
    /// # Arguments
    ///
    /// * `divisor` - The polynomial to divide by
    ///
    /// # Returns
    ///
    /// Option containing a tuple of (quotient, remainder) if division is possible,
    /// None if the divisor is zero or empty
    ///
    /// # Details
    ///
    /// The division is performed using the standard long division algorithm
    /// over the finite field. The remainder will have degree less than the divisor.
    pub fn divide(&self, divisor: &Polynomial) -> Option<(Polynomial, Polynomial)> {
        if divisor.coefficients.is_empty() || divisor.leading_coefficient().is_zero() {
            return None;
        }

        let dividend = self.coefficients.clone();
        let divisor_degree = divisor.degree();
        let dividend_degree = self.degree();

        // If dividend degree is less than divisor degree, quotient is zero
        if dividend_degree < divisor_degree {
            return Some((Polynomial::zero(), self.clone()));
        }

        let mut quotient = vec![Fr::zero(); dividend_degree - divisor_degree + 1];
        let mut remainder = dividend.clone();

        // Perform long division
        for i in (0..=dividend_degree - divisor_degree).rev() {
            let leading_coeff = remainder[i + divisor_degree];
            if leading_coeff.is_zero() {
                continue;
            }

            quotient[i] = leading_coeff / divisor.leading_coefficient();

            // Subtract divisor * quotient term from remainder
            for j in 0..=divisor_degree {
                remainder[i + j] -= quotient[i] * divisor.coefficients[j];
            }
        }

        // Trim leading zeros from remainder
        while !remainder.is_empty() && remainder.last().unwrap().is_zero() {
            remainder.pop();
        }

        Some((Polynomial::new(quotient), Polynomial::new(remainder)))
    }

    /// Converts the polynomial to a string representation.
    ///
    /// # Returns
    ///
    /// A string representation of the polynomial in standard form
    ///
    /// # Details
    ///
    /// The polynomial is displayed in standard form with terms in descending
    /// order of degree. Zero terms are omitted.
    pub fn to_string(&self) -> String {
        if self.coefficients.is_empty() {
            return "0".to_string();
        }

        let mut terms = Vec::new();
        for (i, &coeff) in self.coefficients.iter().enumerate() {
            if !coeff.is_zero() {
                let term = if i == 0 {
                    format!("{}", coeff)
                } else if i == 1 {
                    format!("{}x", coeff)
                } else {
                    format!("{}x^{}", coeff, i)
                };
                terms.push(term);
            }
        }

        if terms.is_empty() {
            "0".to_string()
        } else {
            terms.join(" + ")
        }
    }

    /// Adds two polynomials.
    ///
    /// # Arguments
    ///
    /// * `other` - The polynomial to add
    ///
    /// # Returns
    ///
    /// The sum of the two polynomials
    ///
    /// # Details
    ///
    /// Addition is performed coefficient-wise over the finite field.
    pub fn add(&self, other: &Polynomial) -> Polynomial {
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result = vec![Fr::zero(); max_len];

        for i in 0..self.coefficients.len() {
            result[i] += self.coefficients[i];
        }

        for i in 0..other.coefficients.len() {
            result[i] += other.coefficients[i];
        }

        Polynomial::new(result)
    }

    /// Multiplies two polynomials.
    ///
    /// # Arguments
    ///
    /// * `other` - The polynomial to multiply by
    ///
    /// # Returns
    ///
    /// The product of the two polynomials
    ///
    /// # Details
    ///
    /// Multiplication is performed using the standard polynomial multiplication
    /// algorithm over the finite field.
    pub fn multiply(&self, other: &Polynomial) -> Polynomial {
        if self.coefficients.is_empty() || other.coefficients.is_empty() {
            return Polynomial::new(vec![]);
        }

        let mut result = vec![Fr::zero(); self.degree() + other.degree() + 1];

        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                result[i + j] += self.coefficients[i] * other.coefficients[j];
            }
        }

        Polynomial::new(result)
    }

    /// Evaluates the polynomial at a given point.
    ///
    /// # Arguments
    ///
    /// * `x` - The point at which to evaluate the polynomial
    ///
    /// # Returns
    ///
    /// The value of the polynomial at x
    ///
    /// # Details
    ///
    /// Evaluation is performed using Horner's method for efficiency.
    pub fn evaluate(&self, x: Fr) -> Fr {
        if self.coefficients.is_empty() {
            return Fr::zero();
        }

        let mut result = self.coefficients[self.coefficients.len() - 1];
        for &coeff in self.coefficients.iter().rev().skip(1) {
            result = result * x + coeff;
        }
        result
    }

    /// Converts a dense polynomial from the ark-poly crate to our polynomial type.
    ///
    /// # Arguments
    ///
    /// * `poly` - The dense polynomial to convert
    ///
    /// # Returns
    ///
    /// A new polynomial with the same coefficients
    pub fn from_dense_poly(poly: DensePolynomial<Fr>) -> Self {
        Polynomial::new(poly.coeffs)
    }
}
