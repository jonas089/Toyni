//! Fast Reed-Solomon Interactive Oracle Proof (FRI) protocol implementation.
//!
//! This module provides functionality for the FRI protocol, which is used in the STARK proving system
//! to prove the low-degree of polynomials. It includes functions for polynomial folding and interpolation.
//!
//! # Protocol Overview
//!
//! The FRI protocol is a key component of STARK proofs, providing a way to prove that a polynomial
//! has a low degree by iteratively reducing the size of the evaluation domain while maintaining
//! the low-degree property.
//!
//! The protocol works by:
//! 1. Starting with evaluations of a polynomial over a large domain
//! 2. Iteratively folding the evaluations using random challenges
//! 3. Reducing the domain size by half in each round
//! 4. Finally checking the degree of the resulting polynomial
//!
//! # Security Considerations
//!
//! The current implementation:
//! - Uses random challenges from `rand::thread_rng()`
//! - Does not implement the full FRI protocol (missing commitment phase)
//! - Exposes raw evaluations instead of commitments
//!
//! To achieve full security, we need to:
//! - Implement the commitment phase using Merkle trees
//! - Use Fiat-Shamir transform for challenge generation
//! - Add proper soundness analysis
//!
//! # Mathematical Details
//!
//! For a polynomial f(x) over a domain D, the FRI folding operation computes:
//! ```
//! f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
//! ```
//! where β is a random challenge value. This operation:
//! - Reduces the domain size by half
//! - Maintains the low-degree property
//! - Creates a new polynomial that can be verified

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_poly::{
    EvaluationDomain, Evaluations, GeneralEvaluationDomain, univariate::DensePolynomial,
};

/// Performs one round of FRI folding on evaluations over a symmetric domain.
///
/// The FRI folding operation reduces the size of the evaluation domain by half while
/// maintaining the low-degree property of the polynomial. This is done by combining
/// pairs of evaluations using a random challenge value.
///
/// # Arguments
///
/// * `evals` - The evaluations to fold
/// * `beta` - The random challenge value for this round of folding
///
/// # Returns
///
/// The folded evaluations
///
/// # Panics
///
/// Panics if the length of evaluations is not even
///
/// # Details
///
/// For each pair of points (x, -x), computes:
/// ```
/// f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
/// ```
///
/// # Security Note
///
/// The current implementation:
/// - Uses raw evaluations instead of commitments
/// - Does not implement the full FRI protocol
/// - Leaks information about the polynomial
pub fn fri_fold(evals: &[Fr], beta: Fr) -> Vec<Fr> {
    assert!(evals.len() % 2 == 0, "Evaluations length must be even");
    let mut result = Vec::with_capacity(evals.len() / 2);
    let half = evals.len() / 2;
    let half_inv = Fr::from(2u64).inverse().unwrap();

    // For each pair of points (x, -x), compute f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
    for i in 0..half {
        // In FRI, we pair points as (x, -x) where x is the i-th point and -x is the (i + half)-th point
        let a = evals[i];
        let b = evals[i + half];
        // f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
        let folded = (a + b) * half_inv + (a - b) * half_inv * beta;
        result.push(folded);
    }

    result
}

/// Interpolates a polynomial from a set of points.
///
/// This function uses the Fast Fourier Transform (FFT) to efficiently interpolate
/// a polynomial from its evaluations over a domain.
///
/// # Arguments
///
/// * `xs` - The x-coordinates of the points
/// * `ys` - The y-coordinates of the points
///
/// # Returns
///
/// The interpolated polynomial
///
/// # Panics
///
/// Panics if:
/// * The lengths of xs and ys are not equal
/// * The domain size is not a power of 2
///
/// # Details
///
/// The interpolation is performed using the FFT algorithm, which requires that:
/// 1. The domain size is a power of 2
/// 2. The domain points are evenly spaced
/// 3. The domain is closed under multiplication
///
/// # Security Note
///
/// The current implementation:
/// - Exposes raw polynomial coefficients
/// - Does not use commitments
/// - May leak information about the polynomial
pub fn interpolate_poly(xs: &[Fr], ys: &[Fr]) -> DensePolynomial<Fr> {
    assert_eq!(xs.len(), ys.len(), "Mismatched lengths");
    let domain =
        GeneralEvaluationDomain::<Fr>::new(xs.len()).expect("Domain size must be a power of 2");
    // Build an evaluation struct (domain + values)
    let evals = Evaluations::from_vec_and_domain(ys.to_vec(), domain);
    // Interpolate the polynomial
    evals.interpolate()
}
