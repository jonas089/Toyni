//! Fast Reed-Solomon Interactive Oracle Proof (FRI) protocol implementation.
//!
//! This module provides functionality for the FRI protocol, which is used in the Stark proving system
//! to prove the low-degree of polynomials. It includes functions for polynomial folding and interpolation.

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_poly::{
    EvaluationDomain, Evaluations, GeneralEvaluationDomain, univariate::DensePolynomial,
};

/// Performs one round of FRI folding on evaluations over a symmetric domain.
///
/// The FRI folding operation reduces the size of the evaluation domain by half while
/// maintaining the low-degree property of the polynomial.
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
pub fn interpolate_poly(xs: &[Fr], ys: &[Fr]) -> DensePolynomial<Fr> {
    assert_eq!(xs.len(), ys.len(), "Mismatched lengths");
    let domain =
        GeneralEvaluationDomain::<Fr>::new(xs.len()).expect("Domain size must be a power of 2");
    // Build an evaluation struct (domain + values)
    let evals = Evaluations::from_vec_and_domain(ys.to_vec(), domain);
    // Interpolate the polynomial
    evals.interpolate()
}
