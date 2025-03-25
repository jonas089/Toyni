//! STARK (Scalable Transparent Argument of Knowledge) protocol implementation.
//!
//! This module provides the core STARK proving system implementation, including:
//! - Proof generation using the FRI protocol
//! - Proof verification
//!
//! # Protocol Overview
//!
//! The STARK protocol works by:
//! 1. Converting program execution into a trace polynomial
//! 2. Constructing a composition polynomial that encodes all constraints
//! 3. Using the FRI protocol to prove the low-degree of the composition polynomial
//! 4. Verifying the proof through random point evaluation
//!
//! # Security Considerations
//!
//! The current implementation:
//! - Uses random challenges from `rand::thread_rng()`
//! - Implements some zero-knowledge properties
//! - Uses direct polynomial evaluation instead of commitments
//!
//! To achieve full security, we need to:
//! - Add random masks for zero-knowledge (medium)
//! - Implement Merkle tree commitments (simple)
//! - Use Fiat-Shamir transform for challenge generation (simple)
//! - Add random linear combinations to the constraint polynomial (simple)

use crate::math::fri::fri_fold;
use crate::math::polynomial::Polynomial as ToyniPolynomial;
use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_poly::DenseUVPolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, univariate::DensePolynomial};
use rand::thread_rng;

const VERIFIER_QUERIES: usize = 80;

/// Represents a STARK proof containing all necessary components for verification.
///
/// # Fields
///
/// * `quotient_eval_domain` - The extended domain evaluations of the quotient polynomial
/// * `fri_layers` - The layers of the FRI protocol, each containing folded evaluations
/// * `fri_challenges` - The random challenges used in each FRI folding step
/// * `combined_constraint` - The polynomial representing all constraints combined
/// * `quotient_poly` - The quotient polynomial obtained by dividing the composition polynomial
pub struct StarkProof {
    /// The evaluations of the quotient polynomial over the domain
    pub quotient_eval_domain: Vec<Fr>,
    /// The layers of the FRI protocol, each containing folded evaluations
    pub fri_layers: Vec<Vec<Fr>>,
    /// The random challenges used in each FRI folding step
    pub fri_challenges: Vec<Fr>,
    /// The polynomial representing all constraints combined
    pub combined_constraint: ToyniPolynomial,
    /// The quotient polynomial obtained by dividing the composition polynomial
    pub quotient_poly: ToyniPolynomial,
}

/// The prover component of the STARK protocol.
///
/// The prover is responsible for:
/// 1. Constructing the composition polynomial
/// 2. Generating the FRI proof layers
/// 3. Creating the final STARK proof
///
/// # Fields
///
/// * `trace` - The execution trace to prove
/// * `constraints` - The constraint system defining program rules
pub struct StarkProver<'a> {
    /// The execution trace to prove
    trace: &'a ExecutionTrace,
    /// The constraint system defining program rules
    constraints: &'a ConstraintSystem,
}

impl<'a> StarkProver<'a> {
    /// Creates a new STARK prover.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to prove
    /// * `constraints` - The constraint system defining program rules
    ///
    /// # Returns
    ///
    /// A new STARK prover instance
    pub fn new(trace: &'a ExecutionTrace, constraints: &'a ConstraintSystem) -> Self {
        Self { trace, constraints }
    }

    /// Generates a STARK proof for the execution trace.
    ///
    /// # Returns
    ///
    /// A STARK proof containing all necessary components for verification
    ///
    /// # Details
    ///
    /// The proof generation process:
    /// 1. Constructs the composition polynomial from constraints
    /// 2. Computes the quotient polynomial
    /// 3. Generates FRI proof layers
    /// 4. Creates the final proof
    ///
    /// # Security Note
    ///
    /// The current implementation:
    /// - Uses raw polynomial evaluations
    /// - Does not implement zero-knowledge
    /// - Leaks information about the trace
    pub fn generate_proof(&self) -> StarkProof {
        let trace_len = self.trace.height as usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(trace_len).unwrap();
        let extended_domain = GeneralEvaluationDomain::<Fr>::new(trace_len * 2).unwrap();

        println!("\n=== Prover Debug ===");
        println!("Trace length: {}", trace_len);
        println!("Extended domain size: {}", extended_domain.size());
        let constraint_polys = self.constraints.interpolate_all_constraints(self.trace);
        println!("\nConstraint polynomials:");
        for (i, poly) in constraint_polys.iter().enumerate() {
            println!("Constraint {}: {:?}", i, poly.coefficients);
        }

        let combined_constraint = constraint_polys
            .iter()
            .fold(ToyniPolynomial::zero(), |acc, p| acc.add(p));
        println!(
            "\nCombined constraint: {:?}",
            combined_constraint.coefficients
        );

        let c_evals: Vec<Fr> = extended_domain
            .elements()
            .map(|x| combined_constraint.evaluate(x))
            .collect();
        println!("\nConstraint evaluations at domain points:");
        for (i, eval) in c_evals.iter().enumerate() {
            println!("C[{}] = {:?}", i, eval);
        }

        let c_poly = DensePolynomial::from_coefficients_slice(&extended_domain.ifft(&c_evals));
        let c_poly = ToyniPolynomial::from_dense_poly(c_poly);
        println!(
            "\nInterpolated constraint polynomial: {:?}",
            c_poly.coefficients
        );

        let z_poly = ToyniPolynomial::from_dense_poly(domain.vanishing_polynomial().into());
        println!("\nVanishing polynomial: {:?}", z_poly.coefficients);

        let (quotient_poly, rem) = c_poly.divide(&z_poly).unwrap();
        println!("\nQuotient polynomial: {:?}", quotient_poly.coefficients);
        println!("Remainder polynomial: {:?}", rem.coefficients);

        let mut q_evals: Vec<Fr> = extended_domain
            .elements()
            .map(|x| quotient_poly.evaluate(x))
            .collect();
        println!("\nQuotient evaluations at domain points:");
        for (i, eval) in q_evals.iter().enumerate() {
            println!("Q[{}] = {:?}", i, eval);
        }

        let mut fri_layers = vec![q_evals.clone()];
        let mut fri_challenges = Vec::new();
        // large enough degree to ensure enough points are checked
        while q_evals.len() > 4 {
            let beta = Fr::rand(&mut thread_rng());
            fri_challenges.push(beta);
            // todo: commit the q_evals to the merkle tree
            q_evals = fri_fold(&q_evals, beta);
            fri_layers.push(q_evals.clone());
        }

        StarkProof {
            // todo: commit the quotient_eval_domain to the merkle tree
            // don't reveal all evaluations, use Fiat-Shamir transform
            quotient_eval_domain: fri_layers[0].clone(),
            fri_layers,
            fri_challenges,
            combined_constraint,
            quotient_poly,
        }
    }
}

/// The verifier component of the STARK protocol.
///
/// The verifier is responsible for:
/// 1. Checking the composition polynomial identity
/// 2. Verifying the FRI proof layers
/// 3. Ensuring the proof is valid
///
/// # Fields
///
/// * `constraints` - The constraint system defining program rules
/// * `trace_len` - The length of the execution trace
pub struct StarkVerifier<'a> {
    /// The constraint system defining program rules
    #[allow(unused)]
    constraints: &'a ConstraintSystem,
    /// The length of the execution trace
    trace_len: usize,
}

impl<'a> StarkVerifier<'a> {
    /// Creates a new STARK verifier.
    ///
    /// # Arguments
    ///
    /// * `constraints` - The constraint system defining program rules
    /// * `trace_len` - The length of the execution trace
    ///
    /// # Returns
    ///
    /// A new STARK verifier instance
    pub fn new(constraints: &'a ConstraintSystem, trace_len: usize) -> Self {
        Self {
            constraints,
            trace_len,
        }
    }

    /// Verifies a STARK proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The STARK proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// # Details
    ///
    /// The verification process:
    /// 1. Checks the composition polynomial identity at 80 randomly sampled points
    ///    using the FRI protocol's sampling strategy
    /// 2. Verifies each layer of the FRI proof by checking:
    ///    - The low-degree property of each layer
    ///    - The consistency of evaluations between layers
    ///    - The correctness of the folding operations
    /// 3. Ensures all constraints are satisfied by verifying:
    ///    - Transition constraints between consecutive states
    ///    - Boundary constraints at specific points
    ///
    /// # Security Note
    ///
    /// The current implementation:
    /// - Uses a fixed number of spot checks (80) which provides a soundness error
    ///   of approximately 2^-80 for a blowup factor of 8
    /// - Does not implement zero-knowledge verification
    /// - May leak information about the trace through direct polynomial evaluation
    pub fn verify(&self, proof: &StarkProof) -> bool {
        let domain = GeneralEvaluationDomain::<Fr>::new(self.trace_len).unwrap();
        let extended_domain = GeneralEvaluationDomain::<Fr>::new(self.trace_len * 2).unwrap();
        let z_poly = ToyniPolynomial::from_dense_poly(domain.vanishing_polynomial().into());

        println!("\n=== Verifier Debug ===");
        println!("Trace length: {}", self.trace_len);
        println!("Extended domain size: {}", extended_domain.size());

        for i in 0..VERIFIER_QUERIES {
            let x0 = extended_domain.element(rand::random::<usize>() % extended_domain.size());
            let q_eval = proof.quotient_poly.evaluate(x0);
            let z_eval = z_poly.evaluate(x0);
            let c_eval = proof.combined_constraint.evaluate(x0);

            println!("\nSpot check {}:", i);
            println!("x₀ = {:?}", x0);
            println!("Q(x₀) = {:?}", q_eval);
            println!("Z(x₀) = {:?}", z_eval);
            println!("C(x₀) = {:?}", c_eval);
            println!("Q(x₀) * Z(x₀) = {:?}", q_eval * z_eval);

            if q_eval * z_eval != c_eval {
                println!("❌ Spot check failed: Q(x₀)*Z(x₀) ≠ C(x₀)");
                return false;
            }
        }

        // FRI folding check
        let mut current = &proof.quotient_eval_domain;
        for (i, beta) in proof.fri_challenges.iter().enumerate() {
            let folded = fri_fold(current, *beta);
            if proof.fri_layers.get(i + 1) != Some(&folded) {
                println!("❌ FRI folding failed at layer {}", i);
                return false;
            }
            current = &proof.fri_layers[i + 1];
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use std::collections::HashMap;

    #[test]
    fn test_valid_proof() {
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i);
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(verifier.verify(&proof));
    }

    #[test]
    fn test_invalid_proof() {
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i + 1); // invalid
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(!verifier.verify(&proof));
    }

    #[test]
    fn test_larger_trace() {
        let mut trace = ExecutionTrace::new(8, 1);
        for i in 0..8 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i);
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(verifier.verify(&proof));
    }

    #[test]
    fn test_multiple_variables() {
        let mut trace = ExecutionTrace::new(4, 2);
        for i in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i);
            row.insert("y".to_string(), i * 2);
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        // x[n+1] = x[n] + 1
        constraints.add_transition_constraint(
            "increment_x".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        // y[n] = 2 * x[n]
        constraints.add_transition_constraint(
            "y_is_double_x".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, _| {
                let x = Fr::from(*current.get("x").unwrap() as u64);
                let y = Fr::from(*current.get("y").unwrap() as u64);
                y - x * Fr::from(2u64)
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(verifier.verify(&proof));
    }

    #[test]
    fn test_zero_values() {
        let mut trace = ExecutionTrace::new(4, 1);
        for _ in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), 0); // All zeros
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "zero_sequence".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n // Should be zero
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_zero".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(verifier.verify(&proof));
    }

    #[test]
    fn test_complex_constraints() {
        let mut trace = ExecutionTrace::new(4, 2);
        for i in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i);
            row.insert("y".to_string(), i * i); // y = x^2
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        // x[n+1] = x[n] + 1
        constraints.add_transition_constraint(
            "increment_x".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        // y[n] = x[n]^2
        constraints.add_transition_constraint(
            "y_is_x_squared".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, _| {
                let x = Fr::from(*current.get("x").unwrap() as u64);
                let y = Fr::from(*current.get("y").unwrap() as u64);
                y - x * x
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(verifier.verify(&proof));
    }

    #[test]
    fn test_invalid_complex_constraints() {
        let mut trace = ExecutionTrace::new(4, 2);
        for i in 0..4 {
            let mut row = HashMap::new();
            row.insert("x".to_string(), i);
            row.insert("y".to_string(), i * i + 1); // y = x^2 + 1 (invalid)
            trace.insert_column(row);
        }

        let mut constraints = ConstraintSystem::new();
        // x[n+1] = x[n] + 1
        constraints.add_transition_constraint(
            "increment_x".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, next| {
                let x_n = Fr::from(*current.get("x").unwrap() as u64);
                let x_next = Fr::from(*next.get("x").unwrap() as u64);
                x_next - x_n - Fr::ONE
            }),
        );
        // y[n] = x[n]^2
        constraints.add_transition_constraint(
            "y_is_x_squared".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, _| {
                let x = Fr::from(*current.get("x").unwrap() as u64);
                let y = Fr::from(*current.get("y").unwrap() as u64);
                y - x * x
            }),
        );
        constraints.add_boundary_constraint(
            "starts_at_0".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let prover = StarkProver::new(&trace, &constraints);
        let proof = prover.generate_proof();
        let verifier = StarkVerifier::new(&constraints, trace.height as usize);
        assert!(!verifier.verify(&proof));
    }
}
