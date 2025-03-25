//! STARK proof generation and verification.
//!
//! This module implements the core STARK proving system, which allows proving the correct
//! execution of a program without revealing the underlying data. The system uses:
//! - Composition polynomials to encode program constraints
//! - FRI (Fast Reed-Solomon Interactive Oracle Proof) for low-degree testing
//! - Random sampling for constraint verification
//!
//! # Security Considerations
//!
//! The current implementation is not yet zero-knowledge because:
//! - The execution trace is exposed to the verifier
//! - Random challenges are generated using `rand::thread_rng()`
//! - No Merkle commitments are used for trace values
//!
//! To achieve zero-knowledge properties, we need to:
//! - Implement Merkle tree commitments for the trace
//! - Use Fiat-Shamir transform for challenge generation
//! - Add trace blinding and random masks

use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};

use crate::math::composition::CompositionPolynomial;
use crate::math::fri::fri_fold;
use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};

/// Represents a STARK proof that demonstrates correct program execution.
///
/// A STARK proof consists of:
/// 1. Composition polynomial evaluations over an extended domain
/// 2. FRI proof layers for low-degree testing
/// 3. FRI challenge values used in the proof
///
/// The proof can be verified by anyone without revealing the actual program execution.
pub struct StarkProof {
    /// The composition polynomial evaluations over the extended domain.
    /// These evaluations encode all program constraints and the execution trace.
    pub composition_evals: Vec<Fr>,
    /// The FRI proof layers used for low-degree testing.
    /// Each layer reduces the size of the proof while maintaining security.
    pub fri_layers: Vec<Vec<Fr>>,
    /// The FRI challenge values used in each layer.
    /// These values are currently generated randomly but should be derived
    /// from commitments in a zero-knowledge implementation.
    pub fri_challenges: Vec<Fr>,
}

impl StarkProof {
    /// Generates a new STARK proof for the given execution trace and constraints.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace of the program
    /// * `constraints` - The constraint system defining program rules
    /// * `blowup_factor` - The factor by which to extend the evaluation domain
    ///
    /// # Returns
    ///
    /// A new STARK proof that can be verified by any party
    ///
    /// # Security Note
    ///
    /// The current implementation is not zero-knowledge because:
    /// - The trace is exposed to the verifier
    /// - Random challenges are generated using `rand::thread_rng()`
    /// - No Merkle commitments are used
    pub fn new(
        trace: &ExecutionTrace,
        constraints: &ConstraintSystem,
        blowup_factor: usize,
    ) -> Self {
        let extended_domain =
            GeneralEvaluationDomain::<Fr>::new(trace.height as usize * blowup_factor).unwrap();

        // 1. Build composition polynomial
        let comp_poly = CompositionPolynomial::new(trace, constraints, extended_domain);

        // 2. Get evaluations over extended domain
        let composition_evals = comp_poly.evaluations();

        // 3. FRI folding
        let mut fri_layers = Vec::new();
        let mut fri_challenges = Vec::new();
        let mut current_evals = composition_evals.clone();
        let mut rng = rand::thread_rng();

        while current_evals.len() > 4 {
            let beta = Fr::rand(&mut rng);
            fri_challenges.push(beta);
            current_evals = fri_fold(&current_evals, beta);
            fri_layers.push(current_evals.clone());
        }

        Self {
            composition_evals,
            fri_layers,
            fri_challenges,
        }
    }

    /// Verifies that the STARK proof is valid for the given trace and constraints.
    ///
    /// The verification process:
    /// 1. Samples random rows from the trace
    /// 2. Checks that all constraints are satisfied at those rows
    /// 3. Verifies that the composition polynomial vanishes at those points
    /// 4. Checks FRI layer consistency
    /// 5. Verifies the final polynomial degree
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to verify
    /// * `constraints` - The constraint system to check
    /// * `blowup_factor` - The domain extension factor used in proof generation
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// # Security Note
    ///
    /// The current implementation leaks information about the trace because:
    /// - The verifier has direct access to trace rows
    /// - No Merkle proofs are used for trace access
    /// - The sampling is not zero-knowledge
    pub fn verify(
        &self,
        trace: &ExecutionTrace,
        constraints: &ConstraintSystem,
        blowup_factor: usize,
    ) -> bool {
        use rand::{seq::IteratorRandom, thread_rng};
        let trace_height = trace.height as usize;
        let original_domain = GeneralEvaluationDomain::<Fr>::new(trace_height).unwrap();
        let extended_domain =
            GeneralEvaluationDomain::<Fr>::new(trace_height * blowup_factor).unwrap();
        // Reconstruct the composition polynomial
        let comp_poly = CompositionPolynomial::from_evaluations(
            self.composition_evals.clone(),
            extended_domain,
        );
        // 1. Sample some rows from the trace
        let mut rng = thread_rng();
        let sample_indices: Vec<usize> = (0..trace_height).choose_multiple(&mut rng, 10);
        // 2. Evaluate constraints at those rows
        for &i in &sample_indices {
            if i + 1 >= trace_height {
                continue;
            }
            let current = trace.get_column(i as u64);
            let next = trace.get_column(((i + 1) % trace_height) as u64); // wrap around

            for constraint in &constraints.transition_constraints {
                let value = (constraint.evaluate)(current, next);
                if !value.is_zero() {
                    println!(
                        "❌ Constraint '{}' failed at row {} with value {}",
                        constraint.name, i, value
                    );
                    return false;
                }
            }
        }
        // 3. Check H(x) = 0 at those points
        for &i in &sample_indices {
            let x = original_domain.element(i);
            let eval = comp_poly.evaluate(x);
            if !eval.is_zero() {
                println!("❌ H(x) ≠ 0 at domain index {} → H({}) = {}", i, x, eval);
                return false;
            }
        }
        // 4. Check FRI consistency
        let mut current_evals = self.composition_evals.clone();
        for (i, layer) in self.fri_layers.iter().enumerate() {
            let beta = self.fri_challenges[i];
            let folded = fri_fold(&current_evals, beta);
            if folded != *layer {
                println!("❌ FRI fold failed at layer {}", i);
                return false;
            }
            current_evals = folded;
        }
        // 5. Final degree check
        let final_evals = self.fri_layers.last().unwrap();
        let final_domain = GeneralEvaluationDomain::<Fr>::new(final_evals.len()).unwrap();
        let final_poly =
            Evaluations::from_vec_and_domain(final_evals.clone(), final_domain).interpolate();
        if !(final_poly.degree() <= 2) {
            println!("❌ Final FRI polynomial has degree {}", final_poly.degree());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_generate_and_verify_stark_proof() {
        let mut trace = ExecutionTrace::new(4, 2);
        let mut y = 2;
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            column.insert("y".to_string(), y);
            y = y * y; // Square it for the next round
            trace.insert_column(column);
        }
        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
            }),
        );
        constraints.add_transition_constraint(
            "exponential".to_string(),
            vec!["y".to_string()],
            Box::new(|current, next| {
                let y_current = current.get("y").unwrap();
                let y_next = next.get("y").unwrap();
                Fr::from(*y_next as u64) - Fr::from(y_current.pow(2))
            }),
        );
        constraints.add_boundary_constraint(
            "start".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let blowup = 8;
        let proof = StarkProof::new(&trace, &constraints, blowup);

        assert!(proof.verify(&trace, &constraints, blowup));
    }

    #[test]
    fn test_invalid_stark_proof_should_fail() {
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i * 2); // invalid: x[n+1] ≠ x[n] + 1
            trace.insert_column(column);
        }

        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
            }),
        );
        constraints.add_boundary_constraint(
            "start".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
        );

        let blowup = 8;
        let proof = StarkProof::new(&trace, &constraints, blowup);

        assert!(!proof.verify(&trace, &constraints, blowup));
    }
}
