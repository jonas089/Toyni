use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};

use crate::math::composition::CompositionPolynomial;
use crate::math::fri::fri_fold;
use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};

/// Represents a STARK proof.
pub struct StarkProof {
    /// The composition polynomial evaluations over the extended domain
    pub composition_evals: Vec<Fr>,
    /// The FRI proof layers
    pub fri_layers: Vec<Vec<Fr>>,
    /// The FRI challenge values
    pub fri_challenges: Vec<Fr>,
}

impl StarkProof {
    /// Generates a STARK proof.
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

        let ok = final_poly.degree() <= 2;
        if !ok {
            println!("❌ Final FRI polynomial has degree {}", final_poly.degree());
        }

        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_generate_and_verify_stark_proof() {
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
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
