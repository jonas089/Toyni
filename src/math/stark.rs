use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_poly::DenseUVPolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, univariate::DensePolynomial};
use rand::thread_rng;

use crate::math::fri::fri_fold;
use crate::math::polynomial::Polynomial as ToyniPolynomial;
use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};

pub struct StarkProof {
    pub quotient_eval_domain: Vec<Fr>,
    pub fri_layers: Vec<Vec<Fr>>,
    pub fri_challenges: Vec<Fr>,
    pub combined_constraint: ToyniPolynomial,
    pub quotient_poly: ToyniPolynomial,
}

pub struct StarkProver<'a> {
    trace: &'a ExecutionTrace,
    constraints: &'a ConstraintSystem,
}

impl<'a> StarkProver<'a> {
    pub fn new(trace: &'a ExecutionTrace, constraints: &'a ConstraintSystem) -> Self {
        Self { trace, constraints }
    }

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
        while q_evals.len() > 4 {
            let beta = Fr::rand(&mut thread_rng());
            fri_challenges.push(beta);
            q_evals = fri_fold(&q_evals, beta);
            fri_layers.push(q_evals.clone());
        }

        StarkProof {
            quotient_eval_domain: fri_layers[0].clone(),
            fri_layers,
            fri_challenges,
            combined_constraint,
            quotient_poly,
        }
    }
}

pub struct StarkVerifier<'a> {
    constraints: &'a ConstraintSystem,
    trace_len: usize,
}

impl<'a> StarkVerifier<'a> {
    pub fn new(constraints: &'a ConstraintSystem, trace_len: usize) -> Self {
        Self {
            constraints,
            trace_len,
        }
    }

    pub fn verify(&self, proof: &StarkProof) -> bool {
        let domain = GeneralEvaluationDomain::<Fr>::new(self.trace_len).unwrap();
        let extended_domain = GeneralEvaluationDomain::<Fr>::new(self.trace_len * 2).unwrap();
        let z_poly = ToyniPolynomial::from_dense_poly(domain.vanishing_polynomial().into());

        println!("\n=== Verifier Debug ===");
        println!("Trace length: {}", self.trace_len);
        println!("Extended domain size: {}", extended_domain.size());

        // Spot check 80 points
        for i in 0..80 {
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
    use ark_ff::Field;

    use super::*;
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
}
