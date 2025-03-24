//! Composition polynomial for the STARK proving system.
//!
//! This module provides functionality for creating and evaluating the composition polynomial
//! that encodes all constraints of the STARK system.

use ark_bls12_381::Fr;
use ark_ff::{PrimeField, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial, univariate::DensePolynomial,
};
use std::collections::HashMap;

use crate::vm::constraints::ConstraintSystem;

/// The composition polynomial that encodes all constraints.
pub struct CompositionPolynomial {
    /// The trace polynomial
    trace_poly: DensePolynomial<Fr>,
    /// The constraint polynomials
    constraint_polys: Vec<DensePolynomial<Fr>>,
    /// The domain over which the polynomial is evaluated
    domain: GeneralEvaluationDomain<Fr>,
}

impl CompositionPolynomial {
    /// Creates a new composition polynomial from a trace and constraint system.
    ///
    /// # Arguments
    ///
    /// * `trace_evals` - The evaluations of the trace polynomial
    /// * `constraints` - The constraint system
    /// * `domain` - The evaluation domain
    ///
    /// # Returns
    ///
    /// A new composition polynomial
    pub fn new(
        trace_evals: &[Fr],
        constraints: &ConstraintSystem,
        domain: GeneralEvaluationDomain<Fr>,
    ) -> Self {
        // Interpolate the trace polynomial
        let trace_poly =
            Evaluations::from_vec_and_domain(trace_evals.to_vec(), domain).interpolate();

        // Create constraint polynomials
        let mut constraint_polys = Vec::new();

        // Add transition constraint polynomials
        for constraint in &constraints.transition_constraints {
            let mut evals = vec![Fr::zero(); domain.size()];
            for i in 0..domain.size() - 1 {
                // Convert Fr values to HashMap for constraint evaluation
                let mut current = HashMap::new();
                let mut next = HashMap::new();
                for var in &constraint.variables {
                    // Convert Fr to u64 by taking the first 64 bits
                    current.insert(var.clone(), trace_evals[i].into_bigint().as_ref()[0] as u64);
                    next.insert(
                        var.clone(),
                        trace_evals[i + 1].into_bigint().as_ref()[0] as u64,
                    );
                }
                evals[i] = (constraint.evaluate)(&current, &next);
            }
            let poly = Evaluations::from_vec_and_domain(evals, domain).interpolate();
            constraint_polys.push(poly);
        }

        // Add boundary constraint polynomials
        for constraint in &constraints.boundary_constraints {
            let mut evals = vec![Fr::zero(); domain.size()];
            let row = constraint.row as usize;
            if row < domain.size() {
                // Convert Fr value to HashMap for constraint evaluation
                let mut row_data = HashMap::new();
                for var in &constraint.variables {
                    row_data.insert(
                        var.clone(),
                        trace_evals[row].into_bigint().as_ref()[0] as u64,
                    );
                }
                evals[row] = (constraint.evaluate)(&row_data);
            }
            let poly = Evaluations::from_vec_and_domain(evals, domain).interpolate();
            constraint_polys.push(poly);
        }

        Self {
            trace_poly,
            constraint_polys,
            domain,
        }
    }

    /// Evaluates the composition polynomial at a point.
    ///
    /// # Arguments
    ///
    /// * `x` - The point at which to evaluate
    ///
    /// # Returns
    ///
    /// The value of the composition polynomial at x
    pub fn evaluate(&self, x: Fr) -> Fr {
        // Evaluate the trace polynomial
        let trace_eval = self.trace_poly.evaluate(&x);
        // Evaluate all constraint polynomials
        let mut result = trace_eval;
        for poly in &self.constraint_polys {
            result += poly.evaluate(&x);
        }

        result
    }

    /// Returns the evaluations of the composition polynomial over the domain.
    ///
    /// # Returns
    ///
    /// A vector of evaluations
    pub fn evaluations(&self) -> Vec<Fr> {
        let mut evals = vec![Fr::zero(); self.domain.size()];
        for i in 0..self.domain.size() {
            let x = self.domain.element(i);
            evals[i] = self.evaluate(x);
        }
        evals
    }

    /// Returns the degree of the composition polynomial.
    ///
    /// # Returns
    ///
    /// The degree of the polynomial
    pub fn degree(&self) -> usize {
        self.trace_poly.degree()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::constraints::ConstraintSystem;

    #[test]
    fn test_composition_polynomial() {
        // Create a small domain
        let domain_size = 4;
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();

        // Create a simple trace: x[n] = n
        let trace_evals: Vec<Fr> = (0..domain_size).map(|i| Fr::from(i as u64)).collect();

        // Create a constraint system
        let mut constraints = ConstraintSystem::new();

        // Add a simple constraint: x[n] = x[n-1] + 1
        constraints.add_transition_constraint(
            "x_increments".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
            }),
        );

        // Create the composition polynomial
        let comp_poly = CompositionPolynomial::new(&trace_evals, &constraints, domain);

        // Check that the polynomial evaluates to zero at all points
        for eval in comp_poly.evaluations() {
            assert_eq!(eval, Fr::zero());
        }
    }
}
