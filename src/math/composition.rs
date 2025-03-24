use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial, univariate::DensePolynomial,
};

use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};

/// Represents a composition polynomial in the STARK proving system.
///
/// The composition polynomial combines:
/// 1. The trace polynomial T(x)
/// 2. The constraint polynomials C_i(x)
/// 3. The vanishing polynomial Z_H(x)
///
/// The final composition is:
/// H(x) = T(x) + Z_H(x) * sum(C_i(x))
pub struct CompositionPolynomial {
    /// The composed polynomial
    polynomial: DensePolynomial<Fr>,
    /// The evaluation domain
    domain: GeneralEvaluationDomain<Fr>,
}

impl CompositionPolynomial {
    /// Creates a new composition polynomial from a trace and constraints.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace
    /// * `constraints` - The constraint system
    /// * `domain` - The evaluation domain (can be extended)
    ///
    /// # Returns
    ///
    /// A new composition polynomial
    pub fn new(
        trace: &ExecutionTrace,
        constraints: &ConstraintSystem,
        domain: GeneralEvaluationDomain<Fr>,
    ) -> Self {
        // Create constraint polynomial evaluations
        let mut constraint_evals = vec![Fr::zero(); domain.size()];

        // First, evaluate constraints on the original domain points
        let original_size = trace.height as usize;
        for i in 0..original_size {
            let current_row = trace.get_column(i as u64);
            let next_row = trace.get_column(((i + 1) % original_size) as u64);

            for constraint in &constraints.transition_constraints {
                let eval = (constraint.evaluate)(current_row, next_row);
                constraint_evals[i] += eval;
            }
        }

        // Evaluate boundary constraints
        for constraint in &constraints.boundary_constraints {
            let row = trace.get_column(constraint.row);
            let eval = (constraint.evaluate)(row);
            constraint_evals[constraint.row as usize] += eval;
        }

        // If we have an extended domain, interpolate the constraint evaluations
        if domain.size() > original_size {
            // Create a polynomial from the original evaluations
            let original_domain = GeneralEvaluationDomain::new(original_size).unwrap();
            let constraint_poly = Evaluations::from_vec_and_domain(
                constraint_evals[..original_size].to_vec(),
                original_domain,
            )
            .interpolate();

            // Evaluate this polynomial over the extended domain
            constraint_evals = domain.fft(&constraint_poly.coeffs);
        }

        // Interpolate constraint polynomial sum(C_i(x))
        let constraint_poly =
            Evaluations::from_vec_and_domain(constraint_evals, domain).interpolate();

        // Create the vanishing polynomial Z_H(x)
        let mut z_h_evals = vec![Fr::one(); domain.size()];
        let omega = domain.element(1); // ω is the generator
        for i in 0..domain.size() {
            let x = domain.element(i);
            for j in 0..domain.size() {
                let omega_j = omega.pow(&[j as u64]);
                z_h_evals[i] *= x - omega_j;
            }
        }
        let z_h = Evaluations::from_vec_and_domain(z_h_evals, domain).interpolate();

        // Compute H(x) = Z_H(x) * sum(C_i(x))
        let composition = &z_h * &constraint_poly;

        Self {
            polynomial: composition,
            domain,
        }
    }

    /// Returns the degree of the composition polynomial.
    pub fn degree(&self) -> usize {
        self.polynomial.degree()
    }

    /// Evaluates the composition polynomial at a point.
    pub fn evaluate(&self, point: Fr) -> Fr {
        self.polynomial.evaluate(&point)
    }

    /// Returns the coefficients of the composition polynomial.
    pub fn coefficients(&self) -> &[Fr] {
        &self.polynomial.coeffs
    }

    /// Returns evaluations of the composition polynomial over its domain.
    pub fn evaluations(&self) -> Vec<Fr> {
        self.domain.fft(&self.polynomial.coeffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_composition_polynomial() {
        // Create a simple trace: x[n] = n
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            trace.insert_column(column);
        }

        // Create constraint system: x[n] = x[n-1] + 1
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

        // Create evaluation domain
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();

        // Create composition polynomial
        let comp_poly = CompositionPolynomial::new(&trace, &constraints, domain);

        // Print trace values
        println!("Trace values:");
        for i in 0..trace.height {
            let column = trace.get_column(i);
            println!("x[{}] = {}", i, column.get("x").unwrap());
        }

        // Print constraint evaluations
        println!("\nConstraint evaluations:");
        for i in 0..trace.height - 1 {
            let current_row = trace.get_column(i);
            let next_row = trace.get_column(i + 1);
            let x_current = current_row.get("x").unwrap();
            let x_next = next_row.get("x").unwrap();
            let eval = Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1);
            println!("C[{}] = {}", i, eval);
        }

        // Print composition polynomial evaluations
        println!("\nComposition polynomial evaluations:");
        let evals = comp_poly.evaluations();
        for (i, eval) in evals.iter().enumerate() {
            println!("H[{}] = {}", i, eval);
        }

        // The composition polynomial should evaluate to zero at all points where:
        // 1. The trace values are correct (x[n] = n)
        // 2. The constraints are satisfied (x[n] = x[n-1] + 1)
        for eval in evals {
            assert!(eval.is_zero());
        }
    }
}
