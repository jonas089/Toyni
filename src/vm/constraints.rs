//! Constraint system for the STARK proving system.
//!
//! This module provides functionality for defining and evaluating constraints
//! over the execution trace of a program. It supports both transition constraints
//! (between consecutive rows) and boundary constraints (at specific rows).
//!
//! The constraint system is used to encode the program's logic and requirements
//! into mathematical constraints that can be proven using the STARK protocol.

use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Zero};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use std::collections::HashMap;

use crate::math::polynomial::Polynomial as ToyniPolynomial;
use crate::vm::trace::{ExecutionTrace, ProgramVariable};

/// Represents a constraint that must hold between consecutive rows of the execution trace.
///
/// Transition constraints are used to encode the program's logic by specifying
/// relationships that must hold between consecutive states of the program.
///
/// # Fields
///
/// * `name` - The name of the constraint for debugging purposes
/// * `variables` - The variables used in the constraint
/// * `evaluate` - The function that evaluates the constraint
pub struct TransitionConstraint {
    /// The name of the constraint for debugging purposes
    pub name: String,
    /// The variables used in the constraint
    pub variables: Vec<ProgramVariable>,
    /// The function that evaluates the constraint
    pub evaluate: Box<dyn Fn(&HashMap<ProgramVariable, u64>, &HashMap<ProgramVariable, u64>) -> Fr>,
}

/// Represents a constraint that must hold at a specific row of the execution trace.
///
/// Boundary constraints are used to specify initial conditions, final conditions,
/// or other requirements that must hold at specific points in the program's execution.
///
/// # Fields
///
/// * `name` - The name of the constraint for debugging purposes
/// * `row` - The row at which this constraint must hold
/// * `variables` - The variables used in the constraint
/// * `evaluate` - The function that evaluates the constraint
pub struct BoundaryConstraint {
    /// The name of the constraint for debugging purposes
    pub name: String,
    /// The row at which this constraint must hold
    pub row: u64,
    /// The variables used in the constraint
    pub variables: Vec<ProgramVariable>,
    /// The function that evaluates the constraint
    pub evaluate: Box<dyn Fn(&HashMap<ProgramVariable, u64>) -> Fr>,
}

/// The constraint system that holds all constraints for a program.
///
/// This struct maintains collections of both transition and boundary constraints,
/// and provides methods to evaluate them over an execution trace.
///
/// # Fields
///
/// * `transition_constraints` - Transition constraints between consecutive rows
/// * `boundary_constraints` - Boundary constraints at specific rows
pub struct ConstraintSystem {
    /// Transition constraints between consecutive rows
    pub transition_constraints: Vec<TransitionConstraint>,
    /// Boundary constraints at specific rows
    pub boundary_constraints: Vec<BoundaryConstraint>,
}

impl ConstraintSystem {
    /// Creates a new empty constraint system.
    ///
    /// # Returns
    ///
    /// A new constraint system with no constraints
    pub fn new() -> Self {
        Self {
            transition_constraints: Vec::new(),
            boundary_constraints: Vec::new(),
        }
    }

    /// Adds a transition constraint to the system.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the constraint
    /// * `variables` - The variables used in the constraint
    /// * `evaluate` - The function that evaluates the constraint
    ///
    /// # Details
    ///
    /// The evaluation function takes two HashMaps representing consecutive rows
    /// of the execution trace and returns a field element. The constraint is
    /// satisfied if the evaluation returns zero.
    pub fn add_transition_constraint(
        &mut self,
        name: String,
        variables: Vec<ProgramVariable>,
        evaluate: Box<dyn Fn(&HashMap<ProgramVariable, u64>, &HashMap<ProgramVariable, u64>) -> Fr>,
    ) {
        self.transition_constraints.push(TransitionConstraint {
            name,
            variables,
            evaluate,
        });
    }

    /// Adds a boundary constraint to the system.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the constraint
    /// * `row` - The row at which this constraint must hold
    /// * `variables` - The variables used in the constraint
    /// * `evaluate` - The function that evaluates the constraint
    ///
    /// # Details
    ///
    /// The evaluation function takes a HashMap representing a single row of the
    /// execution trace and returns a field element. The constraint is satisfied
    /// if the evaluation returns zero.
    pub fn add_boundary_constraint(
        &mut self,
        name: String,
        row: u64,
        variables: Vec<ProgramVariable>,
        evaluate: Box<dyn Fn(&HashMap<ProgramVariable, u64>) -> Fr>,
    ) {
        self.boundary_constraints.push(BoundaryConstraint {
            name,
            row,
            variables,
            evaluate,
        });
    }

    /// Evaluates all constraints on the given execution trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to evaluate constraints on
    ///
    /// # Returns
    ///
    /// A vector of constraint evaluations, where each evaluation is a field element.
    /// If all constraints are satisfied, all evaluations should be zero.
    ///
    /// # Details
    ///
    /// The function evaluates both transition and boundary constraints in sequence.
    /// For transition constraints, it evaluates between each pair of consecutive rows.
    /// For boundary constraints, it evaluates at the specified rows.
    pub fn evaluate(&self, trace: &ExecutionTrace) -> Vec<Fr> {
        let mut evaluations = Vec::new();

        // Evaluate transition constraints
        for i in 0..trace.height - 1 {
            let current_row = trace.get_column(i);
            let next_row = trace.get_column(i + 1);

            for constraint in &self.transition_constraints {
                let eval = (constraint.evaluate)(current_row, next_row);
                evaluations.push(eval);
            }
        }

        // Evaluate boundary constraints
        for constraint in &self.boundary_constraints {
            let row = trace.get_column(constraint.row);
            let eval = (constraint.evaluate)(row);
            evaluations.push(eval);
        }

        evaluations
    }

    /// Checks if all constraints are satisfied by the given execution trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to check constraints on
    ///
    /// # Returns
    ///
    /// `true` if all constraints are satisfied (all evaluations are zero),
    /// `false` otherwise
    ///
    /// # Details
    ///
    /// This function calls `evaluate` and checks if all returned values are zero.
    pub fn is_satisfied(&self, trace: &ExecutionTrace) -> bool {
        self.evaluate(trace).iter().all(|&x| x == Fr::ZERO)
    }

    /// Interpolates a transition constraint as a polynomial over the execution trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to interpolate over
    /// * `constraint` - The transition constraint to interpolate
    ///
    /// # Returns
    ///
    /// A polynomial representing the constraint's evaluations over the trace
    ///
    /// # Panics
    ///
    /// Panics if the trace height is not a power of 2
    pub fn interpolate_transition_constraint(
        &self,
        trace: &ExecutionTrace,
        constraint: &TransitionConstraint,
    ) -> ToyniPolynomial {
        let domain = GeneralEvaluationDomain::<Fr>::new(trace.height as usize)
            .expect("Trace height must be a power of 2");

        // Evaluate the constraint at each step
        let mut evaluations = vec![Fr::zero(); trace.height as usize];
        for i in 0..trace.height - 1 {
            let current_row = trace.get_column(i);
            let next_row = trace.get_column(i + 1);
            evaluations[i as usize] = (constraint.evaluate)(current_row, next_row);
        }

        // Interpolate the polynomial
        let evals = Evaluations::from_vec_and_domain(evaluations, domain);
        ToyniPolynomial::from_dense_poly(evals.interpolate())
    }

    /// Interpolates a boundary constraint as a polynomial over the execution trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to interpolate over
    /// * `constraint` - The boundary constraint to interpolate
    ///
    /// # Returns
    ///
    /// A polynomial representing the constraint's evaluations over the trace
    ///
    /// # Panics
    ///
    /// Panics if the trace height is not a power of 2
    pub fn interpolate_boundary_constraint(
        &self,
        trace: &ExecutionTrace,
        constraint: &BoundaryConstraint,
    ) -> ToyniPolynomial {
        let domain = GeneralEvaluationDomain::<Fr>::new(trace.height as usize)
            .expect("Trace height must be a power of 2");

        // Evaluate the constraint at each step
        let mut evaluations = vec![Fr::zero(); trace.height as usize];
        let row = trace.get_column(constraint.row);
        evaluations[constraint.row as usize] = (constraint.evaluate)(row);

        // Interpolate the polynomial
        let evals = Evaluations::from_vec_and_domain(evaluations, domain);
        ToyniPolynomial::from_dense_poly(evals.interpolate())
    }

    /// Interpolates all constraints as polynomials over the execution trace.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to interpolate over
    ///
    /// # Returns
    ///
    /// A vector of polynomials representing all constraints
    ///
    /// # Panics
    ///
    /// Panics if the trace height is not a power of 2
    pub fn interpolate_all_constraints(&self, trace: &ExecutionTrace) -> Vec<ToyniPolynomial> {
        let mut polynomials = Vec::new();

        // Interpolate transition constraints
        for constraint in &self.transition_constraints {
            polynomials.push(self.interpolate_transition_constraint(trace, constraint));
        }

        // Interpolate boundary constraints
        for constraint in &self.boundary_constraints {
            polynomials.push(self.interpolate_boundary_constraint(trace, constraint));
        }

        polynomials
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::trace::ExecutionTrace;

    fn create_test_trace() -> ExecutionTrace {
        let mut trace = ExecutionTrace::new(3, 2);
        for i in 0..3 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            column.insert("y".to_string(), i * 2);
            trace.insert_column(column);
        }
        trace
    }

    #[test]
    fn test_transition_constraint() {
        let mut system = ConstraintSystem::new();

        // Add a constraint: y[n] = 2 * x[n]
        system.add_transition_constraint(
            "y_equals_2x".to_string(),
            vec!["x".to_string(), "y".to_string()],
            Box::new(|current, _| {
                let x = current.get("x").unwrap();
                let y = current.get("y").unwrap();
                Fr::from(*y as u64) - Fr::from(2 * *x as u64)
            }),
        );

        let trace = create_test_trace();
        assert!(system.is_satisfied(&trace));
    }

    #[test]
    fn test_boundary_constraint() {
        let mut system = ConstraintSystem::new();

        // Add a constraint: x[0] = 0
        system.add_boundary_constraint(
            "x_starts_at_zero".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| {
                let x = row.get("x").unwrap();
                Fr::from(*x as u64)
            }),
        );

        let trace = create_test_trace();
        assert!(system.is_satisfied(&trace));
    }

    #[test]
    fn test_unsatisfied_constraint() {
        let mut system = ConstraintSystem::new();

        // Add a constraint: x[n] = x[n-1] + 1
        system.add_transition_constraint(
            "x_increments".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
            }),
        );

        // Create a trace that doesn't satisfy the constraint
        let mut trace = ExecutionTrace::new(3, 1);
        for i in 0..3 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i * 2); // x[n] = 2n instead of n
            trace.insert_column(column);
        }

        assert!(!system.is_satisfied(&trace));
    }

    #[test]
    fn test_constraint_interpolation() {
        let mut system = ConstraintSystem::new();

        // Add a transition constraint: x[n] = x[n-1] + 1
        system.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
            }),
        );

        // Add a boundary constraint: x[0] = 0
        system.add_boundary_constraint(
            "start".to_string(),
            0,
            vec!["x".to_string()],
            Box::new(|row| {
                let x = row.get("x").unwrap();
                Fr::from(*x as u64)
            }),
        );

        // Create a trace that satisfies the constraints
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            trace.insert_column(column);
        }

        // Interpolate all constraints
        let polynomials = system.interpolate_all_constraints(&trace);

        // Verify that the interpolated polynomials evaluate to zero at the trace points
        for (i, poly) in polynomials.iter().enumerate() {
            for j in 0..trace.height {
                let eval = poly.evaluate(Fr::from(j as u64));
                assert!(
                    eval.is_zero(),
                    "Polynomial {} should evaluate to zero at x={}",
                    i,
                    j
                );
            }
        }
    }
}
