//! Constraint system for the STARK proving system.
//!
//! This module provides functionality for defining and evaluating constraints
//! over the execution trace of a program.

use ark_bls12_381::Fr;
use ark_ff::AdditiveGroup;
use std::collections::HashMap;

use crate::vm::trace::{ExecutionTrace, ProgramVariable};

/// Represents a constraint that must hold between consecutive rows of the execution trace.
pub struct TransitionConstraint {
    /// The name of the constraint for debugging purposes
    pub name: String,
    /// The variables used in the constraint
    pub variables: Vec<ProgramVariable>,
    /// The function that evaluates the constraint
    pub evaluate: Box<dyn Fn(&HashMap<ProgramVariable, u64>, &HashMap<ProgramVariable, u64>) -> Fr>,
}

/// Represents a constraint that must hold at a specific row of the execution trace.
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
pub struct ConstraintSystem {
    /// Transition constraints between consecutive rows
    pub transition_constraints: Vec<TransitionConstraint>,
    /// Boundary constraints at specific rows
    pub boundary_constraints: Vec<BoundaryConstraint>,
}

impl ConstraintSystem {
    /// Creates a new empty constraint system.
    pub fn new() -> Self {
        Self {
            transition_constraints: Vec::new(),
            boundary_constraints: Vec::new(),
        }
    }

    /// Adds a transition constraint to the system.
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
    pub fn is_satisfied(&self, trace: &ExecutionTrace) -> bool {
        self.evaluate(trace).iter().all(|&x| x == Fr::ZERO)
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
}
