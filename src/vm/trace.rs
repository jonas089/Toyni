//! Execution trace module for the virtual machine.
//!
//! This module provides functionality for recording and displaying the execution trace
//! of a program running in the virtual machine. The trace is represented as a matrix
//! where each column represents a program variable and each row represents a step
//! in the program's execution.
//!
//! The `ExecutionTrace` struct provides methods to:
//! - Create new traces with specified dimensions
//! - Insert new execution steps
//! - Retrieve execution steps by index
//! - Print the trace in a tabular format
//!
//! This module is particularly useful for debugging and analyzing program execution
//! by tracking the values of program variables throughout the execution steps.

use std::collections::HashMap;

/// Type alias for program variable names.
pub type ProgramVariable = String;

/// Represents the execution trace of a program.
///
/// The trace is stored as a vector of HashMaps, where each HashMap represents a column
/// in the execution trace. Each column maps program variable names to their values at
/// that step of execution.
///
/// # Fields
///
/// * `height` - The number of execution steps in the trace
/// * `width` - The number of program variables being tracked
/// * `trace` - The actual trace data, stored as a vector of HashMaps
///
/// # Invariants
///
/// * The length of each column in the trace must equal the width
/// * The number of columns in the trace must not exceed the height
/// * All columns must contain the same set of variables
pub struct ExecutionTrace {
    pub height: u64,
    pub width: u64,
    pub trace: Vec<HashMap<ProgramVariable, u64>>,
}

impl ExecutionTrace {
    /// Creates a new empty execution trace with the specified dimensions.
    ///
    /// # Arguments
    ///
    /// * `height` - The number of execution steps to allocate
    /// * `width` - The number of program variables to track
    ///
    /// # Returns
    ///
    /// A new `ExecutionTrace` instance with the specified dimensions
    ///
    /// # Panics
    ///
    /// This function will not panic
    pub fn new(height: u64, width: u64) -> Self {
        Self {
            height,
            width,
            trace: Vec::new(),
        }
    }

    /// Inserts a new column into the execution trace.
    ///
    /// # Arguments
    ///
    /// * `column` - A HashMap mapping program variables to their values for this step
    ///
    /// # Panics
    ///
    /// Panics if:
    /// * The number of variables in the column doesn't match the trace width
    /// * The trace has reached its maximum height
    ///
    /// # Safety
    ///
    /// The caller must ensure that the column contains all required variables
    /// and that their values are valid for the program's context.
    pub fn insert_column(&mut self, column: HashMap<ProgramVariable, u64>) {
        assert!(column.len() == self.width as usize);
        assert!(self.trace.len() < self.height as usize);
        self.trace.push(column);
    }

    /// Retrieves a column from the execution trace by index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the column to retrieve
    ///
    /// # Returns
    ///
    /// A reference to the HashMap containing the variable values for that step
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds
    pub fn get_column(&self, index: u64) -> &HashMap<ProgramVariable, u64> {
        &self.trace[index as usize]
    }

    /// Prints the execution trace in a tabular format.
    ///
    /// # Arguments
    ///
    /// * `variables` - A vector of variable names specifying the order in which to print them
    ///
    /// # Format
    ///
    /// The output is formatted as a table where:
    /// - Each row represents an execution step
    /// - Each column represents a variable
    /// - Values are separated by the '|' character
    ///
    /// # Note
    ///
    /// Variables not present in the trace will be printed as empty values.
    pub fn print_trace(&self, variables: Vec<ProgramVariable>) {
        for i in 0..self.height {
            let column = self.get_column(i);
            for var in &variables {
                print!("{} |", column.get(var).unwrap_or(&0));
            }
            println!();
        }
    }

    /// Interpolates a value between two execution steps for a given variable.
    ///
    /// # Arguments
    ///
    /// * `variable` - The name of the variable to interpolate
    /// * `step1` - The first execution step index
    /// * `step2` - The second execution step index
    /// * `t` - The interpolation parameter between 0 and 100 (representing percentage)
    ///
    /// # Returns
    ///
    /// The interpolated value between the two steps
    ///
    /// # Panics
    ///
    /// Panics if:
    /// * Either step index is out of bounds
    /// * The variable is not present in the trace
    /// * The interpolation parameter t is not between 0 and 100
    pub fn interpolate(&self, variable: &ProgramVariable, step1: u64, step2: u64, t: u8) -> u64 {
        assert!(
            step1 < self.height && step2 < self.height,
            "Step indices out of bounds"
        );
        assert!(
            t <= 100,
            "Interpolation parameter must be between 0 and 100"
        );

        let col1 = self.get_column(step1);
        let col2 = self.get_column(step2);

        let val1 = *col1
            .get(variable)
            .expect("Variable not found in first step");
        let val2 = *col2
            .get(variable)
            .expect("Variable not found in second step");

        // Integer interpolation: val1 + (t * (val2 - val1)) / 100
        // We need to handle the division carefully to avoid truncation errors
        let diff = val2 - val1;
        let scaled_diff = (diff * (t as u64)) / 100;
        val1 + scaled_diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_trace() -> ExecutionTrace {
        let mut execution_trace = ExecutionTrace::new(5, 5);
        for i in 0..execution_trace.height {
            let mut column = HashMap::new();
            column.insert("a".to_string(), i);
            column.insert("b".to_string(), i + 1);
            column.insert("c".to_string(), i + 2);
            column.insert("d".to_string(), i + 3);
            column.insert("e".to_string(), i + 4);
            execution_trace.insert_column(column);
        }
        execution_trace
    }

    #[test]
    fn print_test_trace() {
        let execution_trace = generate_test_trace();
        execution_trace.print_trace(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ]);
    }

    #[test]
    fn test_interpolation() {
        let execution_trace = generate_test_trace();

        // Test variable "a" interpolation between steps 0 and 1
        // step 0: 0, step 1: 1
        let interpolated = execution_trace.interpolate(&"a".to_string(), 0, 1, 50);
        assert_eq!(interpolated, 0); // At 50% between 0 and 1

        // Test variable "b" interpolation between steps 0 and 1
        // step 0: 1, step 1: 2
        let interpolated = execution_trace.interpolate(&"b".to_string(), 0, 1, 0);
        assert_eq!(interpolated, 1);

        // Test variable "c" interpolation between steps 0 and 1
        // step 0: 2, step 1: 3
        let interpolated = execution_trace.interpolate(&"c".to_string(), 0, 1, 100);
        assert_eq!(interpolated, 3);

        // Additional test cases
        let interpolated = execution_trace.interpolate(&"a".to_string(), 0, 1, 100);
        assert_eq!(interpolated, 1);

        let interpolated = execution_trace.interpolate(&"b".to_string(), 0, 1, 100);
        assert_eq!(interpolated, 2);
    }
}
