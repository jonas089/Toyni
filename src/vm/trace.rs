//! Execution trace module for the virtual machine.
//!
//! This module provides functionality for recording and displaying the execution trace
//! of a program running in the virtual machine. The trace is represented as a matrix
//! where each column represents a program variable and each row represents a step
//! in the program's execution.

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
    pub fn get_column(&self, index: u64) -> &HashMap<ProgramVariable, u64> {
        &self.trace[index as usize]
    }

    /// Prints the execution trace in a tabular format.
    ///
    /// # Arguments
    ///
    /// * `variables` - A vector of variable names specifying the order in which to print them
    pub fn print_trace(&self, variables: Vec<ProgramVariable>) {
        for i in 0..self.height {
            let column = self.get_column(i);
            for var in &variables {
                print!("{} |", column.get(var).unwrap());
            }
            println!();
        }
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
}
