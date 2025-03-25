//! Virtual machine implementation for the Stark proving system.
//!
//! This module provides the core virtual machine functionality used in the Stark proving system.
//! It includes:
//! - Execution trace recording and management
//! - Constraint system for program verification
//! - Integration with the mathematical components of the proving system
//!
//! The virtual machine is designed to be:
//! - Deterministic: All operations produce the same output for the same input
//! - Simple: Uses basic arithmetic operations and state transitions
//! - Traceable: Records all state changes for proof generation
//! - Verifiable: All operations can be encoded as mathematical constraints
//!
//! This design makes it suitable for generating proofs of program execution
//! while maintaining a clear connection between program logic and mathematical constraints.

pub mod constraints;
pub mod trace;
