//! Virtual machine implementation for the Stark proving system.
//!
//! This module provides the core virtual machine functionality used in the Stark proving system.
//! It includes:
//! - Execution trace recording and management
//! - Constraint system for program verification
//! - Integration with the mathematical components of the proving system
//!
//! The virtual machine is designed to be simple and deterministic, making it suitable
//! for generating proofs of program execution.

pub mod constraints;
pub mod trace;
