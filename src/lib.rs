//! Toyni Stark - A Zero-Knowledge Virtual Machine Implementation
//!
//! This crate provides a toy implementation of a Stark proving system that can be extended
//! for use in an experimental ZKVM or other proving context like circuit arithmetic.
//!
//! # Warning
//! This project is not ready for production and has not been audited.
//! Use at own risk.
//!
//! # Modules
//!
//! * `math` - Mathematical utilities for polynomial operations and FRI protocol
//! * `vm` - Virtual machine implementation with execution tracing

pub mod math;
pub mod vm;
