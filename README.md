# Toyni

A toy implementation of a STARK-based virtual machine.

> [!Warning]
> This project is not ready for production and has not been audited.
> Use at own risk.

## Overview

Toyni is an educational implementation of a STARK (Scalable Transparent ARgument of Knowledge) proving system. It demonstrates the core concepts of STARK proofs, including polynomial commitments, FRI protocol, and constraint satisfaction.

## Architecture

### Core Components

1. **Virtual Machine** (`src/vm/`)
   - Simple stack-based execution model
   - Basic arithmetic operations (add, sub, mul)
   - Variable management
   - Execution trace generation

2. **STARK Proving System** (`src/math/`)
   - Composition polynomial construction
   - FRI protocol implementation
   - Merkle commitments
   - Domain extension with blowup factor

3. **Constraint System** (`src/vm/constraints.rs`)
   - Transition constraints between consecutive states
   - Boundary constraints at specific points
   - Constraint evaluation and satisfaction checking

### Implementation Details

#### 1. STARK Proof Generation

The STARK proof system consists of several key components:

a) **Composition Polynomial** (`src/math/composition.rs`)
```rust
H(x) = Z_H(x) * sum(C_i(x))
```
where:
- Z_H(x) is the vanishing polynomial over the domain
- C_i(x) are the individual constraint polynomials
- The result ensures constraints are satisfied at all points

b) **FRI Protocol** (`src/math/fri.rs`)
- Implements Fast Reed-Solomon Interactive Oracle Proofs
- Uses random challenges for each folding round
- Folds polynomial evaluations to reduce degree
- Formula: f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β

c) **Merkle Commitments** (`src/math/stark.rs`)
- Binary Merkle tree structure
- Currently uses simple addition as hash function (not cryptographically secure)
- Commits to polynomial evaluations at each FRI layer

#### 2. Domain Extension

The system supports domain extension with a blowup factor:
```rust
extended_domain = get_extended_domain(original_size, blowup_factor)
```
This increases the evaluation domain size for better security.

#### 3. Constraint System

Two types of constraints are supported:

a) **Transition Constraints**
```rust
constraints.add_transition_constraint(
    "increment".to_string(),
    vec!["x".to_string()],
    Box::new(|current, next| {
        let x_current = current.get("x").unwrap();
        let x_next = next.get("x").unwrap();
        Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
    }),
);
```

b) **Boundary Constraints**
```rust
constraints.add_boundary_constraint(
    "initial_value".to_string(),
    0,
    vec!["x".to_string()],
    Box::new(|row| {
        let x = row.get("x").unwrap();
        Fr::from(*x as u64) - Fr::from(0u64)
    }),
);
```

### Current Limitations

1. **Security**
   - Using simple addition as hash function (not cryptographically secure)
   - No proper query phase implementation
   - Missing soundness parameters
   - No proper Merkle proof verification

2. **Performance**
   - Basic polynomial operations
   - No optimizations for large domains
   - No parallel processing

3. **Features**
   - Limited constraint types
   - Basic virtual machine operations
   - No support for complex programs

## Usage Example

```rust
use toyni::vm::{trace::ExecutionTrace, constraints::ConstraintSystem};
use toyni::math::stark::StarkProof;

// Create an execution trace
let mut trace = ExecutionTrace::new(4, 1);
for i in 0..4 {
    let mut column = HashMap::new();
    column.insert("x".to_string(), i);
    trace.insert_column(column);
}

// Define constraints
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

// Create evaluation domain with blowup factor
let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
let blowup_factor = 8; // Standard security parameter

// Generate STARK proof
let proof = StarkProof::new(&trace, &constraints, domain, blowup_factor);

// Verify the proof
assert!(proof.verify());
```

## Dependencies

- `ark-bls12-381`: Finite field operations
- `ark-ff`: Field traits and operations
- `ark-poly`: Polynomial operations
- `ark-std`: Standard library traits

## Future Improvements

1. **Security Enhancements**
   - Implement proper cryptographic hash function
   - Add query phase with random points
   - Add soundness parameters
   - Implement proper Merkle proof verification

2. **Performance Optimizations**
   - Optimize polynomial operations
   - Add parallel processing
   - Improve memory usage

3. **Feature Additions**
   - Support for more complex constraints
   - Enhanced virtual machine capabilities
   - Better program representation

## Testing

Run the test suite:
```bash
cargo test
```

Generate documentation:
```bash
cargo doc --open
```

## License

MIT

*Copyright 2025, Ciphercurve GmbH*