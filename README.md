> [!Warning]
> This project is not ready for production 
> and has not been audited.
> Use at own risk.

# Toyni Stark
A toy implementation of a STARK (Scalable Transparent Arguments of Knowledge) proving system that can be extended for use in an experimental ZKVM or other proving context like circuit arithmetic.

## Current Implementation Status

### Core Components Implemented (Ready for MVP)
1. **Polynomial Operations** (`src/math/polynomial.rs`)
   - Basic polynomial arithmetic (addition, multiplication, division)
   - Polynomial evaluation and interpolation
   - Finite field operations using BLS12-381

2. **FRI Protocol** (`src/math/fri.rs`)
   - Fast Reed-Solomon Interactive Oracle Proof implementation
   - Polynomial folding operations
   - Domain extension and evaluation

3. **Execution Trace** (`src/vm/trace.rs`)
   - Structured representation of program execution
   - Support for multiple program variables
   - Trace visualization and debugging

4. **Constraint System** (`src/vm/constraints.rs`)
   - Transition constraints between consecutive rows
   - Boundary constraints at specific rows
   - Constraint evaluation and satisfaction checking

5. **Composition Polynomial** (`src/math/composition.rs`)
   - Combines trace and constraint polynomials
   - Low-degree extension support
   - Polynomial evaluation over extended domains

### MVP Requirements (Next Steps)
For a minimal working STARK proof, we need to add:

1. **Merkle Tree Commitments**
   - Commit to polynomial evaluations
   - Support for Merkle proofs
   - Commitment verification

2. **Proof Composition**
   - Structure the proof with:
     - Merkle commitments for each FRI round
     - Queried evaluations
     - Merkle proofs for queried points
     - FRI folded polynomials

3. **Basic Verification**
   - Verify Merkle proofs
   - Check FRI commitments
   - Validate constraint satisfaction

### Future Enhancements (Post-MVP)
1. **Enhanced Circuit/Program Layer**
   - More complex constraint types
   - Circuit compilation
   - Program representation

2. **Advanced Features**
   - Optimized proof generation
   - Better trace generation
   - More sophisticated constraint types

## Example Usage

```rust
use toyni::vm::{trace::ExecutionTrace, constraints::ConstraintSystem};
use toyni::math::composition::CompositionPolynomial;

// Create an execution trace
let mut trace = ExecutionTrace::new(4, 2);
// ... fill trace with data ...

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

// Create composition polynomial
let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
let comp_poly = CompositionPolynomial::new(&trace_evals, &constraints, domain);

// Use FRI to prove low-degree property
let evals = comp_poly.evaluations();
let beta = Fr::rand(&mut rng);
let folded_evals = fri_fold(&evals, beta);
```

## Dependencies
- `ark-bls12-381`: For finite field operations
- `ark-ff`: For field traits and operations
- `ark-poly`: For polynomial operations
- `ark-std`: For standard library traits

## Documentation
```shell
$ cargo doc --open
```

## Warning
This library is not meant for production use and is purely experimental/educational. It has not been audited and should not be used in any production environment.

*Copyright 2025, Ciphercurve GmbH*