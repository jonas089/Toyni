# Toyni: A STARK Implementation in Progress

>[!WARNING]
> This research implementation of a STARK proving system
> is not yet secure and under heavy development
> Do not use this in production or your will CERTAINLY get compromized
> No audits, no guarantees provided, use at own risk

Welcome to Toyni! This is an implementation of a STARK (Scalable Transparent Argument of Knowledge) proving system in Rust. While it's not yet a full zero-knowledge STARK, it provides a solid foundation for understanding how STARKs work.

## Introduction

STARKs are a powerful cryptographic tool that enables proving the correct execution of a computation without revealing the underlying data. Think of it as a way to convince someone that you know the solution to a puzzle without actually showing them the solution. This property, known as zero-knowledge, is crucial for privacy-preserving applications in areas like financial transactions, voting systems, and private identity verification.

### Why STARKs Matter

```
┌─────────────────────────────────────────────────────────┐
│                     STARK Benefits                      │
├─────────────────┬─────────────────┬─────────────────────┤
│   Scalability   │  Transparency   │  Zero-Knowledge     │
├─────────────────┼─────────────────┼─────────────────────┤
│  • O(log² n)    │  • No trusted   │  • Privacy         │
│    proof size   │    setup        │  • Confidentiality  │
│  • Fast verify  │  • Public       │  • Data protection  │
│  • Efficient    │    parameters   │  • Secure sharing   │
└─────────────────┴─────────────────┴─────────────────────┘
```

### Real-World Applications

```
┌─────────────────────────────────────────────────────────┐
│                   Application Areas                     │
├─────────────────┬─────────────────┬─────────────────────┤
│   Financial     │    Identity     │    Computing        │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Private      │  • Age          │  • Confidential    │
│    payments     │    verification │    computing        │
│  • Asset        │  • Credential   │  • Private ML      │
│    ownership    │    validation   │  • Secure MPC      │
└─────────────────┴─────────────────┴─────────────────────┘
```

## Technical Overview

At its heart, Toyni consists of three main components working together:

```
┌─────────────────────────────────────────────────────────┐
│                     System Architecture                 │
├─────────────────┬─────────────────┬─────────────────────┤
│   Virtual       │   Constraint    │   STARK            │
│   Machine       │   System        │   Prover           │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Executes     │  • Defines      │  • Generates       │
│    programs     │    rules        │    proofs          │
│  • Creates      │  • Validates    │  • Uses FRI        │
│    traces       │    states       │    protocol        │
└─────────────────┴─────────────────┴─────────────────────┘
```

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│                     Proof Generation                    │
├─────────────────┬─────────────────┬─────────────────────┤
│    Program      │   Execution     │   Verification      │
│    Execution    │   Trace         │                     │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Run program  │  • Record       │  • Sample          │
│  • Track state  │    states       │    positions       │
│  • Generate     │  • Build        │  • Check           │
│    trace        │    constraints  │    constraints     │
└─────────────────┴─────────────────┴─────────────────────┘
```

Here's a simple example that demonstrates how Toyni works. We'll create a program that proves a sequence of numbers increments by 1 each time:

```rust
// Create a trace of 4 states, each with one variable 'x'
let mut trace = ExecutionTrace::new(4, 1);
for i in 0..4 {
    let mut column = HashMap::new();
    column.insert("x".to_string(), i);
    trace.insert_column(column);
}

// Define the constraints
let mut constraints = ConstraintSystem::new();

// Transition constraint: x[n+1] = x[n] + 1
constraints.add_transition_constraint(
    "increment".to_string(),
    vec!["x".to_string()],
    Box::new(|current, next| {
        let x_current = current.get("x").unwrap();
        let x_next = next.get("x").unwrap();
        Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 1)
    }),
);

// Boundary constraint: x[0] = 0
constraints.add_boundary_constraint(
    "start".to_string(),
    0,
    vec!["x".to_string()],
    Box::new(|row| Fr::from(*row.get("x").unwrap() as u64)),
);

// Generate and verify the proof
let blowup = 8;
let proof = StarkProof::new(&trace, &constraints, blowup);
assert!(proof.verify(&trace, &constraints, blowup));
```

This example demonstrates how Toyni can prove that a sequence of numbers follows a specific pattern (incrementing by 1) without revealing the actual numbers. The proof can be verified by anyone, but the actual values remain private.

## Project Structure

The codebase is organized into logical components:

```
┌─────────────────────────────────────────────────────────┐
│                     Project Structure                   │
├─────────────────┬─────────────────┬─────────────────────┤
│     Math        │       VM        │     Library        │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Polynomial   │  • Constraints  │  • Entry point     │
│  • Domain       │  • Trace        │  • Public API      │
│  • FRI          │  • Execution    │  • Documentation   │
│  • STARK        │                 │                     │
└─────────────────┴─────────────────┴─────────────────────┘
```

## Current Status

### Implemented Features

```
┌─────────────────────────────────────────────────────────┐
│                     Current Features                    │
├─────────────────┬─────────────────┬─────────────────────┤
│   Constraint    │   FRI Protocol  │   Mathematical      │
│   System        │                 │   Operations        │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Transition   │  • Low-degree   │  • Polynomial      │
│    constraints  │    testing      │    arithmetic      │
│  • Boundary     │  • Interactive  │  • Field           │
│    constraints  │    verification │    operations      │
└─────────────────┴─────────────────┴─────────────────────┘
```

### Missing Components

```
┌─────────────────────────────────────────────────────────┐
│                     Missing Features                    │
├─────────────────┬─────────────────┬─────────────────────┤
│   Zero-         │   Merkle        │   Fiat-Shamir      │
│   Knowledge     │   Commitments   │   Transform        │
├─────────────────┼─────────────────┼─────────────────────┤
│  • Trace        │  • Tree         │  • Deterministic   │
│    privacy      │    structure    │    hashing         │
│  • State        │  • Proof        │  • Non-           │
│    protection   │    generation   │    interactive     │
└─────────────────┴─────────────────┴─────────────────────┘
```

While we have a working STARK implementation, it's not yet a full zero-knowledge system. The main limitations are:

1. The execution trace is currently exposed to the verifier, revealing all program variables and states.
2. We're using random number generation instead of the Fiat-Shamir transform, making the protocol interactive.
3. The proof system lacks Merkle commitments, which are essential for zero-knowledge properties.

To achieve full zero-knowledge capabilities, we need to:
- Implement Merkle tree commitments for the execution trace
- Replace random number generation with deterministic hashing (Fiat-Shamir transform)
- Add trace blinding and random masks to the composition polynomial
- Optimize the proof generation and verification process

## Contributing

We welcome contributions to Toyni! Our current focus is on implementing zero-knowledge properties and improving the overall system. We're particularly interested in:

1. Implementing Merkle tree commitments and the Fiat-Shamir transform
2. Adding comprehensive test coverage and security audits
3. Improving documentation and adding more examples
4. Optimizing performance and reducing proof sizes

## License

MIT License - see LICENSE file for details

---

<div align="center">
  <h3>© 2025 Ciphercurve GmbH</h3>
  <p><em>Building the future of privacy-preserving computation</em></p>
</div>


