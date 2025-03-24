# Toyni: A Toy STARK Implementation

A simple implementation of a STARK (Scalable Transparent Argument of Knowledge) proving system in Rust. This project serves as an educational tool to understand the core concepts of STARKs and zero-knowledge proofs.

## Features

- **STARK Protocol Implementation**
  - Execution trace generation
  - Constraint system
  - Composition polynomial
  - FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol
  - Verifier-generated random challenges for security
  - Domain evaluation and interpolation

- **Mathematical Foundations**
  - Finite field arithmetic using `ark-ff`
  - Polynomial operations
  - FFT for polynomial evaluation
  - FRI folding with random challenges

- **Basic Merkle Tree** (Mock Implementation)
  - Simple hash-based commitment scheme
  - Placeholder for production Merkle tree implementation

## Project Structure

```
src/
├── math/
│   ├── polynomial.rs    # Polynomial arithmetic
│   ├── domain.rs        # Evaluation domain operations
│   ├── composition.rs   # Composition polynomial
│   ├── fri.rs          # FRI protocol implementation
│   └── stark.rs        # STARK proving system
├── program.rs          # Program execution
└── main.rs            # Example usage
```

## Implementation Details

### STARK Protocol

1. **Program Execution**
   - Generate execution trace
   - Apply constraints
   - Create composition polynomial

2. **FRI Protocol**
   - Verifier generates random challenges
   - Prover commits to evaluations
   - Polynomial folding with random challenges
   - Domain size reduction

3. **Proof Generation**
   - Create FRI layers
   - Generate commitments
   - Interpolate final polynomial

4. **Verification**
   - Verify constraints
   - Check FRI layer consistency
   - Validate final polynomial

### Security Features

- Verifier-generated random challenges
- Commitment scheme for evaluations
- Low-degree testing via FRI
- Constraint satisfaction verification

## Usage

```rust
use toyni::program::Program;
use toyni::math::stark::StarkProof;

// Create a program
let program = Program::new(vec![/* constraints */]);

// Generate execution trace
let trace = program.execute(/* inputs */);

// Generate STARK proof
let proof = StarkProof::new(&program.constraints, &trace);

// Verify the proof
assert!(proof.verify(&program.constraints, &trace));
```

## Dependencies

- `ark-ff`: Finite field arithmetic
- `ark-poly`: Polynomial operations
- `ark-std`: Standard library traits
- `rand`: Random number generation

## Future Improvements

1. **Merkle Tree Implementation**
   - Proper binary Merkle tree
   - Efficient proof verification
   - Interactive proof opening

2. **Security Enhancements**
   - More sophisticated query patterns
   - Better security parameters
   - Optimized proof size

3. **Performance Optimizations**
   - Parallel FFT computation
   - Efficient polynomial operations
   - Optimized field arithmetic

## License

MIT License - see LICENSE file for details