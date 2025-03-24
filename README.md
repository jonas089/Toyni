# Toyni: A Tiny STARK Implementation

Welcome to Toyni! This is a minimal implementation of a STARK (Scalable Transparent Argument of Knowledge) proving system in Rust. Think of it as a "toy" version that helps you understand how zero-knowledge proofs work - hence the name "Toyni" (Toy + STARK).

## What's a STARK and Why Should I Care?

STARKs are a powerful cryptographic tool that lets you prove you know something without revealing what it is. Imagine you want to convince someone you know a secret number that solves a complex puzzle, but you don't want to tell them the number itself. STARKs let you do exactly that!

### Real-World Applications

- **Privacy-Preserving Financial Transactions**: Prove you have enough money for a transaction without revealing your balance
- **Secure Voting**: Verify your vote was counted without revealing who you voted for
- **Private Identity Verification**: Prove you're over 18 without showing your ID
- **Confidential Computing**: Run computations on private data while proving the results are correct
- **Private Machine Learning**: Train AI models on private data while proving the results
- **Supply Chain Verification**: Prove product authenticity without revealing trade secrets
- **Private Medical Research**: Share research results while protecting patient privacy
- **Secure Multi-Party Computation**: Collaborate on sensitive data without sharing it

### Why STARKs Matter

1. **Privacy**: Keep your data private while proving things about it
2. **Scalability**: Handle complex computations efficiently
3. **Transparency**: No trusted setup required
4. **Post-Quantum Security**: Resistant to quantum computer attacks
5. **Composability**: Can be combined with other cryptographic tools

## What Makes Toyni Special?

Toyni is designed to be:
- **Simple**: Easy to understand and modify
- **Educational**: Perfect for learning how STARKs work
- **Minimal**: Contains only the essential components
- **Rust-based**: Fast, safe, and modern
- **Well-Documented**: Clear explanations and examples
- **Interactive**: Easy to experiment with and modify

### Learning Path

1. **Start Simple**: Basic examples and concepts
2. **Build Understanding**: Step-by-step explanations
3. **Experiment**: Modify and test different scenarios
4. **Go Deep**: Technical details and optimizations

## How Does It Work? (Simple Version)

1. **Program Execution**: You write a program that does something (like solving a puzzle)
2. **Proof Generation**: Toyni creates a mathematical proof that your program ran correctly
3. **Verification**: Anyone can verify the proof without seeing your actual solution

### A Simple Example

Let's say you want to prove you know a number that, when squared, equals 16. Here's how it works:

```rust
// The secret number is 4
let secret_number = 4;

// Create a program that squares a number
let program = Program::new(vec![
    "input * input == 16"  // The constraint
]);

// Generate a proof
let proof = StarkProof::new(&program, secret_number);

// Anyone can verify the proof without knowing the number
assert!(proof.verify());
```

## Project Structure

```
src/
├── math/              # All the mathematical magic happens here
│   ├── polynomial.rs  # Working with polynomials
│   ├── domain.rs      # Special number sets for calculations
│   ├── composition.rs # Combining different proofs
│   ├── fri.rs        # The FRI protocol (makes proofs small)
│   └── stark.rs      # The main STARK implementation
├── program.rs        # Running your programs
└── main.rs          # Example code
```

### Key Components Explained

1. **polynomial.rs**
   - Handles polynomial arithmetic
   - Manages polynomial evaluation and interpolation
   - Core mathematical operations

2. **domain.rs**
   - Defines evaluation domains
   - Manages FFT (Fast Fourier Transform) operations
   - Handles field element operations

3. **composition.rs**
   - Combines multiple constraints
   - Creates composition polynomials
   - Manages constraint satisfaction

4. **fri.rs**
   - Implements the FRI protocol
   - Handles proof compression
   - Manages interactive verification

5. **stark.rs**
   - Main STARK implementation
   - Coordinates proof generation
   - Handles verification

## Quick Start

Here's a simple example of how to use Toyni:

```rust
use toyni::program::Program;
use toyni::math::stark::StarkProof;

// Create a program (like a puzzle to solve)
let program = Program::new(vec![/* your puzzle rules */]);

// Run your program and get a trace of what happened
let trace = program.execute(/* your solution */);

// Create a proof that you solved it correctly
let proof = StarkProof::new(&program.constraints, &trace);

// Anyone can verify your proof
assert!(proof.verify(&program.constraints, &trace));
```

### More Complex Example

Here's a more realistic example showing how to prove a computation:

```rust
use toyni::program::Program;
use toyni::math::stark::StarkProof;

// Define a program that computes Fibonacci numbers
let program = Program::new(vec![
    "fib[0] == 0",
    "fib[1] == 1",
    "fib[i] == fib[i-1] + fib[i-2] for i > 1"
]);

// Generate a trace for the first 10 Fibonacci numbers
let trace = program.execute(10);

// Create a proof
let proof = StarkProof::new(&program.constraints, &trace);

// Verify the proof
assert!(proof.verify(&program.constraints, &trace));
```

## Technical Deep Dive

### The STARK Protocol in Detail

1. **Program Execution**
   - Your program runs and creates an "execution trace"
   - This trace shows every step of your program
   - Think of it like a detailed log of what happened
   - Each step is recorded with its inputs and outputs

2. **FRI Protocol (Fast Reed-Solomon Interactive Oracle Proof)**
   - This is the magic that makes proofs small and fast to verify
   - It uses special math to compress your proof
   - The verifier helps by choosing random numbers to test
   - Each layer reduces the proof size while maintaining security

3. **Proof Generation**
   - Creates layers of mathematical commitments
   - Each layer makes the proof smaller
   - Uses fancy math to ensure security
   - Combines multiple constraints efficiently

4. **Verification**
   - Checks if all the math adds up
   - Verifies the proof is consistent
   - Makes sure no one cheated
   - Ensures computational integrity

### Security Features

- **Random Challenges**: The verifier picks random numbers to test the proof
- **Commitment Scheme**: Special way to promise you're telling the truth
- **Low-Degree Testing**: Mathematical way to check if you're honest
- **Constraint Verification**: Makes sure you followed all the rules
- **Soundness**: Guarantees that valid proofs can't be forged
- **Completeness**: Ensures honest proofs are always accepted
- **Zero-Knowledge**: Proves knowledge without revealing secrets

### Making Values Public with Merkle Proofs

In STARKs, when you want to make a specific value public while keeping the rest private, you use Merkle proofs. Here's how it works:

1. **Commitment Phase**
   - All values are committed to a Merkle tree
   - The root of the tree becomes part of the proof
   - This root represents all values without revealing them

2. **Public Value Disclosure**
   - To make a value public, you provide:
     - The value itself
     - A Merkle proof showing it's part of the committed tree
   - The proof verifies the value's position in the tree
   - Other values remain private

3. **Verification**
   - The verifier can check the Merkle proof
   - Confirms the public value is authentic
   - Can't learn anything about private values

Example:
```rust
// Commit all values to a Merkle tree
let merkle_root = commit_values(&values);

// Make a specific value public
let public_value = values[42];
let merkle_proof = generate_merkle_proof(&values, 42);

// Verify the public value
assert!(verify_merkle_proof(merkle_root, public_value, merkle_proof));
```

### Mathematical Foundations

1. **Finite Fields**
   - Special number systems for cryptographic operations
   - Ensures all calculations stay within bounds
   - Provides mathematical structure for proofs

2. **Polynomials**
   - Core building blocks of STARKs
   - Represent computations and constraints
   - Enable efficient proof generation

3. **FFT (Fast Fourier Transform)**
   - Speeds up polynomial operations
   - Enables efficient evaluation
   - Makes proofs practical

## Dependencies

- `ark-ff`: For working with special numbers (finite fields)
- `ark-poly`: For polynomial math
- `ark-std`: Basic Rust tools
- `rand`: For generating random numbers

### Version Requirements

```toml
[dependencies]
ark-ff = "0.4.0"
ark-poly = "0.4.0"
ark-std = "0.4.0"
rand = "0.8.0"
```

## Future Improvements

1. **Better Merkle Trees**
   - More efficient proof storage
   - Faster verification
   - Better security
   - Optimized for specific use cases

2. **Enhanced Security**
   - More sophisticated testing
   - Better security parameters
   - Smaller proof sizes
   - Improved resistance to attacks

3. **Performance**
   - Faster calculations
   - Better memory usage
   - Parallel processing
   - GPU acceleration

4. **Developer Experience**
   - Better error messages
   - More examples
   - Improved documentation
   - Development tools

## License

MIT License - see LICENSE file for details

## Contributing

Feel free to contribute! This is a learning project, and we welcome:
- Bug fixes
- Better documentation
- New features
- Educational examples
- Performance improvements
- Test cases
- Security audits

### How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request


## Acknowledgments

- Inspired by [STARKs](https://starkware.co/)
- Built with [Rust](https://www.rust-lang.org/)
- Mathematical foundations from [ARKworks](https://arkworks.rs/)
- Community contributions and feedback

## Support

If you find this project helpful, consider:
- Starring the repository
- Contributing code or documentation
- Sharing with others
- Reporting issues or suggesting improvements

## Roadmap

1. **Short Term**
   - Improve documentation
   - Add more examples
   - Fix bugs
   - Optimize performance

2. **Medium Term**
   - Add more features
   - Improve security
   - Better tooling
   - Community growth

3. **Long Term**
   - Production readiness
   - Advanced optimizations
   - Ecosystem development
   - Research contributions

---

<div align="center">
  <h3>© 2025 Ciphercurve GmbH</h3>
  <p><em>Building the future of privacy-preserving computation</em></p>
</div>


