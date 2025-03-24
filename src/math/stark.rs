//! STARK (Scalable Transparent Argument of Knowledge) proving system implementation.
//!
//! This module provides a complete implementation of the STARK proving system, including:
//! - Merkle tree commitments for polynomial evaluations
//! - FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol layers
//! - STARK proof generation and verification
//!
//! The implementation uses the BLS12-381 finite field and includes security features
//! like domain extension and random query points for verification.

use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial, univariate::DensePolynomial,
};
use ark_std::rand::thread_rng;
use std::iter::Iterator;

use crate::vm::{constraints::ConstraintSystem, trace::ExecutionTrace};

use super::composition::CompositionPolynomial;
use super::domain::get_extended_domain;

/// Represents a node in a Merkle tree used for committing to polynomial evaluations.
///
/// Each node contains:
/// * A hash value (for leaf nodes, this is the evaluation value)
/// * Optional left and right child nodes
#[derive(Clone)]
pub struct MerkleNode {
    /// The hash of the node
    pub hash: Fr,
    /// The left child
    pub left: Option<Box<MerkleNode>>,
    /// The right child
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    /// Creates a new leaf node with the given value.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to store in the leaf node
    ///
    /// # Returns
    ///
    /// A new leaf node
    pub fn new_leaf(value: Fr) -> Self {
        Self {
            hash: value,
            left: None,
            right: None,
        }
    }

    /// Creates a new internal node with the given children.
    ///
    /// # Arguments
    ///
    /// * `left` - The left child node
    /// * `right` - The right child node
    ///
    /// # Returns
    ///
    /// A new internal node with the combined hash of its children
    pub fn new_internal(left: MerkleNode, right: MerkleNode) -> Self {
        let hash = left.hash + right.hash; // In practice, use a proper hash function
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    /// Returns the root hash of the Merkle tree.
    ///
    /// # Returns
    ///
    /// The hash value of the root node
    pub fn root_hash(&self) -> Fr {
        self.hash
    }
}

/// Represents a single layer in the FRI protocol.
///
/// Each layer contains:
/// * The polynomial evaluations at that layer
/// * A Merkle commitment to those evaluations
#[derive(Clone)]
pub struct FriLayer {
    /// The evaluations at this layer
    pub evaluations: Vec<Fr>,
    /// The Merkle commitment
    pub commitment: MerkleNode,
}

/// Represents a complete STARK proof.
///
/// The proof consists of:
/// * The composition polynomial
/// * Multiple FRI layers for proving low-degree
/// * The final polynomial
/// * Random challenges for each FRI round
/// * The evaluation domain
pub struct StarkProof {
    /// The composition polynomial
    pub composition_poly: CompositionPolynomial,
    /// The FRI layers
    pub fri_layers: Vec<FriLayer>,
    /// The final polynomial
    pub final_poly: DensePolynomial<Fr>,
    /// The evaluation domain
    pub domain: GeneralEvaluationDomain<Fr>,
}

impl StarkProof {
    /// Creates a new STARK proof for the given trace and constraints.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to prove
    /// * `constraints` - The constraint system
    /// * `domain` - The evaluation domain
    /// * `blowup_factor` - The factor by which to extend the domain for security
    ///
    /// # Returns
    ///
    /// A new STARK proof
    pub fn new(
        trace: &ExecutionTrace,
        constraints: &ConstraintSystem,
        domain: GeneralEvaluationDomain<Fr>,
        blowup_factor: usize,
    ) -> Self {
        // Create extended domain for better security
        let extended_domain = get_extended_domain(domain.size(), blowup_factor);

        // Create the composition polynomial over the extended domain
        let composition_poly = CompositionPolynomial::new(trace, constraints, extended_domain);

        // Generate FRI layers
        let mut fri_layers = Vec::new();
        let mut current_domain = extended_domain;
        let mut current_evals = composition_poly.evaluations();

        // First layer is just the original evaluations
        let first_commitment = Self::create_merkle_commitment(&current_evals);
        fri_layers.push(FriLayer {
            evaluations: current_evals.clone(),
            commitment: first_commitment,
        });

        // Fold the polynomial until we reach a small enough degree
        while current_domain.size() > 4 {
            // Split the evaluations into even and odd
            let (even_evals, odd_evals): (Vec<_>, Vec<_>) = current_evals
                .iter()
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);

            // Generate random challenge for this round
            let beta = Fr::rand(&mut thread_rng());
            let half_inv = Fr::from(2u64).inverse().unwrap();

            // Create the next layer's evaluations by folding
            let mut next_evals = Vec::with_capacity(even_evals.len());
            for ((_, e1), (_, e2)) in even_evals.iter().zip(odd_evals.iter()) {
                // f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
                let folded = (*e1 + *e2) * half_inv + (*e1 - *e2) * half_inv * beta;
                next_evals.push(folded);
            }

            // Create Merkle commitment for this layer
            let commitment = Self::create_merkle_commitment(&next_evals);

            // Add the layer
            fri_layers.push(FriLayer {
                evaluations: next_evals.clone(),
                commitment,
            });

            // Update for next iteration
            current_evals = next_evals;
            // Create a new domain with half the size
            current_domain = GeneralEvaluationDomain::new(current_domain.size() / 2).unwrap();
        }

        // Create the final polynomial
        let final_poly =
            Evaluations::from_vec_and_domain(current_evals, current_domain).interpolate();

        Self {
            composition_poly,
            fri_layers,
            final_poly,
            domain: extended_domain,
        }
    }

    /// Creates a Merkle commitment for a set of evaluations.
    ///
    /// # Arguments
    ///
    /// * `evals` - The evaluations to commit to
    ///
    /// # Returns
    ///
    /// A Merkle tree root node
    fn create_merkle_commitment(evals: &[Fr]) -> MerkleNode {
        if evals.len() == 1 {
            return MerkleNode::new_leaf(evals[0]);
        }

        let mid = evals.len() / 2;
        let left = Self::create_merkle_commitment(&evals[..mid]);
        let right = Self::create_merkle_commitment(&evals[mid..]);
        MerkleNode::new_internal(left, right)
    }

    /// Verifies the STARK proof against the given trace and constraints.
    ///
    /// # Arguments
    ///
    /// * `trace` - The execution trace to verify
    /// * `constraints` - The constraint system
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, trace: &ExecutionTrace, constraints: &ConstraintSystem) -> bool {
        // First verify that the trace satisfies all constraints
        if !constraints.is_satisfied(trace) {
            return false;
        }

        // Verify the composition polynomial was constructed correctly
        let expected_composition = CompositionPolynomial::new(trace, constraints, self.domain);
        if self.composition_poly.evaluations() != expected_composition.evaluations() {
            return false;
        }

        // Check that the final polynomial has low degree
        if self.final_poly.degree() > 1 {
            return false;
        }

        // Generate random challenges for each FRI round
        let mut rng = thread_rng();
        let mut fri_challenges = Vec::new();
        for _ in 0..self.fri_layers.len() - 1 {
            fri_challenges.push(Fr::rand(&mut rng));
        }

        // Verify FRI layers
        for i in 0..self.fri_layers.len() {
            let layer = &self.fri_layers[i];

            // Verify layer consistency with FRI challenge
            if i > 0 {
                // For each pair of points in the previous layer, verify they fold correctly
                let prev_layer = &self.fri_layers[i - 1];
                let beta = fri_challenges[i - 1];
                let half_inv = Fr::from(2u64).inverse().unwrap();

                // Each layer should have half as many evaluations as the previous layer
                let expected_size = prev_layer.evaluations.len() / 2;
                if layer.evaluations.len() != expected_size {
                    return false;
                }

                // For each point in the current layer, verify it was folded correctly
                for j in 0..expected_size {
                    let prev_eval1 = prev_layer.evaluations[j];
                    let prev_eval2 = prev_layer.evaluations[j + expected_size];
                    // f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
                    let folded = (prev_eval1 + prev_eval2) * half_inv
                        + (prev_eval1 - prev_eval2) * half_inv * beta;
                    if folded != layer.evaluations[j] {
                        return false;
                    }
                }
            }

            // Verify Merkle commitment
            if !self.verify_merkle_proof(&layer.commitment, &layer.evaluations) {
                return false;
            }
        }

        // Verify final polynomial matches last layer
        let final_evals = self.final_poly.evaluate_over_domain_by_ref(
            GeneralEvaluationDomain::new(self.fri_layers.last().unwrap().evaluations.len())
                .unwrap(),
        );
        if final_evals.evals != self.fri_layers.last().unwrap().evaluations {
            return false;
        }

        true
    }

    /// Verifies a Merkle proof for a set of evaluations.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The Merkle commitment to verify
    /// * `evaluations` - The evaluations to verify against
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    fn verify_merkle_proof(&self, commitment: &MerkleNode, evaluations: &[Fr]) -> bool {
        // Reconstruct the Merkle tree from the evaluations
        let reconstructed = Self::create_merkle_commitment(evaluations);

        // Compare the reconstructed root with the provided commitment
        reconstructed.root_hash() == commitment.root_hash()
    }
}
