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

/// Represents a Merkle tree node
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
    /// Creates a new leaf node
    pub fn new_leaf(value: Fr) -> Self {
        Self {
            hash: value,
            left: None,
            right: None,
        }
    }

    /// Creates a new internal node
    pub fn new_internal(left: MerkleNode, right: MerkleNode) -> Self {
        let hash = left.hash + right.hash; // In practice, use a proper hash function
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    /// Returns the root hash
    pub fn root_hash(&self) -> Fr {
        self.hash
    }
}

/// Represents a FRI layer
#[derive(Clone)]
pub struct FriLayer {
    /// The evaluations at this layer
    pub evaluations: Vec<Fr>,
    /// The Merkle commitment
    pub commitment: MerkleNode,
}

/// Represents a STARK proof
pub struct StarkProof {
    /// The composition polynomial
    pub composition_poly: CompositionPolynomial,
    /// The FRI layers
    pub fri_layers: Vec<FriLayer>,
    /// The final polynomial
    pub final_poly: DensePolynomial<Fr>,
    /// Random challenges for each FRI round
    pub fri_challenges: Vec<Fr>,
}

impl StarkProof {
    /// Creates a new STARK proof
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
        let mut fri_challenges = Vec::new();

        // Generate random challenges for each FRI round
        let mut rng = thread_rng();

        // First layer is just the original evaluations
        let first_commitment = Self::create_merkle_commitment(&current_evals);
        fri_layers.push(FriLayer {
            evaluations: current_evals.clone(),
            commitment: first_commitment,
        });

        // Fold the polynomial until we reach a small enough degree
        while current_domain.size() > 4 {
            // Generate random challenge for this round
            let beta = Fr::rand(&mut rng);
            fri_challenges.push(beta);

            // Split the evaluations into even and odd
            let (even_evals, odd_evals): (Vec<_>, Vec<_>) = current_evals
                .iter()
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);

            // Create the next layer's evaluations using FRI folding with the challenge
            let next_evals: Vec<Fr> = even_evals
                .iter()
                .zip(odd_evals.iter())
                .map(|((_, e1), (_, e2))| {
                    // f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
                    let half_inv = Fr::from(2u64).inverse().unwrap();
                    (*e1 + *e2) * half_inv + (*e1 - *e2) * half_inv * beta
                })
                .collect();

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
            fri_challenges,
        }
    }

    /// Creates a Merkle commitment for a set of evaluations
    fn create_merkle_commitment(evals: &[Fr]) -> MerkleNode {
        if evals.len() == 1 {
            return MerkleNode::new_leaf(evals[0]);
        }

        let mid = evals.len() / 2;
        let left = Self::create_merkle_commitment(&evals[..mid]);
        let right = Self::create_merkle_commitment(&evals[mid..]);
        MerkleNode::new_internal(left, right)
    }

    /// Verifies the STARK proof
    pub fn verify(&self, trace: &ExecutionTrace, constraints: &ConstraintSystem) -> bool {
        // First verify that the trace satisfies all constraints
        if !constraints.is_satisfied(trace) {
            return false;
        }

        // Check that the final polynomial has low degree
        if self.final_poly.degree() > 1 {
            return false;
        }

        // Check that the composition polynomial evaluates to zero at all points
        let evals = self.composition_poly.evaluations();
        for eval in evals.iter() {
            if !eval.is_zero() {
                return false;
            }
        }

        // Verify FRI layers with challenges
        let mut current_evals = evals.clone();
        for (i, layer) in self.fri_layers.iter().enumerate() {
            // Verify Merkle commitment
            if !self.verify_merkle_proof(&layer.commitment, &layer.evaluations) {
                return false;
            }

            // Verify layer consistency with FRI challenge
            if i > 0 {
                // For each pair of points in the previous layer, verify they fold correctly
                let prev_layer = &self.fri_layers[i - 1];
                let beta = self.fri_challenges[i - 1];
                let half_inv = Fr::from(2u64).inverse().unwrap();

                for j in 0..layer.evaluations.len() {
                    let prev_eval1 = prev_layer.evaluations[j];
                    let prev_eval2 = prev_layer.evaluations[j + layer.evaluations.len()];
                    // f_next(x) = (f(x) + f(-x))/2 + (f(x) - f(-x))/2 * β
                    let folded = (prev_eval1 + prev_eval2) * half_inv
                        + (prev_eval1 - prev_eval2) * half_inv * beta;
                    if folded != layer.evaluations[j] {
                        return false;
                    }
                }
            }

            current_evals = layer.evaluations.clone();
        }

        // Verify final polynomial matches last layer
        let final_evals = self.final_poly.evaluate_over_domain_by_ref(
            GeneralEvaluationDomain::new(current_evals.len()).unwrap(),
        );
        if final_evals.evals != current_evals {
            return false;
        }

        true
    }

    /// Verifies a Merkle proof for a set of evaluations
    fn verify_merkle_proof(&self, commitment: &MerkleNode, evaluations: &[Fr]) -> bool {
        // Reconstruct the Merkle tree from the evaluations
        let reconstructed = Self::create_merkle_commitment(evaluations);

        // Compare the reconstructed root with the provided commitment
        reconstructed.root_hash() == commitment.root_hash()
    }
}
