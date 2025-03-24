#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ark_bls12_381::Fr;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use toyni::{
        math::stark::StarkProof,
        vm::{constraints::ConstraintSystem, trace::ExecutionTrace},
    };

    #[test]
    fn test_stark_proof() {
        // Create a simple trace: x[n] = n
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            trace.insert_column(column);
        }

        // Create constraint system: x[n] = x[n-1] + 1
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
        assert!(proof.verify(&trace, &constraints));

        // Verify FRI layers
        assert!(
            !proof.fri_layers.is_empty(),
            "FRI layers should not be empty"
        );

        // Calculate expected number of layers:
        // Start with domain_size * blowup_factor
        // Reduce by half until we reach size 4
        let initial_size = domain.size() * blowup_factor;
        let mut expected_layers = 1;
        let mut current_size = initial_size;
        while current_size > 4 {
            current_size /= 2;
            expected_layers += 1;
        }

        assert_eq!(
            proof.fri_layers.len(),
            expected_layers,
            "Number of FRI layers should match domain size reduction"
        );
    }

    #[test]
    fn test_stark_proof_fails_with_wrong_constraints() {
        // Create a simple trace: x[n] = n
        let mut trace = ExecutionTrace::new(4, 1);
        for i in 0..4 {
            let mut column = HashMap::new();
            column.insert("x".to_string(), i);
            trace.insert_column(column);
        }

        // Create constraint system: x[n] = x[n-1] + 2 (wrong increment)
        let mut constraints = ConstraintSystem::new();
        constraints.add_transition_constraint(
            "increment".to_string(),
            vec!["x".to_string()],
            Box::new(|current, next| {
                let x_current = current.get("x").unwrap();
                let x_next = next.get("x").unwrap();
                Fr::from(*x_next as u64) - Fr::from(*x_current as u64 + 2) // Wrong increment
            }),
        );

        // Create evaluation domain with blowup factor
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let blowup_factor = 8;

        // Generate STARK proof
        let proof = StarkProof::new(&trace, &constraints, domain, blowup_factor);

        // Verify the proof should fail
        assert!(!proof.verify(&trace, &constraints));
    }
}
