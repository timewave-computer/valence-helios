// This is the wrapper circuit that verifies recursive proofs from the main recursion circuit.
// It serves as a bridge between recursive proofs, ensuring that each new proof is properly
// verified against the previous one in the chain.

#![no_main]
sp1_zkvm::entrypoint!(main);
use recursion_types::WrapperCircuitInputs;
use sp1_verifier::Groth16Verifier;

fn main() {
    // Get the Groth16 verification key for proof verification
    let groth16_vk: &[u8] = *sp1_verifier::GROTH16_VK_BYTES;

    // Deserialize the wrapper circuit inputs which contain the recursive proof
    let inputs: WrapperCircuitInputs =
        borsh::from_slice(&sp1_zkvm::io::read_vec()).expect("Failed to deserialize Inputs");

    // Get the public outputs from the recursive proof
    let public_outputs = inputs.recursive_public_values;

    // Verify the recursive proof using Groth16 verification
    Groth16Verifier::verify(
        &inputs.recursive_proof,
        &public_outputs,
        // todo: hardcode this verifying key (must be the Recursive circuit VK)
        { recursive_vk },
        groth16_vk,
    )
    .expect("Failed to verify previous proof");

    // Re-commit the public outputs after recursive proof verification
    // This ensures the outputs are available for the next proof in the chain
    sp1_zkvm::io::commit_slice(&public_outputs);
}
