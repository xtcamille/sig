use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use hex;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Groth16Fixture {
    pub_key: String,
    signature: String,
    message: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // 1. Setup environment
    sp1_sdk::utils::setup_logger();

    // 2. Load the fixture data
    let fixture_path = "../contracts/src/fixtures/groth16-fixture.json";
    println!("Loading fixture from: {}", fixture_path);
    let fixture_content = std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
    let fixture: Groth16Fixture = serde_json::from_str(&fixture_content).expect("Failed to parse fixture JSON");

    // Decode hex strings
    let pub_key_bytes = hex::decode(fixture.pub_key.trim_start_matches("0x")).expect("Invalid pubKey hex");
    let signature_bytes = hex::decode(fixture.signature.trim_start_matches("0x")).expect("Invalid signature hex");
    let message_bytes = hex::decode(fixture.message.trim_start_matches("0x")).expect("Invalid message hex");
    let public_values_bytes = hex::decode(fixture.public_values.trim_start_matches("0x")).expect("Invalid publicValues hex");
    let proof_bytes = hex::decode(fixture.proof.trim_start_matches("0x")).expect("Invalid proof hex");

    println!("Fixture loaded successfully.");
    println!("Public Key: {}", fixture.pub_key);
    println!("Message: {}", fixture.message);

    // 3. Verify using the new Rust logic (matching Solidity behavior)
    println!("\n--- Running Rust Verification Logic (Matching Solidity) ---");
    
    // The expected verifier hash for SP1 v5.0.0 Groth16 is:
    // 0xa4594c59bbc142f3b81c3ecb7f50a7c34bc9af7c4c444b5d48b795427e285913
    let vkey_bytes = hex::decode(fixture.vkey.trim_start_matches("0x")).expect("Invalid vkey hex");
    let mut vkey = [0u8; 32];
    vkey.copy_from_slice(&vkey_bytes);

    let iterations = 10;
    let mut durations = Vec::new();

    for i in 1..=iterations {
        let start_verify = Instant::now();
        ed25519_script::verify::verify_signature_flow(
            &pub_key_bytes,
            &message_bytes,
            &signature_bytes,
            vkey,
            &public_values_bytes,
            &proof_bytes,
        ).expect("Full signature flow verification failed (mimicking Solidity contracts)");
        let duration = start_verify.elapsed();
        durations.push(duration);
        println!("Iteration {}: Full signature flow verified successfully! (Time: {:?})", i, duration);
    }

    let total_duration: std::time::Duration = durations.iter().sum();
    let average_duration = total_duration / (iterations as u32);

    println!("\nAll Rust-side checks passed! This matches the logic executed on-chain (SignatureVerifier.sol & SP1VerifierGroth16.sol).");
    println!("✓ Successfully verified full signature flow locally {} times.", iterations);
    println!("Average Proof verify took: {:?}", average_duration);

    println!("Verification complete.");
}
