//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use shared_lib::{PublicValuesStruct, Sm2VerificationData};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use sm2::{SecretKey, dsa::{SigningKey, Signature, signature::Signer}, elliptic_curve::{sec1::ToEncodedPoint, Generate}};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SM2_ELF: &[u8] = include_elf!("sm2-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1Sm2ProofFixture {
    pub_key: String,
    message: String,
    signature: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    let system_str = format!("{:?}", args.system).to_lowercase();
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../contracts/src/fixtures/{}-fixture.json", system_str));

    println!("Reading fixture at {:?}...", fixture_path);
    let fixture_data = std::fs::read_to_string(&fixture_path).expect("failed to read fixture file");
    let fixture: SP1Sm2ProofFixture = serde_json::from_str(&fixture_data).expect("failed to deserialize fixture");
    
    run_verification_benchmark(&fixture);
}

/// Run a verification benchmark loop.
fn run_verification_benchmark(fixture: &SP1Sm2ProofFixture) {
    let decode_hex = |s: &str| {
        let s = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(s).expect("invalid hex string")
    };

    let pub_key = decode_hex(&fixture.pub_key);
    let message = decode_hex(&fixture.message);
    let signature = decode_hex(&fixture.signature);
    let vkey_bytes = decode_hex(&fixture.vkey);
    let public_values = decode_hex(&fixture.public_values);
    let proof_bytes = decode_hex(&fixture.proof);

    let mut vkey = [0u8; 32];
    vkey.copy_from_slice(&vkey_bytes);

    let iterations = 10;
    let mut durations = Vec::new();

    use std::time::Instant;
    println!("Starting local verification benchmark (10 iterations)...");
    for i in 1..=iterations {
        let start = Instant::now();
        sm2_script::verify::verify_signature_flow(
            &pub_key,
            &message,
            &signature,
            vkey,
            &public_values,
            &proof_bytes,
        )
        .expect("failed to verify full signature flow locally");
        
        let duration = start.elapsed();
        durations.push(duration);
        println!("Iteration {}: Proof verify took: {:?}", i, duration);
    }

    let total_duration: std::time::Duration = durations.iter().sum();
    let average_duration = total_duration / (iterations as u32);

    println!("Successfully verified full signature flow locally {} times (Mimics Groth16Verifier.sol).", iterations);
    println!("Average Proof verify took: {:?}", average_duration);
}