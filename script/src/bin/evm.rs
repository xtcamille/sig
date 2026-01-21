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

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sp1_sdk::include_elf;
use std::path::PathBuf;
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SECP256K1_ELF: &[u8] = include_elf!("secp256k1-program");

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
struct SP1Secp256k1ProofFixture {
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

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures/groth16-fixture.json");
    if !fixture_path.exists() {
        println!("Fixture file not found at {:?}", fixture_path);
        println!("Please run this script with --system groth16 first to generate the fixture.");
        return;
    }

    let fixture_data = std::fs::read_to_string(&fixture_path).expect("failed to read fixture file");
    let fixture: SP1Secp256k1ProofFixture = serde_json::from_str(&fixture_data).expect("failed to deserialize fixture");

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

    let start = Instant::now();
    // Verify the entire logic flow (mimicking Solidity contracts).
    secp256k1_script::verify::verify_signature_flow(
        &pub_key,
        &message,
        &signature,
        vkey,
        &public_values,
        &proof_bytes,
    )
    .expect("failed to verify full signature flow locally");

    let duration = start.elapsed();
    println!("Successfully verified full signature flow locally (Mimics Groth16Verifier.sol).");
    println!("Proof verify took: {:?}", duration);
}
