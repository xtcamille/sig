use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ED25519_ELF: &[u8] = include_elf!("ed25519-program");

fn main() {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(ED25519_ELF);
    println!("{}", vk.bytes32());
}