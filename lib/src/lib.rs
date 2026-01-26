use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use alloy_sol_types::sol;

#[derive(Serialize, Deserialize)]
pub struct Ed25519VerificationData {
    pub pub_key: [u8; 32],      // Ed25519 公钥 (32字节)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],    // Ed25519 签名 (64字节)

    pub message: Vec<u8>,       // 交易内容 X
}

sol! {
    struct PublicValuesStruct {
        bytes pub_key;
        bytes message;
        bytes signature;
    }
}

/// Hashes the public values to a field element inside Bn254.
/// Equivalent to Solidity's hashPublicValues in SP1VerifierGroth16.sol.
pub fn hash_public_values(public_values: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_values);
    let mut hash: [u8; 32] = hasher.finalize().into();

    // Apply the mask: (1 << 253) - 1
    // This wipes the first 3 bits (32 * 8 = 256, 256 - 253 = 3)
    // In big-endian, the first byte is hash[0].
    // 1 << 253 in 256-bit big-endian is 0x20...00 (00100000...)
    // (1 << 253) - 1 is 0x1F...FF (00011111...)
    // So we mask the first byte with 0x1F.
    hash[0] &= 0x1F;
    hash
}

/// Verifies that the provided public values correspond to the inputs.
/// Equivalent to SignatureVerifier.sol's logic inside verifySignature.
pub fn verify_public_values(
    pub_key: &[u8],
    message: &[u8],
    signature: &[u8],
    public_values: &[u8],
) -> Result<(), String> {
    use alloy_sol_types::SolValue;
    use tiny_keccak::{Hasher, Keccak};

    let expected_struct = PublicValuesStruct {
        pub_key: pub_key.to_vec().into(),
        message: message.to_vec().into(),
        signature: signature.to_vec().into(),
    };
    let expected_encoded = expected_struct.abi_encode();

    // Check if keccak256(public_values) == keccak256(expected_encoded)
    let mut k1 = Keccak::v256();
    let mut h1 = [0u8; 32];
    k1.update(public_values);
    k1.finalize(&mut h1);

    let mut k2 = Keccak::v256();
    let mut h2 = [0u8; 32];
    k2.update(&expected_encoded);
    k2.finalize(&mut h2);

    if h1 != h2 {
        return Err("Public values mismatch".to_string());
    }

    Ok(())
}

/// Reproduces the logic of SP1VerifierGroth16.sol's verifyProof selector check.
pub fn check_verifier_selector(proof_bytes: &[u8], expected_verifier_hash: &[u8; 32]) -> Result<(), String> {
    if proof_bytes.len() < 4 {
        return Err("Proof too short".to_string());
    }
    let received_selector = &proof_bytes[0..4];
    let expected_selector = &expected_verifier_hash[0..4];
    if received_selector != expected_selector {
        return Err(format!(
            "Wrong verifier selector: received 0x{:02x}{:02x}{:02x}{:02x}, expected 0x{:02x}{:02x}{:02x}{:02x}",
            received_selector[0], received_selector[1], received_selector[2], received_selector[3],
            expected_selector[0], expected_selector[1], expected_selector[2], expected_selector[3]
        ));
    }
    Ok(())
}