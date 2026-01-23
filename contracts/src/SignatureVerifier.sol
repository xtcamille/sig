// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {
    ISP1Verifier
} from "https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/v5.0.0/SP1VerifierGroth16.sol";

/// @title SignatureVerifier
/// @notice A contract that verifies Secp256k1 signatures using SP1 zkVM.
contract SignatureVerifier {
    /// @notice The address of the SP1 verifier contract.
    address public verifier;

    /// @notice The verification key for the Secp256k1 program.
    bytes32 public vkey;

    /// @notice The public values for the Secp256k1 proof.
    struct PublicValues {
        bytes32 pub_key;
        bytes signature;
        bytes message;
    }

    constructor(address _verifier, bytes32 _vkey) {
        verifier = _verifier;
        vkey = _vkey;
    }

    error PublicValuesMismatch(bytes expected, bytes actual);

    /// @notice Verifies a Secp256k1 signature proof.
    /// @param pubKey The expected public key.
    /// @param message The expected message.
    /// @param signature The expected signature.
    /// @param publicValues The encoded public values.
    /// @param proofBytes The proof bytes.
    function verifySignature(
        bytes32 pubKey,
        bytes calldata message,
        bytes calldata signature,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) public view {
        // 1. Verify that the publicValues correspond to the provided pubKey and message and signature.
        // This ensures the proof is actually for the inputs we care about.
        // The SP1 program committed to PublicValues { bytes pub_key; bytes message; bytes signature; }
        // Note: We encode the whole struct to match the encoding from the SP1 program's commit.
        bytes memory expectedPublicValues = abi.encode(
            PublicValues(pubKey, message, signature)
        );

        if (keccak256(publicValues) != keccak256(expectedPublicValues)) {
            revert PublicValuesMismatch(expectedPublicValues, publicValues);
        }

        // 2. Verify the proof.
        ISP1Verifier(verifier).verifyProof(vkey, publicValues, proofBytes);
    }

    /// @notice Decodes the public values.
    /// @param publicValues The ABI-encoded public values.
    function decodePublicValues(
        bytes calldata publicValues
    ) public pure returns (PublicValues memory) {
        return abi.decode(publicValues, (PublicValues));
    }
}
