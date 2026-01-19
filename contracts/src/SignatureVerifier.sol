// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title SignatureVerifier
/// @notice A contract that verifies Secp256k1 signatures using SP1 zkVM.
contract SignatureVerifier {
    /// @notice The address of the SP1 verifier contract.
    address public verifier;

    /// @notice The verification key for the Secp256k1 program.
    bytes32 public vkey;

    /// @notice The public values for the Secp256k1 proof.
    struct PublicValues {
        bytes pub_key;
        bytes message;
    }

    constructor(address _verifier, bytes32 _vkey) {
        verifier = _verifier;
        vkey = _vkey;
    }

    /// @notice Verifies a Secp256k1 signature proof.
    /// @param publicValues The public values (pub_key and message).
    /// @param proofBytes The proof bytes.
    function verifySignature(
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) public view returns (bool) {
        // Verify the proof.
        ISP1Verifier(verifier).verifyProof(vkey, publicValues, proofBytes);
        return true;
    }

    /// @notice Decodes the public values.
    /// @param publicValues The ABI-encoded public values.
    function decodePublicValues(bytes calldata publicValues) public pure returns (PublicValues memory) {
        (bytes memory pub_key, bytes memory message) = abi.decode(publicValues, (bytes, bytes));
        return PublicValues(pub_key, message);
    }
}
