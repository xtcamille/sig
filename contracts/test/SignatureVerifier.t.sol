// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {
    Test
} from "https://github.com/foundry-rs/forge-std/blob/master/src/Test.sol";
import {
    console
} from "https://github.com/foundry-rs/forge-std/blob/master/src/console.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {
    ISP1Verifier
} from "https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/v5.0.0/SP1VerifierGroth16.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifierContract;
    address public sp1Verifier =
        address(0xd9145CCE52D386f254917e481eB44e9943F39138); // Mock or actual address

    struct Fixture {
        string pubKey;
        string message;
        string vkey;
        string publicValues;
        string proof;
    }

    function setUp() public {
        bytes32 vkey = bytes32(
            0x0070334e1b25e3e1806829a54550b17294cbba8f218d2345d7b4f399307ca91f
        );

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public view {
        bytes
            memory pubKey = hex"04b02d97ba4f16946e4d659bb40095178a0fb52b27856143b10577495cd9d749595d79ab8d1c37f8f4f06c915b67c7710047cfa99045805edc32a319bd49874dd6";
        bytes
            memory message = hex"556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d";
        bytes
            memory signature = hex"e6741c3c4cea9de62b345a92f8daf4720097c9ec0964ef9b1f81e0d6cbf54dbe0c69e04958159bfbe86615dec01db7f661fcb860065cdf802f3b6c48c6250a2a";
        bytes
            memory publicValues = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000004104b02d97ba4f16946e4d659bb40095178a0fb52b27856143b10577495cd9d749595d79ab8d1c37f8f4f06c915b67c7710047cfa99045805edc32a319bd49874dd6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d00000000000000000000000000000000000000000000000000000000000000000000000000000040e6741c3c4cea9de62b345a92f8daf4720097c9ec0964ef9b1f81e0d6cbf54dbe0c69e04958159bfbe86615dec01db7f661fcb860065cdf802f3b6c48c6250a2a";
        bytes
            memory proof = hex"a4594c590af509257b2c20f8c43ad412798dd3744d610e615791bc9fcd0f4a2086ccc6b32ebafd8ee4af0e81ea972cd46c9acef34951239b85c63d99ada8d85299fd6b1214a4ad5db0648596903dcd92fedbe17e8d38b12e5edae73247deede43a8ba34e141bacdb696f660d1c0538612e622626dfcbee172474d0690ed15b20ab39db232ce95fecd2da0adf2735ae5e7e2426e0ca9b5b060bf1fce3926e2ab29b925cc30d9d2dcf8da1cadbe9918ae1416ff56503fce55ce1d60cd6440966cc8cc946f00af06605e568db337ea91fe0100ab31e86f7aa4428c0d14642a42103412948990b938402255092b81cd28a9b0522a9ee70a987ce73cfc3df47241349d1de60db";

        // Call verify
        verifierContract.verifySignature(
            pubKey,
            message,
            signature,
            publicValues,
            proof
        );

        console.log("Proof verified successfully!");
    }

    /// @notice Decodes the public values.
    /// @param publicValues The ABI-encoded public values.
    function decodePublicValues(
        bytes calldata publicValues
    ) public pure returns (SignatureVerifier.PublicValues memory) {
        return abi.decode(publicValues, (SignatureVerifier.PublicValues));
    }
}
