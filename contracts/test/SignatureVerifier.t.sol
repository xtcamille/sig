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
            0x001a06a21900cca77abae37989167cbaa76122eaf1f491dddb355fcd2036c94f
        );

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public view {
        bytes32 pubKey = 0x437a13a300bd636a3b7b185fa7e895f59843ddbecb4ebd16785499aaa02e092f;
        bytes
            memory message = hex"556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d";
        bytes
            memory signature = hex"20b73fea5d6a86c7ae452755d4106e3ae044cb7d3290eea6320ffe8efceac91dfd7cd3c10c55065f3ee56a50c8b109afb318185f128d3f33f62b282024fab10a";
        // Note: The publicValues string in the test might need regeneration to match the actual output from the program
        // but for now we follow the structure: bytes32 pub_key, bytes signature, bytes message.
        bytes
            memory publicValues = hex"0000000000000000000000000000000000000000000000000000000000000020437a13a300bd636a3b7b185fa7e895f59843ddbecb4ebd16785499aaa02e092f000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004020b73fea5d6a86c7ae452755d4106e3ae044cb7d3290eea6320ffe8efceac91dfd7cd3c10c55065f3ee56a50c8b109afb318185f128d3f33f62b282024fab10a0000000000000000000000000000000000000000000000000000000000000038556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d0000000000000000";
        bytes
            memory proof = hex"a4594c5921bed9047ad164ac27f127e09b5e14d7a9a7d967ecfa1df0af316a11e969864b1272b91193c4a69022f7271cc8fdccba1c6c49971d69c0d1c2c8e6e712a317441d993c0ee09976433891f5870964c69f45ee2ee1f89b538448bcbd1a83c73559002e40815feb426177670d2549bd9d48733486674da8aecdb7637bd16ad753411a0901ada7f0174cb3b69dda6b6bfe38183202b38d526562b505fbe4fc0a37e41558541e9f996d04eeff3a2278a19006741ef2a8f8fc34c2eef240a5564348701e2004a9c366fc3e51c4d189bd58e89b895c1e922e807aaa00aa07006f232dec0b5009bb84471e74cf123b4e3991173933696842ac8030619b8a5d65c75a67bb";

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
