// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {
    ISP1Verifier
} from "https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/v5.0.0/SP1VerifierGroth16.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifierContract;
    address public sp1Verifier = address(0x123); // Mock or actual address

    struct Fixture {
        string pubKey;
        string message;
        string vkey;
        string publicValues;
        string proof;
    }

    function setUp() public {
        // Load fixture
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory vkeyBytes = vm.parseJsonBytes(json, ".vkey");
        bytes32 vkey = abi.decode(vkeyBytes, (bytes32));

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public {
        // Load fixture again for specific values
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/groth16-fixture.json");
        string memory json = vm.readFile(path);

        bytes memory pubKey = vm.parseJsonBytes(json, ".pubKey");
        bytes memory message = vm.parseJsonBytes(json, ".message");
        bytes memory publicValues = vm.parseJsonBytes(json, ".publicValues");
        bytes memory proof = vm.parseJsonBytes(json, ".proof");

        // Mock the SP1 verifier call if not using a real one
        vm.mockCall(
            sp1Verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector),
            abi.encode(true)
        );

        // Call verify
        verifierContract.verifySignature(pubKey, message, publicValues, proof);

        console.log("Proof verified successfully!");
    }
}
