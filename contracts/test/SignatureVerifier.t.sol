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
        address(0x540d7E428D5207B30EE03F2551Cbb5751D3c7569); // Mock or actual address

    struct Fixture {
        string pubKey;
        string message;
        string vkey;
        string publicValues;
        string proof;
    }

    function setUp() public {
        bytes32 vkey = bytes32(
            0x00a94131493c64d0efa9cc342c65b2fc40210b84698738c7f95efbe383691a1e
        );

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public view {
        bytes
            memory pubKey = hex"036661ca79c8303cd3295221599c46e51348028f40c97d562819e819d99c5ca91a";
        bytes memory message = hex"48656c6c6f2c2053503120536563703235366b3121";
        bytes
            memory signature = hex"5a21f4825b00a7f26e9d16c4894a0c7b6c13d8c609e347b4f1a0add90d6077ff42b2d08287f91568bbb206696e80b0675839c7b1e9607f369dac8e3a3024df8f";
        bytes
            memory publicValues = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000021036661ca79c8303cd3295221599c46e51348028f40c97d562819e819d99c5ca91a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001548656c6c6f2c2053503120536563703235366b3121000000000000000000000000000000000000000000000000000000000000000000000000000000000000405a21f4825b00a7f26e9d16c4894a0c7b6c13d8c609e347b4f1a0add90d6077ff42b2d08287f91568bbb206696e80b0675839c7b1e9607f369dac8e3a3024df8f";
        bytes
            memory proof = hex"a4594c5906dcbf4be9fa2dac8014358e8cc837b90f33c94023373f576c0bb7b544e5faeb1d0fe853812adf72ce137a1bc842772a8a37bfc369deebdd3071b71d8322e93d2a48173cdc2a01cdd34fddf394fc7e6213389386ccd4dd56a6d8234bb6f663260c95cd8ff3d38a9abfd8f7af6f2e7cda73d6b7e37f1dde626e622cff790fe39604a0bf4e8c3164489835876f0f53a77cfda729362295203f9cd1b8641836705520213e25de828eb583445b1bc984ad84b264f2a61635d77ef1726d9dfb453d4f1ad527c4388baeb44b0f2e2a6190a5018212715af8def62a51073b608fd566420138a3fe494a869084e09bb3c2d9984c7cc50f50504ddb32380d72827c12013c";

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
