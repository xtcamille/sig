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
            0x0035377f4a38ef9a2919dc3632097ec32609cf73a5fb7059c09329400b627212
        );

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public view {
        bytes
            memory pubKey = hex"d9324c72486871eac2bb7bf710574eccfb246ad641531dc7966bc46b468dc42b";
        bytes
            memory message = hex"556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d";
        bytes
            memory signature = hex"40030d8a69c9d534894dd9c57829a4c92fcdf54c9ebaa8d55eaa6944e3435cb935976801724aae8b37982263dd594bfa412856754faa2c07478448276344ad0a";
        bytes
            memory publicValues = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000020d9324c72486871eac2bb7bf710574eccfb246ad641531dc7966bc46b468dc42b0000000000000000000000000000000000000000000000000000000000000038556e692d5257412043726f73732d436861696e204173736574205472616e736665723a20313030205553444320746f20457468657265756d0000000000000000000000000000000000000000000000000000000000000000000000000000004040030d8a69c9d534894dd9c57829a4c92fcdf54c9ebaa8d55eaa6944e3435cb935976801724aae8b37982263dd594bfa412856754faa2c07478448276344ad0a";
        bytes
            memory proof = hex"a4594c59178bbe92f86e4bb72cb3bb0715d85998d248ded109eecf258afc49f49a2e4fa408371320795f33ac03b91cdbd8ba3416b5bd2cf1146a75c73e0c2055783898d505f71663848a4c5b69407167464a65ba15e299b0c968b5e15c7902841468100e12deaa7477de96567a09e3fecc06c4543019e535889597f972d1ba620475acab2d61facd8bd31fe11bbdd4ba083fdead8703c9c534f75e2780ab947629b7444027d1bf2e5d7b82b21e2468ce144f40d641259bda58f92dd4860a52a8672345a00cf470c506e79086c99b36c391f65df37eb4d2da28704c495ed7affeb74a80101522df8d44bbf63c03644ea9650128891fcc2634a68264181712ec763168d2f8";

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
