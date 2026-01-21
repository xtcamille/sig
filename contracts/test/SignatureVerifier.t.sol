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
} from "https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/v3.0.0/SP1VerifierGroth16.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifierContract;
    address public sp1Verifier =
        address(0x7EF2e0048f5bAeDe046f6BF797943daF4ED8CB47); // Mock or actual address

    struct Fixture {
        string pubKey;
        string message;
        string vkey;
        string publicValues;
        string proof;
    }

    function setUp() public {
        bytes32 vkey = bytes32(
            0x000abf9a8841705f09d799e68274bb147445a368162d6dfbca8fc7c3dcd99ca1
        );

        // Deploy contract
        verifierContract = new SignatureVerifier(sp1Verifier, vkey);
    }

    function test_VerifySignature() public view {
        bytes
            memory pubKey = "0x02676ea680623b7e5d9002c7a37c734c003af53dd07d0a91b78e3a44d4548c2a62";
        bytes memory message = "0x48656c6c6f2c2053503120536563703235366b3121";
        bytes
            memory signature = "0xd98c94323d33d67cc39bc48c5bf35b3682d24b20820f56f10334591bc2bd86111bca5adf6fa3b0f155eb585fc495e782afd9bb3413e5e556f14dde030e39ab24";
        bytes
            memory publicValues = "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002102676ea680623b7e5d9002c7a37c734c003af53dd07d0a91b78e3a44d4548c2a6200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001548656c6c6f2c2053503120536563703235366b31210000000000000000000000";
        bytes
            memory proof = "0xa4594c5920d4607aa9fca5019cae504b089163ad040aa1122c1b53f3bea452769ab4b08d0f79b9df1a3614f6a215b751eb0a948606478666368e4a6678651e67fa2e8d8a2451f2dcfe4612c1f442243a928e7156ebdcaa60da0b65c6d3be4a1d00d078500a796c1808a3c02ab53b0721b6d5c382d281d253105852a813f3676b3d5aa108234bb27c0bdc71cb8ee101de78b92ad3ef89f2f63862fe2ac24d848809f2a03a16be089e5277d435324c80f5b64172f9a58d5392765c7abffd4adc8aaf0617aa2f33425432be37d0c6009d501642a2b7edcad58742d2eb566dab9d1d1317b9da173af8d438165b551fcd2d6e9e777ab738c4263e937d9539dbb66ae28a0905f4";

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
