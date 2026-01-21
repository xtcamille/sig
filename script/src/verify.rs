use alloy_sol_types::SolType;
use sha2::{Digest, Sha256};
use sp1_sdk::SP1ProofWithPublicValues;
use shared_lib::PublicValues;
use ark_bn254::{Bn254, G1Affine, G2Affine, Fq, Fq2, Fr, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

// --- Constants from Groth16Verifier.sol ---

const ALPHA_X: &str = "20491192805390485299153009773594534940189261866228447918068658471970481763042";
const ALPHA_Y: &str = "9383485363053290200918347156157836566562967994039712273449902621266178545958";

const BETA_NEG_X_0: &str = "6375614351688725206403948262868962793625744043794305715222011528459656738731";
const BETA_NEG_X_1: &str = "4252822878758300859123897981450591353533073413197771768651442665752259397132";
const BETA_NEG_Y_0: &str = "11383000245469012944693504663162918391286475477077232690815866754273895001727";
const BETA_NEG_Y_1: &str = "41207766310529818958173054109690360505148424997958324311878202295167071904";

const GAMMA_NEG_X_0: &str = "10857046999023057135944570762232829481370756359578518086990519993285655852781";
const GAMMA_NEG_X_1: &str = "11559732032986387107991004021392285783925812861821192530917403151452391805634";
const GAMMA_NEG_Y_0: &str = "13392588948715843804641432497768002650278120570034223513918757245338268106653";
const GAMMA_NEG_Y_1: &str = "17805874995975841540914202342111839520379459829704422454583296818431106115052";

const DELTA_NEG_X_0: &str = "1807939758600928081661535078044266309701426477869595321608690071623627252461";
const DELTA_NEG_X_1: &str = "13017767206419180294867239590191240882490168779777616723978810680471506089190";
const DELTA_NEG_Y_0: &str = "11385252965472363874004017020523979267854101512663014352368174256411716100034";
const DELTA_NEG_Y_1: &str = "707821308472421780425082520239282952693670279239989952629124761519869475067";

const CONSTANT_X: &str = "17203997695518370725253383800612862082040222186834248316724952811913305748878";
const CONSTANT_Y: &str = "282619892079818506885924724237935832196325815176482254129420869757043108110";

const PUB_0_X: &str = "2763789253671512309630211343474627955637016507408470052385640371173442321228";
const PUB_0_Y: &str = "7070003421332099028511324531870215047017050364545890942981741487547942466073";

const PUB_1_X: &str = "2223923876691923064813371578678400285087400227347901303400514986210692294428";
const PUB_1_Y: &str = "3228708299174762375496115493137156328822199374794870011715145604387710550517";

pub const GROTH16_SELECTOR: [u8; 4] = [0xa4, 0x59, 0x4c, 0x59];

fn str_to_fq(s: &str) -> Fq {
    Fq::from(BigUint::parse_bytes(s.as_bytes(), 10).unwrap())
}

fn str_to_fr(s: &str) -> Fr {
    Fr::from(BigUint::parse_bytes(s.as_bytes(), 10).unwrap())
}

/// Reproduces publicInputMSM logic.
/// Computes: CONSTANT + input[0] * PUB_0 + input[1] * PUB_1
fn public_input_msm(input: [Fr; 2]) -> G1Affine {
    let constant = G1Affine::new(str_to_fq(CONSTANT_X), str_to_fq(CONSTANT_Y));
    let pub_0 = G1Affine::new(str_to_fq(PUB_0_X), str_to_fq(PUB_0_Y));
    let pub_1 = G1Affine::new(str_to_fq(PUB_1_X), str_to_fq(PUB_1_Y));

    let mut res = G1Projective::from(constant);
    res += pub_0 * input[0];
    res += pub_1 * input[1];

    res.into_affine()
}

/// Reproduces hashPublicValues logic.
/// sha256(publicValues) & bytes32(uint256((1 << 253) - 1))
pub fn hash_public_values(public_values: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_values);
    let mut digest: [u8; 32] = hasher.finalize().into();
    digest[0] &= 0x1F;
    digest
}

/// Reproduces Groth16 verify logic.
/// e(A, B) * e(C, -delta) * e(alpha, -beta) * e(L_pub, -gamma) == 1
pub fn verify_groth16(
    proof: [G1Affine; 3], // [A, B (G2 handled separately), C]
    b_g2: G2Affine,
    public_inputs: [Fr; 2],
) -> Result<(), String> {
    let alpha = G1Affine::new(str_to_fq(ALPHA_X), str_to_fq(ALPHA_Y));
    
    // G2 points from constants (negative signs already included in Solidity constants)
    let neg_beta = G2Affine::new(
        Fq2::new(str_to_fq(BETA_NEG_X_0), str_to_fq(BETA_NEG_X_1)),
        Fq2::new(str_to_fq(BETA_NEG_Y_0), str_to_fq(BETA_NEG_Y_1))
    );
    let neg_gamma = G2Affine::new(
        Fq2::new(str_to_fq(GAMMA_NEG_X_0), str_to_fq(GAMMA_NEG_X_1)),
        Fq2::new(str_to_fq(GAMMA_NEG_Y_0), str_to_fq(GAMMA_NEG_Y_1))
    );
    let neg_delta = G2Affine::new(
        Fq2::new(str_to_fq(DELTA_NEG_X_0), str_to_fq(DELTA_NEG_X_1)),
        Fq2::new(str_to_fq(DELTA_NEG_Y_0), str_to_fq(DELTA_NEG_Y_1))
    );

    let l_pub = public_input_msm(public_inputs);

    // Pairing check
    let a = proof[0];
    let c = proof[2];

    let is_valid = Bn254::multi_pairing(
        [a, c, alpha, l_pub],
        [b_g2, neg_delta, neg_beta, neg_gamma]
    ).is_zero();

    if is_valid {
        Ok(())
    } else {
        Err("Groth16 pairing check failed.".to_string())
    }
}

/// High-level entry point to verify the entire flow.
pub fn verify_signature_flow(
    pub_key: &[u8],
    message: &[u8],
    signature: &[u8],
    vkey: [u8; 32],
    public_values: &[u8],
    proof_bytes: &[u8],
) -> Result<(), String> {
    // 1. SignatureVerifier.sol Consistency Check
    let expected_pv = PublicValues {
        pub_key: pub_key.to_vec().into(),
        message: message.to_vec().into(),
        signature: signature.to_vec().into(),
    };
    let encoded_expected = PublicValues::abi_encode(&expected_pv);
    if public_values != encoded_expected.as_slice() {
        return Err("Public values mismatch.".to_string());
    }

    // 2. SP1VerifierGroth16.sol Selection & Hashing
    if proof_bytes.len() < 4 || &proof_bytes[0..4] != GROTH16_SELECTOR {
        return Err("Wrong verifier selector.".to_string());
    }

    let pv_digest = hash_public_values(&encoded_expected);
    
    // 3. Groth16Verifier.sol Verify
    // Decode proof points from proof_bytes
    // format: [A_x, A_y, B_x1, B_x0, B_y1, B_y0, C_x, C_y] (each 32 bytes)
    let p = &proof_bytes[4..];
    if p.len() < 256 {
        return Err("Proof bytes too short for Groth16 elements.".to_string());
    }

    let decode_u256 = |offset: usize| {
        BigUint::from_bytes_be(&p[offset..offset+32])
    };

    let a = G1Affine::new(Fq::from(decode_u256(0)), Fq::from(decode_u256(32)));
    let b = G2Affine::new(
        Fq2::new(Fq::from(decode_u256(96)), Fq::from(decode_u256(64))), // Bx1, Bx0
        Fq2::new(Fq::from(decode_u256(160)), Fq::from(decode_u256(128))) // By1, By0
    );
    let c = G1Affine::new(Fq::from(decode_u256(192)), Fq::from(decode_u256(224)));

    let inputs = [
        Fr::from(BigUint::from_bytes_be(&vkey)),
        Fr::from(BigUint::from_bytes_be(&pv_digest))
    ];

    verify_groth16([a, G1Affine::default(), c], b, inputs)
}
