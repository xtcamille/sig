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