use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

sol! {
    /// The public values encoded as a struct that can be easily decoded in Solidity.
    struct PublicValues {
        bytes pub_key;
        bytes message;
        bytes signature;
    }
}

#[derive(Serialize, Deserialize)]
pub struct Secp256k1VerificationData {
    #[serde(with = "BigArray")]
    pub pub_key: [u8; 33],      // Secp256k1 公钥 (33字节 压缩格式)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],    // Secp256k1 签名 (64字节, r|s)

    pub message: Vec<u8>,       // 交易内容 X
}