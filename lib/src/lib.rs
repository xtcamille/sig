use serde::{Deserialize, Serialize};

#
pub struct Ed25519VerificationData {
    pub pub_key: [u8; 32],      // Ed25519 公钥 (32字节)
    pub signature: [u8; 64],    // Ed25519 签名 (64字节)
    pub message: Vec<u8>,       // 交易内容 X
}