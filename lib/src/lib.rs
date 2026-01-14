use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;


#[derive(Serialize, Deserialize)]
pub struct Sm2VerificationData {
    #[serde(with = "BigArray")]
    pub pub_key: [u8; 65],      // SM2 公钥 (65字节 非压缩格式 0x04 | x | y)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],    // SM2 签名 (64字节, r|s)

    pub message: Vec<u8>,       // 交易内容 X
}