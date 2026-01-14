#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use shared_lib::Secp256k1VerificationData;

pub fn main() {
    // 1. 读取输入
    // 从 Host 传入的序列化数据中读取公钥、签名和消息
    let input: Secp256k1VerificationData = sp1_zkvm::io::read();

    // 2. 重建公钥对象
    let verifying_key = VerifyingKey::from_sec1_bytes(&input.pub_key)
       .expect("Invalid Secp256k1 Public Key");

    // 3. 重建签名对象
    let signature = Signature::from_slice(&input.signature)
        .expect("Invalid Secp256k1 Signature");

    // 4. 执行核心验证
    // 这里调用的是 k256::ecdsa::VerifyingKey::verify。
    // 由于应用了补丁，这个调用会被编译为 SP1 的特殊系统调用，
    // 直接在 Secp256k1 预编译电路中执行。
    verifying_key
       .verify(&input.message, &signature)
       .expect("Secp256k1 Signature Verification Failed");

    // 5. 提交公共输出 (Public Values)
    // 这一步至关重要。我们需要告诉链上验证者：
    // “这个证明是关于 地址 A (input.pub_key) 和 交易 X (input.message) 的”
    // 如果不提交这些值，拥有者可以为任意公钥生成证明，链上将无法区分。
    sp1_zkvm::io::commit(&input.pub_key.as_slice());
    sp1_zkvm::io::commit(&input.message);
    
    // 可选：打印日志（仅在调试模式下可见）
    println!("Successfully verified signature for message len: {}", input.message.len());
}