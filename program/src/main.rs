#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use shared_lib::{Ed25519VerificationData, PublicValuesStruct};

pub fn main() {
    // 1. 读取输入
    // 从 Host 传入的序列化数据中读取公钥、签名和消息
    let input: Ed25519VerificationData = sp1_zkvm::io::read();

    // 2. 重建公钥对象
    // from_bytes 会检查公钥点是否在曲线上，这是一个昂贵的操作，但被预编译加速
    let verifying_key = VerifyingKey::from_bytes(&input.pub_key)
       .expect("Invalid Ed25519 Public Key");

    // 3. 重建签名对象
    let signature = Signature::from_bytes(&input.signature);

    // 4. 执行核心验证
    // 这里调用的是 ed25519_dalek::verify。
    // 由于应用了补丁，这个调用会被编译为 SP1 的特殊系统调用，
    // 直接在 Ed25519 预编译电路中执行，而不是在 RISC-V CPU 中模拟。
    // 如果验证失败，程序会 panic，导致证明生成失败。
    // 因此，生成了证明就意味着验证通过。
    verifying_key
       .verify(&input.message, &signature)
       .expect("Ed25519 Signature Verification Failed");

    // 5. 提交公共输出 (Public Values)
    // 这一步至关重要。我们需要告诉链上验证者：
    // “这个证明是关于 地址 A (input.pub_key) 和 交易 X (input.message) 的”
    // 如果不提交这些值，拥有者可以为任意公钥生成证明，链上将无法区分。
    // 可选：打印日志（仅在调试模式下可见）
    println!("Successfully verified signature for message len: {}", input.message.len());

    let public_values = PublicValuesStruct {
        pub_key: input.pub_key.into(),
        signature: input.signature.into(),
        message: input.message.into(),
    };
    sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
}