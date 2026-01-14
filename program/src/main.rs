#![no_main]
sp1_zkvm::entrypoint!(main);

use sm2::dsa::{VerifyingKey, Signature, signature::Verifier};
use shared_lib::Sm2VerificationData;

pub fn main() {
    // 1. 读取输入
    // 从 Host 传入的序列化数据中读取公钥、签名和消息
    let input: Sm2VerificationData = sp1_zkvm::io::read();

    // 2. 重建公钥对象
    let verifying_key = VerifyingKey::from_sec1_bytes("1234567812345678", &input.pub_key)
       .expect("Invalid SM2 Public Key");

    // 3. 重建签名对象
    let signature = Signature::from_slice(&input.signature)
        .expect("Invalid SM2 Signature");

    // 4. 执行核心验证
    // 注意：目前 SP1 没有 SM2 的原生预编译电路，
    // 因此这里会作为普通的 Rust 代码编译并在 zkVM 中执行。
    verifying_key
       .verify(&input.message, &signature)
       .expect("SM2 Signature Verification Failed");

    // 5. 提交公共输出 (Public Values)
    // 这一步至关重要。我们需要告诉链上验证者：
    // “这个证明是关于 地址 A (input.pub_key) 和 交易 X (input.message) 的”
    // 如果不提交这些值，拥有者可以为任意公钥生成证明，链上将无法区分。
    sp1_zkvm::io::commit(&input.pub_key.as_slice());
    sp1_zkvm::io::commit(&input.message);
    
    // 可选：打印日志（仅在调试模式下可见）
    println!("Successfully verified SM2 signature for message len: {}", input.message.len());
}