use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use sm2::{SecretKey, dsa::{SigningKey, Signature, VerifyingKey, signature::{Signer, Verifier}}, elliptic_curve::{sec1::ToEncodedPoint, Generate}};
use shared_lib::Sm2VerificationData;
use std::time::Instant;

fn main() {
    // 1. 设置环境 (日志等)
    sp1_sdk::utils::setup_logger();

    // 2. 模拟用户行为：生成密钥并签名
    // 在实际应用中，这里可能是从钱包 (Wallet) 接收签名，或者是读取本地私钥文件
    let secret_key = SecretKey::generate();
    let signing_key = SigningKey::new("1234567812345678", &secret_key).expect("Failed to create signing key");
    let verifying_key = signing_key.verifying_key().clone();
    
    // 交易内容 X
    let message = b"Uni-RWA Cross-Chain Asset Transfer: 100 USDC to Ethereum".to_vec();
    
    // 签名 (纯本地操作，不涉及 zkVM)
    let signing_start = Instant::now();
    let signature: Signature = signing_key.sign(&message);
    let signing_duration = signing_start.elapsed();

    
    let signature_size = signature.to_bytes().len();
    println!("Public Key: {:?}", hex::encode(verifying_key.to_encoded_point(false).as_bytes()));
    println!("Signature: {:?} ({} bytes)", hex::encode(signature.to_bytes()), signature_size);

    // 直接验证签名 (Sanity Check)
    let direct_verify_start = Instant::now();
    verifying_key.verify(&message, &signature).expect("Direct verification failed");
    let direct_verify_duration = direct_verify_start.elapsed();
    println!("Direct Verification: Signature is valid. Time: {:?}", direct_verify_duration);

    // 3. 准备 zkVM 输入
    let input_data = Sm2VerificationData {
        pub_key: verifying_key.to_encoded_point(false).as_bytes().try_into().expect("Invalid public key length"),
        signature: signature.to_bytes().as_slice().try_into().expect("Invalid signature length"),
        message: message.clone(),
    };

    // 写入 SP1Stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_data);

    // 4. 初始化 Prover 并加载 ELF
    let client = ProverClient::from_env();
    // include_elf! 宏会加载编译好的 Guest 二进制文件
    let elf = include_elf!("sm2-program");
    
    // 获取执行统计信息 (Cycles / Constraints)
    println!("Executing program to collect statistics...");
    let (_, report) = client.execute(elf, &stdin).run().expect("Execution failed");
    let total_cycles = report.total_instruction_count();
    println!("Program executed successfully with {} cycles.", total_cycles);

    // 设置证明密钥 (Proving Key) 和 验证密钥 (Verifying Key)
    let (pk, vk) = client.setup(elf);

    // 5. 生成证明
    // 推荐使用 'compressed' 或 'groth16' 模式以便链上验证
    // 这里演示生成 Groth16 证明，因为它适合以太坊验证
    println!("Starting proof generation...");
    let prover_start = Instant::now();
    let mut proof = client.prove(&pk, &stdin).groth16().run().expect("Proof generation failed");
    let prover_duration = prover_start.elapsed();
    println!("Proof generated successfully in {:?}", prover_duration);

    let proof_size = proof.bytes().len();
    

    // 6. 验证证明 (本地完整性检查)
    println!("Starting proof verification...");
    let verifier_start = Instant::now();
    client.verify(&proof, &vk).expect("Verification failed");
    let verifier_duration = verifier_start.elapsed();
    println!("Proof verified successfully in {:?}", verifier_duration);

    // 7. 读取公共输出以确认
    use alloy_sol_types::SolType;
    use shared_lib::PublicValuesStruct;
    
    let public_values = PublicValuesStruct::abi_decode(proof.public_values.as_slice())
        .expect("Failed to decode public values");
    let committed_pub_key = public_values.pubKey;
    let committed_message = public_values.message;
    let committed_signature = public_values.signature;

    assert_eq!(committed_pub_key, verifying_key.to_encoded_point(false).as_bytes());
    assert_eq!(committed_message, message);
    assert_eq!(committed_signature, signature.to_bytes().as_slice());

    println!("Assertion Verified: Proof binds Address to Transaction X");
    
    // 8. 性能总结
    println!("\n--- Performance Metrics ---");
    println!("Signature Size: {} bytes", signature_size);
    println!("Signing Time: {:?}", signing_duration);
    println!("Direct Verification Time: {:?}", direct_verify_duration);
    println!("Cycle Count (Constraints): {}", total_cycles);
    println!("Prover Time: {:?}", prover_duration);
    println!("Verifier Time: {:?}", verifier_duration);
    println!("SP1 Proof size: {} bytes", proof_size);
    println!("Peak RAM: See SP1 logger output for system-level memory usage.");
    println!("---------------------------\n");

    // client.export_solidity_verifier(&vk);
}
