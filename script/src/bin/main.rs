use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng; // 随机数生成器
use shared_lib::Ed25519VerificationData;
use std::time::Instant;
use clap::{Parser, ValueEnum};


/// The arguments for the ed25519 script.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, value_enum, default_value = "compressed")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Core,
    Compressed,
    // Plonk,
    // Groth16,
}

fn main() {
    // 1. 设置环境 (日志等)
    sp1_sdk::utils::setup_logger();

    // 解析命令行参数
    let args = Args::parse();

    // 2. 模拟用户行为：生成密钥并签名
    // 在实际应用中，这里可能是从钱包 (Wallet) 接收签名，或者是读取本地私钥文件
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    
    // 交易内容 X
    let message = b"Uni-RWA Cross-Chain Asset Transfer: 100 USDC to Ethereum".to_vec();
    
    // 签名 (纯本地操作，不涉及 zkVM)
    let signature = signing_key.sign(&message);
    
    println!("Public Key: {:?}", hex::encode(verifying_key.to_bytes()));
    println!("Signature: {:?}", hex::encode(signature.to_bytes()));

    // 3. 准备 zkVM 输入
    let input_data = Ed25519VerificationData {
        pub_key: verifying_key.to_bytes(),
        signature: signature.to_bytes(),
        message: message.clone(),
    };

    // 写入 SP1Stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_data);

    // 4. 初始化 Prover 并加载 ELF
    let client = ProverClient::from_env();
    // include_elf! 宏会加载编译好的 Guest 二进制文件
    let elf = include_elf!("ed25519-program");
    
    // 获取执行统计信息 (Cycles / Constraints)
    println!("Executing program to collect statistics...");
    let (_, report) = client.execute(elf, &stdin).run().expect("Execution failed");
    let total_cycles = report.total_instruction_count();
    println!("Program executed successfully with {} cycles.", total_cycles);

    // 设置证明密钥 (Proving Key) 和 验证密钥 (Verifying Key)
    let (pk, vk) = client.setup(elf);

    // 5. 生成证明
    println!("Starting proof generation ({:?} mode)...", args.system);
    let prover_start = Instant::now();
    let mut proof = match args.system {
        ProofSystem::Core => client.prove(&pk, &stdin).run(),
        ProofSystem::Compressed => client.prove(&pk, &stdin).compressed().run(),
        // ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        // ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("Proof generation failed");
     
// 2. ✅ 安全地计算 Proof 大小
    // 使用 bincode 序列化整个 proof 对象 (包含 public values)
    let serialized_proof = bincode::serialize(&proof).expect("failed to serialize proof"
);
    let proof_size = serialized_proof.len();
    
    let prover_duration = prover_start.elapsed();
    println!("Proof generated successfully in {:?}", prover_duration);

    // 6. 验证证明 (本地完整性检查)
    println!("Starting proof verification...");
    let verifier_start = Instant::now();
    client.verify(&proof, &vk).expect("Verification failed");
    let verifier_duration = verifier_start.elapsed();
    println!("Proof verified successfully in {:?}", verifier_duration);

    // 7. 读取公共输出以确认
    let committed_pub_key = proof.public_values.read::<[u8; 32]>();
    let committed_message = proof.public_values.read::<Vec<u8>>();

    assert_eq!(committed_pub_key, verifying_key.to_bytes());
    assert_eq!(committed_message, message);
    let total_cycles = report.total_instruction_count();

    println!("Assertion Verified: Proof binds Address to Transaction X");
    
    // 8. 性能总结
    println!("\n--- Performance Metrics ---");
    println!("Cycle Count (Constraints): {}", total_cycles);
    println!("Prover Time: {:?}", prover_duration);
    println!("Verifier Time: {:?}", verifier_duration);
    println!("Proof Size: {} bytes", proof_size);
    println!("Peak RAM: See SP1 logger output for system-level memory usage.");
    println!("---------------------------\n");

    // client.export_solidity_verifier(&vk);
}
