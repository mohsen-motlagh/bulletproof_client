use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use reqwest::Error;
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct ProofData {
    proof: Vec<u8>,
    committed_value: Vec<u8>,
    proof_size: usize, // Store the size of the proof in bytes
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let blinding = Scalar::random(&mut OsRng);

    let mut prover_transcript = Transcript::new(b"ProveKnowledgeOfSecret");
    let secret_value = 42u64; // The secret as a u64

    // Start timing the proof generation
    let start_time = Instant::now();

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        64,
    ).expect("Proof generation should not fail");

    // End timing and calculate duration
    let duration = start_time.elapsed();

    let proof_bytes = proof.to_bytes();
    let committed_value_bytes = committed_value.to_bytes();

    // Calculate proof size
    let proof_size = proof_bytes.len();
    println!("Proof size: {} bytes", proof_size);
    println!("Proof generation time: {:?}", duration);
    let proof_data = ProofData {
        proof: proof_bytes.to_vec(),
        committed_value: committed_value_bytes.to_vec(),
        proof_size, // Include the size of the proof in the output
    };

    let client = reqwest::Client::new();
    let server_url = std::env::var("SERVER_URL").unwrap_or_else(|_| "http://server_bulletproof:8080/verify_proof".to_string());
    let res = client.post(&server_url)
    .json(&proof_data)
    .send()
    .await?;

    // Debugging: Print or log the status code and response body for more insight
    let status = res.status();
    let body = res.text().await?;

    println!("Response status: {}", status);
    println!("Response body: {}", body);

    if status.is_success() {
        println!("Proof successfully verified by the server.");
    } else {
        println!("Proof verification failed.");
    }
    
    Ok(())
}
