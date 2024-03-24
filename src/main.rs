use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use reqwest::Error;
use serde::Serialize;

#[derive(Serialize)]
struct ProofData {
    proof: Vec<u8>,
    committed_value: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let blinding = Scalar::random(&mut OsRng);

    let mut prover_transcript = Transcript::new(b"ProveKnowledgeOfSecret");
    let secret_value = 42u64; // The secret as a u64

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        64,
    ).expect("Proof generation should not fail");

    let proof_bytes = proof.to_bytes();
    let committed_value_bytes = committed_value.to_bytes();

    let proof_data = ProofData {
        proof: proof_bytes.to_vec(),
        committed_value: committed_value_bytes.to_vec(),
    };

    let client = reqwest::Client::new();
    let res = client.post("http://127.0.0.1:8080/verify_proof")
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
