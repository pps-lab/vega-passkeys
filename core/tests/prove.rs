//! Full Vega setup → prove → verify roundtrip. Slow in debug; run with --release.
mod common;

use pop_vega::api::{self, expected_public_values};
use std::time::Instant;

#[test]
fn prove_and_verify_roundtrip() {
  let t = Instant::now();
  let (pk, vk) = api::setup().unwrap();
  println!("setup: {:?}", t.elapsed());
  let pk_bytes = api::serialize(&pk).unwrap();
  let vk_bytes = api::serialize(&vk).unwrap();
  println!("pk: {} bytes, vk: {} bytes", pk_bytes.len(), vk_bytes.len());

  let f = common::fixture();
  let t = Instant::now();
  let out = api::prove(&pk, f.inputs.witness().unwrap()).unwrap();
  println!("prove: {:?}, proof: {} bytes", t.elapsed(), out.proof.len());
  assert_eq!(out.public_values, expected_public_values(&f.challenge, &f.root));

  // Verify with a deserialized key, as the server does.
  let vk2: api::VerifierKey = api::deserialize(&vk_bytes).unwrap();
  let t = Instant::now();
  let publics = api::verify(&vk2, &out.proof).unwrap();
  println!("verify: {:?}", t.elapsed());
  assert_eq!(publics, out.public_values);

  // A corrupted proof must not verify.
  let mut bad = out.proof.clone();
  let mid = bad.len() / 2;
  bad[mid] ^= 1;
  assert!(api::verify(&vk2, &bad).is_err());
}
