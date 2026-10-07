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

#[test]
fn split_prove_and_verify_roundtrip() {
  let (sig_pk, sig_vk) = api::setup_signature().unwrap();
  let (acc_pk, acc_vk) = api::setup_accumulator(pop_vega::circuit::TREE_DEPTH).unwrap();
  let f = common::fixture();
  let (sig, acc) = api::split(f.inputs.witness().unwrap(), pop_vega::Scalar::from(99u64));
  let t = Instant::now();
  let s = api::prove_signature(&sig_pk, sig).unwrap();
  let a = api::prove_accumulator(&acc_pk, acc).unwrap();
  println!("split prove: {:?}, proofs: {} + {} bytes", t.elapsed(), s.proof.len(), a.proof.len());
  let sp = api::verify(&sig_vk, &s.proof).unwrap();
  let ap = api::verify(&acc_vk, &a.proof).unwrap();
  assert_eq!(sp, s.public_values);
  assert_eq!(ap, a.public_values);
  assert_eq!(sp[..2], expected_public_values(&f.challenge, &f.root)[..2]);
  assert_eq!(sp[2], ap[0], "linked");
  assert_eq!(ap[1], api::scalar_to_hex(&f.root));
  // Keys are not interchangeable.
  assert!(api::verify(&acc_vk, &s.proof).is_err());
}
