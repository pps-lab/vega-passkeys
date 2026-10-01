mod common;

use bellpepper_core::test_cs::TestConstraintSystem;
use pop_vega::api::{expected_public_values, scalar_to_hex};
use pop_vega::circuit::{PopCircuit, PopWitness};
use pop_vega::Scalar;

fn satisfied(w: PopWitness) -> bool {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  PopCircuit { w }.synthesize_all(&mut cs).expect("synthesis");
  if let Some(c) = cs.which_is_unsatisfied() {
    println!("unsatisfied: {c}");
  }
  cs.is_satisfied()
}

#[test]
fn valid_assertion_satisfies() {
  let f = common::fixture();
  let w = f.inputs.witness().unwrap();
  assert_eq!(w.root(), f.root);
  let publics: Vec<String> = w.public_values().iter().map(scalar_to_hex).collect();
  assert_eq!(publics, expected_public_values(&f.challenge, &f.root));

  let mut cs = TestConstraintSystem::<Scalar>::new();
  PopCircuit { w }.synthesize_all(&mut cs).unwrap();
  assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
  println!("constraints: {}, inputs: {}", cs.num_constraints(), cs.num_inputs());
}

#[test]
fn other_leaf_positions_satisfy() {
  for idx in [0, 1, 0xfffff] {
    let f = common::fixture_with(&[9u8; 32], [1u8; 32], idx);
    assert!(satisfied(f.inputs.witness().unwrap()), "leaf {idx}");
  }
}

#[test]
fn tampered_signature_fails() {
  let mut w = common::fixture().inputs.witness().unwrap();
  w.r += 1;
  assert!(!satisfied(w));
}

#[test]
fn wrong_key_fails() {
  let mut w = common::fixture().inputs.witness().unwrap();
  let other = common::fixture_with(&[8u8; 32], [42u8; 32], 5).inputs.witness().unwrap();
  w.qx = other.qx;
  w.qy = other.qy;
  assert!(!satisfied(w));
}

#[test]
fn different_public_challenge_fails() {
  // Signed clientDataJSON carries challenge [42; 32]; claim a different one.
  let mut w = common::fixture().inputs.witness().unwrap();
  w.challenge[0] ^= 1;
  assert!(!satisfied(w));
}

#[test]
fn wrong_challenge_offset_fails() {
  let mut w = common::fixture().inputs.witness().unwrap();
  w.challenge_offset += 1;
  assert!(!satisfied(w));
}

#[test]
fn tampered_client_data_fails() {
  let mut w = common::fixture().inputs.witness().unwrap();
  let last = w.cdj.len() - 2;
  w.cdj[last] ^= 1; // outside the challenge; breaks the hash in the signed message
  assert!(!satisfied(w));
}

#[test]
fn tampered_auth_data_fails() {
  let mut w = common::fixture().inputs.witness().unwrap();
  w.msg[32] ^= 0x04; // flip UV
  assert!(!satisfied(w));
}

#[test]
fn wrong_merkle_path_fails() {
  // The circuit exposes whatever root the path leads to; a wrong path yields a root
  // that the verifier's comparison against the live tree rejects.
  let mut w = common::fixture().inputs.witness().unwrap();
  w.path[3] += Scalar::from(1u64);
  assert_ne!(w.root(), common::fixture().root);
  let mut w2 = common::fixture().inputs.witness().unwrap();
  w2.indices[0] = !w2.indices[0];
  // The root changes, so the honest public root no longer matches the original.
  assert_ne!(w2.root(), common::fixture().root);
}

#[test]
fn shape_is_witness_independent() {
  let count = |w: PopWitness| {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    PopCircuit { w }.synthesize_all(&mut cs).unwrap();
    (cs.num_constraints(), cs.num_inputs())
  };
  let real = common::fixture().inputs.witness().unwrap();
  assert_eq!(count(PopWitness::dummy()), count(real));
}
