mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bellpepper_core::test_cs::TestConstraintSystem;
use pop_vega::api::{expected_public_values, scalar_to_hex};
use pop_vega::circuit::{split, AccCircuit, PopCircuit, PopWitness, SigCircuit, TREE_DEPTH};
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
fn uv_unset_fails() {
  // A genuinely signed assertion with UP but not UV.
  let f = common::fixture_with_flags(&[7u8; 32], [42u8; 32], 5, 0x01);
  assert!(f.inputs.witness().is_err(), "witness() should reject UV=0");
  // Bypass the input check, then restore the signed flags byte: the signature is valid,
  // so only the UV constraint can fail.
  let mut inputs = f.inputs.clone();
  let mut ad = URL_SAFE_NO_PAD.decode(&inputs.authenticator_data).unwrap();
  ad[32] = 0x05;
  inputs.authenticator_data = URL_SAFE_NO_PAD.encode(&ad);
  let mut w = inputs.witness().unwrap();
  w.msg[32] = 0x01;
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
  assert_eq!(count(PopWitness::dummy(TREE_DEPTH)), count(real));
}

#[test]
fn other_depths_satisfy() {
  for depth in [22, 28] {
    let f = common::fixture_at_depth(&[9u8; 32], [1u8; 32], 5, depth);
    let w = f.inputs.witness().unwrap();
    assert_eq!(w.path.len(), depth);
    assert_eq!(w.root(), f.root);
    assert!(satisfied(w), "depth {depth}");
  }
}

fn sig_ok(c: SigCircuit) -> bool {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  c.synthesize_all(&mut cs).expect("synthesis");
  cs.is_satisfied()
}

fn acc_ok(c: AccCircuit) -> bool {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  c.synthesize_all(&mut cs).expect("synthesis");
  cs.is_satisfied()
}

#[test]
fn split_halves_satisfy_and_link() {
  for depth in [20, 26] {
    let f = common::fixture_at_depth(&[9u8; 32], [3u8; 32], 11, depth);
    let (sig, acc) = split(f.inputs.witness().unwrap(), Scalar::from(777u64));
    let (sp, ap) = (sig.public_values(), acc.public_values());
    assert_eq!(sp[2], ap[0], "both halves expose the same link");
    assert_eq!(ap[1], f.root);
    assert!(sig_ok(sig) && acc_ok(acc), "depth {depth}");
  }
}

#[test]
fn split_link_hides_leaf_and_depends_on_blind() {
  let w = common::fixture().inputs.witness().unwrap();
  let (_, a1) = split(w.clone(), Scalar::from(1u64));
  let (_, a2) = split(w, Scalar::from(2u64));
  assert_ne!(a1.public_values()[0], a2.public_values()[0]);
  assert_ne!(a1.public_values()[0], a1.leaf);
}

#[test]
fn split_signature_rejects_tampering() {
  let mut w = common::fixture().inputs.witness().unwrap();
  w.s += 1;
  let (sig, _) = split(w, Scalar::from(1u64));
  assert!(!sig_ok(sig));
}

#[test]
fn split_shapes_are_witness_independent() {
  let count_sig = |c: SigCircuit| {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    c.synthesize_all(&mut cs).unwrap();
    (cs.num_constraints(), cs.num_inputs())
  };
  let count_acc = |c: AccCircuit| {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    c.synthesize_all(&mut cs).unwrap();
    (cs.num_constraints(), cs.num_inputs())
  };
  let (sig, acc) = split(common::fixture().inputs.witness().unwrap(), Scalar::from(5u64));
  assert_eq!(count_sig(SigCircuit::dummy()), count_sig(sig));
  assert_eq!(count_acc(AccCircuit::dummy(TREE_DEPTH)), count_acc(acc));
  println!("sig {:?} acc {:?}", count_sig(SigCircuit::dummy()), count_acc(AccCircuit::dummy(TREE_DEPTH)));
}
