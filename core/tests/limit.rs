//! The limit circuit: satisfiable for honest witnesses, and for nothing else.
//! Proving tests are slow in debug; run with --release.
mod common;

use bellpepper_core::test_cs::TestConstraintSystem;
use pop_vega::api::{self, scalar_to_hex, LimitInputs};
use pop_vega::circuit::{PopCircuit, TREE_DEPTH};
use pop_vega::limit::{LimitCircuit, LimitWitness, LIMIT_BITS, MAX_LIMIT};
use pop_vega::{poseidon, Scalar};

const SECRET: u64 = 0x5ec2e7;

/// Inputs whose path (the fixture's siblings) is read from the limit leaf.
fn inputs(counter: u32, limit: u32) -> LimitInputs {
  LimitInputs {
    pop: common::fixture().inputs,
    secret: scalar_to_hex(&Scalar::from(SECRET)),
    epoch: scalar_to_hex(&api::epoch_from_label("event/1")),
    counter,
    limit,
  }
}

fn witness(counter: u32, limit: u32) -> LimitWitness {
  inputs(counter, limit).witness().unwrap()
}

/// Synthesizes `w`, then overwrites nothing: every wire is computed from the witness as given.
fn unsatisfied(w: LimitWitness) -> Option<String> {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  LimitCircuit { w }.synthesize_all(&mut cs).expect("synthesis");
  cs.which_is_unsatisfied().map(String::from)
}

/// Public inputs as the circuit allocated them (input 0 is the constant one).
fn circuit_publics(w: LimitWitness) -> (TestConstraintSystem<Scalar>, Vec<String>) {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  LimitCircuit { w }.synthesize_all(&mut cs).unwrap();
  let publics = cs.scalar_inputs()[1..].iter().map(scalar_to_hex).collect();
  (cs, publics)
}

#[test]
fn honest_uses_satisfy() {
  for (counter, limit) in [(0, 1), (0, 5), (4, 5), (0, MAX_LIMIT), (MAX_LIMIT - 1, MAX_LIMIT)] {
    assert_eq!(unsatisfied(witness(counter, limit)), None, "{counter} of {limit}");
  }
}

#[test]
fn public_values_match_the_wires() {
  let w = witness(3, 5);
  let expected: Vec<String> = w.public_values().iter().map(scalar_to_hex).collect();
  let (cs, publics) = circuit_publics(w.clone());
  assert!(cs.is_satisfied());
  assert_eq!(publics, expected);
  // What the verifier recomputes is everything but the token.
  let f = common::fixture();
  let want = api::expected_limit_public_values(&f.challenge, &w.root(), &api::epoch_from_label("event/1"), 5).unwrap();
  assert_eq!(publics[..5], want[..]);
  assert_eq!(publics[5], scalar_to_hex(&poseidon::limit_token(Scalar::from(SECRET), w.epoch, 3)));
}

#[test]
fn counter_at_or_over_the_limit_fails() {
  assert!(inputs(5, 5).witness().is_err());
  for (counter, limit) in [(1, 1), (5, 5), (6, 5), (MAX_LIMIT, MAX_LIMIT), (u32::MAX, 5), (0, 0)] {
    let mut w = witness(0, 1);
    w.counter = counter;
    w.limit = limit;
    assert!(unsatisfied(w).is_some(), "{counter} of {limit} must not satisfy");
  }
}

#[test]
fn limit_is_bounded() {
  assert!(inputs(0, 0).witness().is_err());
  assert!(inputs(0, MAX_LIMIT + 1).witness().is_err());
  assert_eq!(MAX_LIMIT, 1 << LIMIT_BITS);
}

#[test]
fn limit_public_input_is_bound() {
  // Claim a larger limit on the wire than the counter's range proof was built for.
  let (mut cs, _) = circuit_publics(witness(0, 1));
  cs.set("limit/num", Scalar::from(5u64));
  assert!(!cs.is_satisfied());
}

#[test]
fn every_public_input_is_bound() {
  let (cs, publics) = circuit_publics(witness(0, 1));
  assert!(cs.is_satisfied());
  assert_eq!(publics.len(), 6);
  for path in ["epoch input/input variable", "limit input/input variable", "token input/input variable", "limit root/input variable"] {
    let (mut cs, _) = circuit_publics(witness(0, 1));
    cs.set(path, Scalar::from(77u64));
    assert!(!cs.is_satisfied(), "{path} is free");
  }
}

#[test]
fn token_wires_are_bound() {
  // A prover who changes the counter or the secret on the PRF's side only.
  for path in ["counter/num", "secret/num", "zero/num"] {
    let (mut cs, _) = circuit_publics(witness(0, 3));
    cs.set(path, Scalar::from(1u64));
    assert!(!cs.is_satisfied(), "{path} is free");
  }
}

#[test]
fn another_secret_is_another_leaf() {
  // The circuit accepts any secret, but the leaf and so the root are then not the registered ones.
  let honest = witness(0, 1);
  let mut other = honest.clone();
  other.secret += Scalar::from(1u64);
  assert_eq!(unsatisfied(other.clone()), None);
  assert_ne!(other.root(), honest.root());
  // And a key without a secret's leaf (the plain tree's leaf) leads elsewhere too.
  assert_ne!(honest.root(), honest.pop.root());
}

#[test]
fn another_key_with_the_same_secret_fails_or_is_another_leaf() {
  let honest = witness(0, 1);
  let mut other = honest.clone();
  other.pop = common::fixture_with(&[8u8; 32], [42u8; 32], 5).inputs.witness().unwrap();
  assert_ne!(other.leaf(), honest.leaf());
  // Keeping the first key's signature with the second key breaks the ECDSA check.
  let mut mixed = honest;
  mixed.pop.qx = other.pop.qx;
  mixed.pop.qy = other.pop.qy;
  assert!(unsatisfied(mixed).is_some());
}

#[test]
fn tampered_signature_fails() {
  let mut w = witness(0, 1);
  w.pop.r += 1;
  assert!(unsatisfied(w).is_some());
}

#[test]
fn tokens_are_deterministic_and_distinct() {
  let token = |secret: u64, label: &str, counter: u32| poseidon::limit_token(Scalar::from(secret), api::epoch_from_label(label), counter);
  assert_eq!(token(1, "a", 0), token(1, "a", 0));
  let all = [token(1, "a", 0), token(1, "a", 1), token(1, "b", 0), token(2, "a", 0), token(1, "b", 1)];
  for i in 0..all.len() {
    for j in 0..i {
      assert_ne!(all[i], all[j]);
    }
  }
  // The same device's token doesn't depend on the challenge, the limit or the tree.
  let mut w = witness(0, 1);
  let t = w.token();
  w.limit = 9;
  w.pop.path[0] += Scalar::from(1u64);
  assert_eq!(w.token(), t);
}

#[test]
fn epoch_label_vector() {
  // SHA-256("verena/epoch/v1" ‖ 00 ‖ "event/1")[..31], also in test/epoch-limit.test.js.
  let mut be = [0u8; 32];
  use sha2::{Digest, Sha256};
  be[1..].copy_from_slice(&Sha256::digest(b"verena/epoch/v1\0event/1")[..31]);
  assert_eq!(scalar_to_hex(&api::epoch_from_label("event/1")), format!("0x{}", hex::encode(be)));
}

#[test]
fn secret_from_random_is_below_the_modulus() {
  assert!(api::secret_from_random(&[0xff; 32]).is_ok());
  assert!(api::secret_from_random(&[0xff; 31]).is_err());
}

#[test]
fn shape_is_witness_independent() {
  let count = |w: LimitWitness| {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    LimitCircuit { w }.synthesize_all(&mut cs).unwrap();
    (cs.num_constraints(), cs.num_inputs())
  };
  let dummy = count(LimitWitness::dummy(TREE_DEPTH));
  assert_eq!(dummy, count(witness(3, 5)));
  let mut cs = TestConstraintSystem::<Scalar>::new();
  PopCircuit { w: common::fixture().inputs.witness().unwrap() }.synthesize_all(&mut cs).unwrap();
  println!("limit circuit: {dummy:?}, plain circuit: {} constraints", cs.num_constraints());
}

#[test]
fn prove_and_verify_roundtrip() {
  let (pk, vk) = api::setup_limit(TREE_DEPTH).unwrap();
  let w = witness(2, 5);
  let expected: Vec<String> = w.public_values().iter().map(scalar_to_hex).collect();
  let t = std::time::Instant::now();
  let out = api::prove_limit(&pk, w).unwrap();
  println!("limit prove: {:?}, proof: {} bytes", t.elapsed(), out.proof.len());
  let t = std::time::Instant::now();
  assert_eq!(api::verify(&vk, &out.proof).unwrap(), expected);
  println!("limit verify: {:?}", t.elapsed());

  // An out-of-range counter has no proof that verifies.
  let mut bad = witness(0, 1);
  bad.counter = 1;
  if let Ok(out) = api::prove_limit(&pk, bad) {
    assert!(api::verify(&vk, &out.proof).is_err());
  }
  // The plain circuit's key doesn't accept a limited proof, nor the other way round.
  let (plain_pk, plain_vk) = api::setup().unwrap();
  assert!(api::verify(&plain_vk, &out.proof).is_err());
  let plain = api::prove(&plain_pk, common::fixture().inputs.witness().unwrap()).unwrap();
  assert!(api::verify(&vk, &plain.proof).is_err());
}
