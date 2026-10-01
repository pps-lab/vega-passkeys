//! Poseidon over the P-256 base field (the circuit's native field), t = 3, x^7 S-box.
//!
//! Replaces the BN254 Poseidon2 used by the Noir circuit: Poseidon2's BN254 field is
//! non-native here, while P-256's base field is exactly `T256HyraxEngine::Scalar`.
//! Parameters come from `scripts/poseidon_params.py`.
//!
//! `hash2(tag, a, b)` absorbs `[tag, a, b]` into the full state, permutes once and
//! returns `state[1]`. The tag separates key commitments from Merkle nodes.

use crate::poseidon_constants::{ALPHA, MDS, R_F, R_P, ROUND_CONSTANTS, T};
use crate::Scalar;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use ff::{Field, PrimeField};
use std::sync::OnceLock;

/// Domain tag for `commitment(x, y)`.
pub const TAG_COMMITMENT: u64 = 1;
/// Domain tag for a Merkle node `H(left, right)`.
pub const TAG_NODE: u64 = 2;

struct Params {
  rc: Vec<Scalar>,
  mds: [[Scalar; T]; T],
}

fn params() -> &'static Params {
  static PARAMS: OnceLock<Params> = OnceLock::new();
  PARAMS.get_or_init(|| Params {
    rc: ROUND_CONSTANTS.iter().map(|h| scalar_from_hex(h)).collect(),
    mds: MDS.map(|row| row.map(scalar_from_hex)),
  })
}

/// Parses a `0x`-prefixed big-endian hex field element.
pub fn scalar_from_hex(h: &str) -> Scalar {
  let mut be = [0u8; 32];
  hex::decode_to_slice(h.trim_start_matches("0x"), &mut be).expect("valid 32-byte hex");
  scalar_from_be_bytes(&be).expect("constant below modulus")
}

/// Big-endian 32 bytes to a field element; `None` if not below the modulus.
pub fn scalar_from_be_bytes(be: &[u8; 32]) -> Option<Scalar> {
  let mut repr = <Scalar as PrimeField>::Repr::default();
  let mut le = *be;
  le.reverse();
  repr.as_mut().copy_from_slice(&le);
  Option::from(Scalar::from_repr(repr))
}

/// Field element to big-endian 32 bytes.
pub fn scalar_to_be_bytes(s: &Scalar) -> [u8; 32] {
  let mut out = [0u8; 32];
  out.copy_from_slice(s.to_repr().as_ref());
  out.reverse();
  out
}

// `sbox` and `sbox_gadget` hardcode x^7.
const _: () = assert!(ALPHA == 7);

fn sbox(x: Scalar) -> Scalar {
  let x2 = x.square();
  let x4 = x2.square();
  x4 * x2 * x
}

fn is_full_round(r: usize) -> bool {
  r < R_F / 2 || r >= R_F / 2 + R_P
}

/// The Poseidon permutation.
pub fn permute(mut state: [Scalar; T]) -> [Scalar; T] {
  let p = params();
  for r in 0..R_F + R_P {
    for (i, s) in state.iter_mut().enumerate() {
      *s += p.rc[r * T + i];
    }
    if is_full_round(r) {
      for s in state.iter_mut() {
        *s = sbox(*s);
      }
    } else {
      state[0] = sbox(state[0]);
    }
    let mut next = [Scalar::ZERO; T];
    for (i, n) in next.iter_mut().enumerate() {
      for (j, s) in state.iter().enumerate() {
        *n += p.mds[i][j] * s;
      }
    }
    state = next;
  }
  state
}

/// Two-to-one hash with a domain tag.
pub fn hash2(tag: u64, a: Scalar, b: Scalar) -> Scalar {
  permute([Scalar::from(tag), a, b])[1]
}

/// Commitment to a P-256 public key; x and y are native field elements.
pub fn commitment(x: Scalar, y: Scalar) -> Scalar {
  hash2(TAG_COMMITMENT, x, y)
}

/// Merkle node.
pub fn node(left: Scalar, right: Scalar) -> Scalar {
  hash2(TAG_NODE, left, right)
}

/// A state element: a linear combination plus its witness value. Keeping the linear
/// layer symbolic means only the S-boxes cost constraints (4 per x^7).
#[derive(Clone)]
struct Elt {
  lc: LinearCombination<Scalar>,
  val: Option<Scalar>,
}

fn sbox_gadget<CS: ConstraintSystem<Scalar>>(mut cs: CS, x: &Elt) -> Result<Elt, SynthesisError> {
  let x2 = AllocatedNum::alloc(cs.namespace(|| "x2"), || x.val.map(|v| v.square()).ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(|| "x*x=x2", |_| x.lc.clone(), |_| x.lc.clone(), |lc| lc + x2.get_variable());
  let x4 = x2.square(cs.namespace(|| "x4"))?;
  let x6 = x4.mul(cs.namespace(|| "x6"), &x2)?;
  let x7 = AllocatedNum::alloc(cs.namespace(|| "x7"), || x.val.map(sbox).ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(|| "x6*x=x7", |lc| lc + x6.get_variable(), |_| x.lc.clone(), |lc| lc + x7.get_variable());
  Ok(Elt { lc: LinearCombination::from_variable(x7.get_variable()), val: x7.get_value() })
}

fn permute_gadget<CS: ConstraintSystem<Scalar>>(mut cs: CS, input: [Elt; T]) -> Result<[Elt; T], SynthesisError> {
  let p = params();
  let mut state = input;
  for r in 0..R_F + R_P {
    for (i, s) in state.iter_mut().enumerate() {
      let c = p.rc[r * T + i];
      s.lc = s.lc.clone() + (c, CS::one());
      s.val = s.val.map(|v| v + c);
    }
    for i in 0..T {
      if i == 0 || is_full_round(r) {
        state[i] = sbox_gadget(cs.namespace(|| format!("round {r} sbox {i}")), &state[i])?;
      }
    }
    let next: [Elt; T] = std::array::from_fn(|i| {
      let mut lc = LinearCombination::zero();
      let mut val = Some(Scalar::ZERO);
      for (j, s) in state.iter().enumerate() {
        lc = lc + (p.mds[i][j], &s.lc);
        val = val.zip(s.val).map(|(acc, v)| acc + p.mds[i][j] * v);
      }
      Elt { lc, val }
    });
    state = next;
  }
  Ok(state)
}

/// In-circuit `hash2(tag, a, b)`; returns the output as an allocated number.
pub fn hash2_gadget<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  tag: u64,
  a: &AllocatedNum<Scalar>,
  b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let tag = Scalar::from(tag);
  let input = [
    Elt { lc: LinearCombination::zero() + (tag, CS::one()), val: Some(tag) },
    Elt { lc: LinearCombination::from_variable(a.get_variable()), val: a.get_value() },
    Elt { lc: LinearCombination::from_variable(b.get_variable()), val: b.get_value() },
  ];
  let out = permute_gadget(cs.namespace(|| "permute"), input)?;
  let res = AllocatedNum::alloc(cs.namespace(|| "out"), || out[1].val.ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(|| "out == state[1]", |_| out[1].lc.clone(), |lc| lc + CS::one(), |lc| lc + res.get_variable());
  Ok(res)
}

#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;

  #[test]
  fn gadget_matches_native() {
    let a = Scalar::from(12345u64);
    let b = -Scalar::from(678u64);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let an = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(a)).unwrap();
    let bn = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(b)).unwrap();
    let out = hash2_gadget(cs.namespace(|| "h"), TAG_NODE, &an, &bn).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(out.get_value().unwrap(), node(a, b));
    assert_ne!(node(a, b), commitment(a, b));
    println!("poseidon hash2 constraints: {}", cs.num_constraints());
  }

  #[test]
  fn byte_roundtrip() {
    let s = node(Scalar::ONE, Scalar::ZERO);
    assert_eq!(scalar_from_be_bytes(&scalar_to_be_bytes(&s)), Some(s));
  }
}
