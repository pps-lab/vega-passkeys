//! Byte/bit helpers and the WebAuthn-specific checks (challenge-in-clientDataJSON,
//! clientDataJSON-hash placement in the signed message).

use crate::vendor::ecdsa::{LIMB_WIDTH, N_LIMBS};
use crate::vendor::nonnative::bignat::{limbs_to_nat, BigNat, BigNatParams};
use crate::Scalar;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::Field;

/// Allocates `bytes` as MSB-first bits.
pub fn alloc_byte_bits<CS: ConstraintSystem<Scalar>>(mut cs: CS, bytes: &[u8]) -> Result<Vec<Boolean>, SynthesisError> {
  bytes
    .iter()
    .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
    .enumerate()
    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(b)).map(Boolean::from))
    .collect()
}

/// Linear combination (and value) of an MSB-first group of bits.
pub fn bits_to_lc<CS: ConstraintSystem<Scalar>>(bits: &[Boolean]) -> (LinearCombination<Scalar>, Option<Scalar>) {
  let mut lc = LinearCombination::zero();
  let mut val = Some(Scalar::ZERO);
  let mut coeff = Scalar::ONE;
  for bit in bits.iter().rev() {
    lc = lc + &bit.lc(CS::one(), coeff);
    val = val.zip(bit.get_value()).map(|(v, b)| if b { v + coeff } else { v });
    coeff = coeff.double();
  }
  (lc, val)
}

/// Byte `i` of an MSB-first bit vector as a linear combination.
pub fn byte_lc<CS: ConstraintSystem<Scalar>>(bits: &[Boolean], i: usize) -> (LinearCombination<Scalar>, Option<Scalar>) {
  bits_to_lc::<CS>(&bits[i * 8..i * 8 + 8])
}

/// A 256-bit big-endian digest as the 4×64-bit `BigNat` the ECDSA gadget expects.
/// Limbs are linear combinations of boolean wires, so the result is well-formed.
pub fn bits_be_to_bignat<CS: ConstraintSystem<Scalar>>(bits: &[Boolean]) -> Result<BigNat<Scalar>, SynthesisError> {
  assert_eq!(bits.len(), N_LIMBS * LIMB_WIDTH);
  let mut limbs = Vec::with_capacity(N_LIMBS);
  let mut values = Some(Vec::with_capacity(N_LIMBS));
  // Limb 0 is least significant.
  for k in 0..N_LIMBS {
    let start = 256 - LIMB_WIDTH * (k + 1);
    let (lc, val) = bits_to_lc::<CS>(&bits[start..start + LIMB_WIDTH]);
    limbs.push(lc);
    values = values.zip(val).map(|(mut vs, v)| {
      vs.push(v);
      vs
    });
  }
  let value = values.as_ref().map(|vs| limbs_to_nat::<Scalar, _, _>(vs.iter(), LIMB_WIDTH));
  Ok(BigNat { limbs, limb_values: values, value, params: BigNatParams::new(LIMB_WIDTH, N_LIMBS) })
}

/// Allocates a one-hot vector of length `n` with bit `hot` set, constrained to sum to 1.
pub fn alloc_one_hot<CS: ConstraintSystem<Scalar>>(mut cs: CS, n: usize, hot: usize) -> Result<Vec<AllocatedBit>, SynthesisError> {
  let bits = (0..n)
    .map(|k| AllocatedBit::alloc(cs.namespace(|| format!("sel {k}")), Some(k == hot)))
    .collect::<Result<Vec<_>, _>>()?;
  let sum = bits.iter().fold(LinearCombination::zero(), |lc, b| lc + b.get_variable());
  cs.enforce(|| "one-hot", |_| sum, |lc| lc + CS::one(), |lc| lc + CS::one());
  Ok(bits)
}

/// Enforces `sum_k sel[k] * values[k] == target`, where `sel` is one-hot (so this
/// reads `values[hot]`). Costs one constraint per candidate.
pub fn enforce_selected_eq<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  sel: &[Boolean],
  values: &[(LinearCombination<Scalar>, Option<Scalar>)],
  target: &LinearCombination<Scalar>,
) -> Result<(), SynthesisError> {
  assert_eq!(sel.len(), values.len());
  let mut acc = LinearCombination::zero();
  for (k, (s, (v_lc, v_val))) in sel.iter().zip(values).enumerate() {
    let prod_val = s.get_value().zip(*v_val).map(|(b, v)| if b { v } else { Scalar::ZERO });
    let prod = cs.alloc(|| format!("prod {k}"), || prod_val.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce(|| format!("sel*val {k}"), |_| s.lc(CS::one(), Scalar::ONE), |_| v_lc.clone(), |lc| lc + prod);
    acc = acc + prod;
  }
  cs.enforce(|| "selected == target", |_| acc, |lc| lc + CS::one(), |_| target.clone());
  Ok(())
}

/// base64url alphabet value of a 6-bit index.
pub fn b64url_char(v: u8) -> u8 {
  match v {
    0..=25 => b'A' + v,
    26..=51 => b'a' + v - 26,
    52..=61 => b'0' + v - 52,
    62 => b'-',
    _ => b'_',
  }
}

/// Number of characters in an unpadded base64url encoding of 32 bytes.
pub const CHALLENGE_B64_LEN: usize = 43;

/// Encodes 256 MSB-first challenge bits as 43 base64url characters, each returned as
/// a linear combination over a per-character one-hot selector.
pub fn b64url_encode_challenge<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  challenge_bits: &[Boolean],
) -> Result<Vec<LinearCombination<Scalar>>, SynthesisError> {
  assert_eq!(challenge_bits.len(), 256);
  let mut out = Vec::with_capacity(CHALLENGE_B64_LEN);
  for j in 0..CHALLENGE_B64_LEN {
    // 42 full sextets, then 4 bits padded with two zero bits on the right.
    let start = j * 6;
    let end = (start + 6).min(256);
    let group = &challenge_bits[start..end];
    let (mut v_lc, mut v_val) = bits_to_lc::<CS>(group);
    if group.len() < 6 {
      let shift = Scalar::from(1u64 << (6 - group.len()));
      v_lc = LinearCombination::zero() + (shift, &v_lc);
      v_val = v_val.map(|v| v * shift);
    }
    let hot = v_val.map(|v| {
      let le = ff::PrimeField::to_repr(&v);
      le.as_ref()[0] as usize
    });
    let sel = alloc_one_hot(cs.namespace(|| format!("char {j} sel")), 64, hot.unwrap_or(0))?;
    let mut index_lc = LinearCombination::zero();
    let mut char_lc = LinearCombination::zero();
    for (k, b) in sel.iter().enumerate() {
      index_lc = index_lc + (Scalar::from(k as u64), b.get_variable());
      char_lc = char_lc + (Scalar::from(b64url_char(k as u8) as u64), b.get_variable());
    }
    cs.enforce(|| format!("char {j} index"), |_| index_lc, |lc| lc + CS::one(), |_| v_lc);
    out.push(char_lc);
  }
  Ok(out)
}
