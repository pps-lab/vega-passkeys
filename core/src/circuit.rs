//! `PopCircuit`: the passkey-membership statement.
//!
//! Private: P-256 public key (qx, qy), signature (r, s), the signed message
//! `authenticatorData || SHA-256(clientDataJSON)`, clientDataJSON, the challenge's
//! offset inside it, and a depth-20 Merkle path.
//! Public: `[challenge_hi, challenge_lo, merkle_root]` (challenge as two 128-bit halves).
//!
//! Checks, mirroring `circuits/src/main.nr`:
//! 1. base64url(challenge) appears in clientDataJSON at the offset, inside its real length;
//! 2. the signed message ends with SHA-256(clientDataJSON) (same length wires as the hash);
//! 3. ECDSA-P256 verifies (r, s) over SHA-256(message) under (qx, qy);
//! 4. Poseidon commitment(qx, qy) is a leaf of the tree with the public root.

use crate::gadgets::{
  alloc_byte_bits, alloc_one_hot, b64url_encode_challenge, bits_be_to_bignat, bits_to_lc, byte_lc, enforce_selected_eq,
  CHALLENGE_B64_LEN,
};
use crate::poseidon::{self, hash2_gadget, TAG_COMMITMENT, TAG_NODE};
use crate::vendor::ecdsa::verify_ecdsa_p256_with_digest;
use crate::vendor::p256_ecc::p256_generator;
use crate::vendor::sha256_var::{sha256_var_sized_with_selector, terminal_block_for_len};
use crate::{Engine_, Scalar};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::Field;
use num_bigint::BigInt;
use vega_prover::traits::circuit::VegaCircuit;

pub const TREE_DEPTH: usize = 20;
/// authenticatorData is at least rpIdHash (32) + flags (1) + signCount (4).
pub const MIN_AUTH_DATA: usize = 37;
pub const MAX_AUTH_DATA: usize = 128;
pub const MAX_MSG: usize = MAX_AUTH_DATA + 32;
pub const MSG_BLOCKS: usize = terminal_block_for_len(MAX_MSG);
pub const MAX_CDJ: usize = 256;
pub const CDJ_BLOCKS: usize = terminal_block_for_len(MAX_CDJ);

/// All witness data for one proof. Built by `api::PopInputs::witness`.
#[derive(Clone, Debug)]
pub struct PopWitness {
  pub challenge: [u8; 32],
  /// `authenticatorData || SHA-256(clientDataJSON)`, unpadded.
  pub msg: Vec<u8>,
  /// clientDataJSON, unpadded.
  pub cdj: Vec<u8>,
  pub challenge_offset: usize,
  pub qx: Scalar,
  pub qy: Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
  pub path: [Scalar; TREE_DEPTH],
  /// `true` when the current node is the right child at that level.
  pub indices: [bool; TREE_DEPTH],
}

impl PopWitness {
  /// A structurally valid but unsatisfying witness, used only to derive the R1CS shape
  /// at setup. The shape does not depend on witness values.
  pub fn dummy() -> Self {
    // Q = G keeps witness computation (point arithmetic, inversions) panic-free.
    let (gx, gy) = p256_generator::<Scalar>();
    PopWitness {
      challenge: [0; 32],
      msg: vec![0; MIN_AUTH_DATA + 32],
      cdj: vec![b'a'; 64],
      challenge_offset: 0,
      qx: gx,
      qy: gy,
      r: BigInt::from(1),
      s: BigInt::from(1),
      s_inv: BigInt::from(1),
      path: [Scalar::ZERO; TREE_DEPTH],
      indices: [false; TREE_DEPTH],
    }
  }

  /// The two 128-bit halves of the challenge, big-endian.
  pub fn challenge_halves(challenge: &[u8; 32]) -> [Scalar; 2] {
    let half = |b: &[u8]| {
      let mut be = [0u8; 32];
      be[16..].copy_from_slice(b);
      poseidon::scalar_from_be_bytes(&be).expect("128-bit value fits")
    };
    [half(&challenge[..16]), half(&challenge[16..])]
  }

  /// The Merkle root this witness's path leads to.
  pub fn root(&self) -> Scalar {
    let mut cur = poseidon::commitment(self.qx, self.qy);
    for (sib, &right) in self.path.iter().zip(&self.indices) {
      cur = if right { poseidon::node(*sib, cur) } else { poseidon::node(cur, *sib) };
    }
    cur
  }

  pub fn public_values(&self) -> Vec<Scalar> {
    let [hi, lo] = Self::challenge_halves(&self.challenge);
    vec![hi, lo, self.root()]
  }
}

#[derive(Clone, Debug)]
pub struct PopCircuit {
  pub w: PopWitness,
}

fn pad(bytes: &[u8], len: usize) -> Vec<u8> {
  let mut v = bytes.to_vec();
  v.resize(len, 0);
  v
}

fn inputize_lc<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  lc: LinearCombination<Scalar>,
  val: Option<Scalar>,
) -> Result<(), SynthesisError> {
  let num = AllocatedNum::alloc(cs.namespace(|| "num"), || val.ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(|| "num == lc", |_| lc, |l| l + CS::one(), |l| l + num.get_variable());
  num.inputize(cs.namespace(|| "input"))
}

impl PopCircuit {
  /// All constraints. Public inputs are allocated in the order of `public_values`.
  pub fn synthesize_all<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let w = &self.w;
    assert!(w.msg.len() >= MIN_AUTH_DATA + 32 && w.msg.len() <= MAX_MSG, "message length out of range");
    assert!(w.cdj.len() <= MAX_CDJ, "clientDataJSON too long");
    assert!(w.challenge_offset + CHALLENGE_B64_LEN <= MAX_CDJ, "challenge offset out of range");

    // Public challenge.
    let chal_bits = alloc_byte_bits(cs.namespace(|| "challenge"), &w.challenge)?;
    let (hi_lc, hi_val) = bits_to_lc::<CS>(&chal_bits[..128]);
    let (lo_lc, lo_val) = bits_to_lc::<CS>(&chal_bits[128..]);
    inputize_lc(cs.namespace(|| "challenge hi"), hi_lc, hi_val)?;
    inputize_lc(cs.namespace(|| "challenge lo"), lo_lc, lo_val)?;

    // 1. base64url(challenge) at challenge_offset in clientDataJSON.
    let cdj_bits = alloc_byte_bits(cs.namespace(|| "cdj"), &pad(&w.cdj, MAX_CDJ))?;
    let (cdj_hash, cdj_active, _) =
      sha256_var_sized_with_selector(cs.namespace(|| "sha256(cdj)"), &cdj_bits, w.cdj.len(), MAX_CDJ, CDJ_BLOCKS)?;
    let cdj_bytes: Vec<_> = (0..MAX_CDJ).map(|i| byte_lc::<CS>(&cdj_bits, i)).collect();
    let chars = b64url_encode_challenge(cs.namespace(|| "b64url"), &chal_bits)?;
    let n_offsets = MAX_CDJ - CHALLENGE_B64_LEN + 1;
    let off_sel: Vec<Boolean> = alloc_one_hot(cs.namespace(|| "offset"), n_offsets, w.challenge_offset)?
      .into_iter()
      .map(Boolean::from)
      .collect();
    for (j, ch) in chars.iter().enumerate() {
      enforce_selected_eq(
        cs.namespace(|| format!("challenge char {j}")),
        &off_sel,
        &cdj_bytes[j..j + n_offsets],
        ch,
      )?;
    }
    // The last challenge character must lie inside the real clientDataJSON; bytes past its
    // length are unconstrained padding that the hash never reads.
    let active: Vec<_> = cdj_active[CHALLENGE_B64_LEN - 1..]
      .iter()
      .map(|b| (b.lc(CS::one(), Scalar::ONE), b.get_value().map(|v| if v { Scalar::ONE } else { Scalar::ZERO })))
      .collect();
    enforce_selected_eq(
      cs.namespace(|| "challenge within cdj"),
      &off_sel,
      &active,
      &(LinearCombination::zero() + CS::one()),
    )?;

    // 2. message = authData || SHA-256(cdj): the hash sits in the last 32 bytes of the
    // hashed length, selected by the same one-hot length wires the SHA gadget uses.
    let msg_bits = alloc_byte_bits(cs.namespace(|| "msg"), &pad(&w.msg, MAX_MSG))?;
    let (z_bits, _msg_active, len_sel) =
      sha256_var_sized_with_selector(cs.namespace(|| "sha256(msg)"), &msg_bits, w.msg.len(), MAX_MSG, MSG_BLOCKS)?;
    let too_short = len_sel[..MIN_AUTH_DATA + 32]
      .iter()
      .fold(LinearCombination::zero(), |lc, b| lc + &b.lc(CS::one(), Scalar::ONE));
    cs.enforce(|| "msg length >= 69", |_| too_short, |lc| lc + CS::one(), |lc| lc);
    let msg_bytes: Vec<_> = (0..MAX_MSG).map(|i| byte_lc::<CS>(&msg_bits, i)).collect();
    let tail_sel = &len_sel[MIN_AUTH_DATA + 32..];
    for j in 0..32 {
      let (h_lc, _) = byte_lc::<CS>(&cdj_hash, j);
      // len n selects msg byte n - 32 + j.
      let start = MIN_AUTH_DATA + j;
      enforce_selected_eq(
        cs.namespace(|| format!("cdj hash byte {j}")),
        tail_sel,
        &msg_bytes[start..start + tail_sel.len()],
        &h_lc,
      )?;
    }

    // 3. ECDSA-P256 over SHA-256(message).
    let qx = AllocatedNum::alloc(cs.namespace(|| "qx"), || Ok(w.qx))?;
    let qy = AllocatedNum::alloc(cs.namespace(|| "qy"), || Ok(w.qy))?;
    let z = bits_be_to_bignat::<CS>(&z_bits)?;
    verify_ecdsa_p256_with_digest(cs.namespace(|| "ecdsa"), &qx, &qy, &w.r, &w.s, &w.s_inv, &z)?;

    // 4. Commitment and Merkle membership.
    let mut cur = hash2_gadget(cs.namespace(|| "commitment"), TAG_COMMITMENT, &qx, &qy)?;
    for level in 0..TREE_DEPTH {
      let mut cs = cs.namespace(|| format!("merkle {level}"));
      let sib = AllocatedNum::alloc(cs.namespace(|| "sibling"), || Ok(w.path[level]))?;
      let right = AllocatedBit::alloc(cs.namespace(|| "is right"), Some(w.indices[level]))?;
      // left = cur + right * (sib - cur); right_node = cur + sib - left
      let left_val = if w.indices[level] { sib.get_value() } else { cur.get_value() };
      let left = AllocatedNum::alloc(cs.namespace(|| "left"), || left_val.ok_or(SynthesisError::AssignmentMissing))?;
      cs.enforce(
        || "swap",
        |lc| lc + right.get_variable(),
        |lc| lc + sib.get_variable() - cur.get_variable(),
        |lc| lc + left.get_variable() - cur.get_variable(),
      );
      let right_val = cur.get_value().zip(sib.get_value()).zip(left.get_value()).map(|((c, s), l)| c + s - l);
      let right_node = AllocatedNum::alloc(cs.namespace(|| "right"), || right_val.ok_or(SynthesisError::AssignmentMissing))?;
      cs.enforce(
        || "right node",
        |lc| lc + cur.get_variable() + sib.get_variable() - left.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + right_node.get_variable(),
      );
      cur = hash2_gadget(cs.namespace(|| "node"), TAG_NODE, &left, &right_node)?;
    }
    cur.inputize(cs.namespace(|| "merkle root"))?;
    Ok(())
  }
}

impl VegaCircuit<Engine_> for PopCircuit {
  fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
    Ok(self.w.public_values())
  }

  fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<Scalar>],
  ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<Scalar>],
    _: &[AllocatedNum<Scalar>],
    _: Option<&[Scalar]>,
  ) -> Result<(), SynthesisError> {
    self.synthesize_all(cs)
  }
}
