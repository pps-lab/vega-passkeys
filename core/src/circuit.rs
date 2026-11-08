//! `PopCircuit`: the passkey-membership statement.
//!
//! Private: P-256 public key (qx, qy), signature (r, s), the signed message
//! `authenticatorData || SHA-256(clientDataJSON)`, clientDataJSON, and a Merkle path. The
//! tree depth is the path length, fixed at setup (`api::setup_with_depth`); keys for one
//! depth do not accept proofs for another.
//! Public: `[challenge_hi, challenge_lo, merkle_root]` (challenge as two 128-bit halves).
//!
//! Checks, mirroring `circuits/src/main.nr`:
//! 1. clientDataJSON is `{"type":"webauthn.get","challenge":"` ‖ base64url(challenge) ‖ `"`
//!    ‖ …, i.e. the WebAuthn client-data serialization with the challenge as the value of
//!    the `challenge` member (the spec fixes the member order, so the prefix is a constant),
//!    and the closing quote lies inside its real length;
//! 2. the signed message ends with SHA-256(clientDataJSON) (same length wires as the hash),
//!    and its authenticatorData has the UP and UV flags set;
//! 3. ECDSA-P256 verifies (r, s) over SHA-256(message) under (qx, qy);
//! 4. Poseidon commitment(qx, qy) is a leaf of the tree with the public root.
//!
//! The same statement also comes split in two, like the Noir signature + accumulator pair,
//! joined by a blinded link `L = H_link(commitment(qx, qy), blind)`:
//! - `SigCircuit` proves 1–3 and publishes `[challenge_hi, challenge_lo, L]`;
//! - `AccCircuit` proves that the leaf inside `L` is in the tree: `[L, merkle_root]`.
//! A verifier accepts the pair when both verify and their `L` values are equal. The split
//! lets the signature proof start before the Merkle path is known.

use crate::gadgets::{
  alloc_byte_bits, b64url_encode_challenge, bits_be_to_bignat, bits_to_lc, byte_lc, enforce_selected_eq, CHALLENGE_B64_LEN,
};
use crate::poseidon::{self, hash2_gadget, TAG_COMMITMENT, TAG_LINK, TAG_NODE};
use crate::vendor::ecdsa::verify_ecdsa_p256_with_digest;
use crate::vendor::p256_ecc::p256_generator;
use crate::vendor::sha256_var::{sha256_var_sized_with_selector, terminal_block_for_len};
use crate::{Engine_, Scalar};
use bellpepper_core::{
  boolean::AllocatedBit,
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::Field;
use num_bigint::BigInt;
use vega_prover::traits::circuit::VegaCircuit;

/// Depth of the proof-of-person deployment's tree; the zk-passkeys benchmarks sweep 20..=28.
pub const TREE_DEPTH: usize = 20;
/// authenticatorData is at least rpIdHash (32) + flags (1) + signCount (4).
pub const MIN_AUTH_DATA: usize = 37;
pub const MAX_AUTH_DATA: usize = 128;
pub const MAX_MSG: usize = MAX_AUTH_DATA + 32;
pub const MSG_BLOCKS: usize = terminal_block_for_len(MAX_MSG);
/// Browsers append `origin`, `crossOrigin`, `topOrigin` (when embedded cross-origin, e.g. the
/// widget iframe on a customer page) and Chrome's ~110-byte `other_keys_can_be_added_here` note,
/// so real clientDataJSON runs to ~300 bytes. 375 is the most that fits in 6 SHA-256 blocks.
pub const MAX_CDJ: usize = 375;
pub const CDJ_BLOCKS: usize = terminal_block_for_len(MAX_CDJ);
const _: () = assert!(CDJ_BLOCKS == 6 && terminal_block_for_len(MAX_CDJ + 1) == 7);
/// How a client serializes clientDataJSON for an assertion (WebAuthn §5.8.1.1): `type` first,
/// then `challenge`, so base64url(challenge) always starts at byte `CHALLENGE_OFFSET`.
pub const CDJ_PREFIX: &[u8] = b"{\"type\":\"webauthn.get\",\"challenge\":\"";
pub const CHALLENGE_OFFSET: usize = CDJ_PREFIX.len();
/// Shortest clientDataJSON the circuit accepts: prefix, challenge, closing quote.
pub const MIN_CDJ: usize = CHALLENGE_OFFSET + CHALLENGE_B64_LEN + 1;
/// authenticatorData flags byte (`authData[32]`), MSB-first bit positions.
pub const FLAGS_BYTE: usize = 32;
/// UP (0x01): the user was present.
pub const FLAG_UP_BIT: usize = 7;
/// UV (0x04): the user was verified.
pub const FLAG_UV_BIT: usize = 5;

/// All witness data for one proof. Built by `api::PopInputs::witness`.
#[derive(Clone, Debug)]
pub struct PopWitness {
  pub challenge: [u8; 32],
  /// `authenticatorData || SHA-256(clientDataJSON)`, unpadded.
  pub msg: Vec<u8>,
  /// clientDataJSON, unpadded.
  pub cdj: Vec<u8>,
  pub qx: Scalar,
  pub qy: Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
  pub path: Vec<Scalar>,
  /// `true` when the current node is the right child at that level.
  pub indices: Vec<bool>,
}

impl PopWitness {
  /// A structurally valid but unsatisfying witness, used only to derive the R1CS shape
  /// at setup. The shape depends only on `depth`, not on witness values.
  pub fn dummy(depth: usize) -> Self {
    // Q = G keeps witness computation (point arithmetic, inversions) panic-free.
    let (gx, gy) = p256_generator::<Scalar>();
    let mut cdj = CDJ_PREFIX.to_vec();
    cdj.extend([b'A'; CHALLENGE_B64_LEN]);
    cdj.extend(b"\"}");
    PopWitness {
      challenge: [0; 32],
      msg: vec![0; MIN_AUTH_DATA + 32],
      cdj,
      qx: gx,
      qy: gy,
      r: BigInt::from(1),
      s: BigInt::from(1),
      s_inv: BigInt::from(1),
      path: vec![Scalar::ZERO; depth],
      indices: vec![false; depth],
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

/// Statement parts 1–3 (challenge, message, ECDSA); returns the key `(qx, qy)`. The
/// challenge halves are the first two public inputs.
fn synthesize_signature<CS: ConstraintSystem<Scalar>>(
  cs: &mut CS,
  w: &PopWitness,
) -> Result<(AllocatedNum<Scalar>, AllocatedNum<Scalar>), SynthesisError> {
  assert!(w.msg.len() >= MIN_AUTH_DATA + 32 && w.msg.len() <= MAX_MSG, "message length out of range");
  assert!(w.cdj.len() <= MAX_CDJ, "clientDataJSON too long");

  // Public challenge.
  let chal_bits = alloc_byte_bits(cs.namespace(|| "challenge"), &w.challenge)?;
  let (hi_lc, hi_val) = bits_to_lc::<CS>(&chal_bits[..128]);
  let (lo_lc, lo_val) = bits_to_lc::<CS>(&chal_bits[128..]);
  inputize_lc(cs.namespace(|| "challenge hi"), hi_lc, hi_val)?;
  inputize_lc(cs.namespace(|| "challenge lo"), lo_lc, lo_val)?;

  // 1. clientDataJSON = CDJ_PREFIX ‖ base64url(challenge) ‖ '"' ‖ …. Every byte position is
  // fixed, so each check is one constraint on the byte's linear combination.
  let cdj_bits = alloc_byte_bits(cs.namespace(|| "cdj"), &pad(&w.cdj, MAX_CDJ))?;
  let (cdj_hash, cdj_active, _) =
    sha256_var_sized_with_selector(cs.namespace(|| "sha256(cdj)"), &cdj_bits, w.cdj.len(), MAX_CDJ, CDJ_BLOCKS)?;
  let enforce_byte = |cs: &mut CS, name: String, i: usize, target: LinearCombination<Scalar>| {
    let (byte, _) = byte_lc::<CS>(&cdj_bits, i);
    cs.enforce(|| name, |_| byte, |lc| lc + CS::one(), |_| target);
  };
  let constant = |c: u8| LinearCombination::zero() + (Scalar::from(c as u64), CS::one());
  for (i, &c) in CDJ_PREFIX.iter().enumerate() {
    enforce_byte(cs, format!("cdj prefix {i}"), i, constant(c));
  }
  let chars = b64url_encode_challenge(cs.namespace(|| "b64url"), &chal_bits)?;
  for (j, ch) in chars.into_iter().enumerate() {
    enforce_byte(cs, format!("challenge char {j}"), CHALLENGE_OFFSET + j, ch);
  }
  // The challenge member's value is exactly the 43 characters: a quote follows them.
  enforce_byte(cs, "challenge closing quote".into(), MIN_CDJ - 1, constant(b'"'));
  // That quote must lie inside the real clientDataJSON; bytes past its length are
  // unconstrained padding that the hash never reads.
  cs.enforce(
    || "challenge within cdj",
    |_| cdj_active[MIN_CDJ - 1].lc(CS::one(), Scalar::ONE),
    |lc| lc + CS::one(),
    |lc| lc + CS::one(),
  );

  // 2. message = authData || SHA-256(cdj): the hash sits in the last 32 bytes of the
  // hashed length, selected by the same one-hot length wires the SHA gadget uses.
  let msg_bits = alloc_byte_bits(cs.namespace(|| "msg"), &pad(&w.msg, MAX_MSG))?;
  // authData's flags byte is msg[32]; require UP (0x01) and UV (0x04). These wires are
  // hashed and signed below, so the flags are bound to the signature.
  for (name, bit) in [("flags.UP", FLAG_UP_BIT), ("flags.UV", FLAG_UV_BIT)] {
    let flag = &msg_bits[FLAGS_BYTE * 8 + bit];
    cs.enforce(|| name, |_| flag.lc(CS::one(), Scalar::ONE), |lc| lc + CS::one(), |lc| lc + CS::one());
  }
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

  Ok((qx, qy))
}

/// Part 4's Merkle path: walks from `leaf` up the given path and returns the root.
fn synthesize_membership<CS: ConstraintSystem<Scalar>>(
  cs: &mut CS,
  leaf: AllocatedNum<Scalar>,
  path: &[Scalar],
  indices: &[bool],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  assert_eq!(path.len(), indices.len(), "Merkle path and indices differ in length");
  let mut cur = leaf;
  for level in 0..path.len() {
    let mut cs = cs.namespace(|| format!("merkle {level}"));
    let sib = AllocatedNum::alloc(cs.namespace(|| "sibling"), || Ok(path[level]))?;
    let right = AllocatedBit::alloc(cs.namespace(|| "is right"), Some(indices[level]))?;
    // left = cur + right * (sib - cur); right_node = cur + sib - left
    let left_val = if indices[level] { sib.get_value() } else { cur.get_value() };
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
  Ok(cur)
}

impl PopCircuit {
  /// All constraints. Public inputs are allocated in the order of `public_values`.
  pub fn synthesize_all<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let (qx, qy) = synthesize_signature(cs, &self.w)?;
    // 4. Commitment and Merkle membership.
    let leaf = hash2_gadget(cs.namespace(|| "commitment"), TAG_COMMITMENT, &qx, &qy)?;
    let root = synthesize_membership(cs, leaf, &self.w.path, &self.w.indices)?;
    root.inputize(cs.namespace(|| "merkle root"))?;
    Ok(())
  }
}

/// The signature half of the split statement: parts 1–3 plus the blinded link to the key's
/// leaf. `w.path` is ignored. Public: `[challenge_hi, challenge_lo, link]`.
#[derive(Clone, Debug)]
pub struct SigCircuit {
  pub w: PopWitness,
  pub blind: Scalar,
}

impl SigCircuit {
  /// Shape-only instance for setup.
  pub fn dummy() -> Self {
    SigCircuit { w: PopWitness::dummy(0), blind: Scalar::ZERO }
  }

  pub fn public_values(&self) -> Vec<Scalar> {
    let [hi, lo] = PopWitness::challenge_halves(&self.w.challenge);
    vec![hi, lo, poseidon::link(poseidon::commitment(self.w.qx, self.w.qy), self.blind)]
  }

  pub fn synthesize_all<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let (qx, qy) = synthesize_signature(cs, &self.w)?;
    let leaf = hash2_gadget(cs.namespace(|| "commitment"), TAG_COMMITMENT, &qx, &qy)?;
    let blind = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(self.blind))?;
    let link = hash2_gadget(cs.namespace(|| "link"), TAG_LINK, &leaf, &blind)?;
    link.inputize(cs.namespace(|| "link input"))
  }
}

/// The accumulator half: the leaf inside the link is in the tree.
/// Public: `[link, merkle_root]`.
#[derive(Clone, Debug)]
pub struct AccCircuit {
  /// `commitment(qx, qy)`, the key's leaf.
  pub leaf: Scalar,
  pub blind: Scalar,
  pub path: Vec<Scalar>,
  pub indices: Vec<bool>,
}

impl AccCircuit {
  /// Shape-only instance for setup at a depth.
  pub fn dummy(depth: usize) -> Self {
    AccCircuit { leaf: Scalar::ZERO, blind: Scalar::ZERO, path: vec![Scalar::ZERO; depth], indices: vec![false; depth] }
  }

  pub fn root(&self) -> Scalar {
    let mut cur = self.leaf;
    for (sib, &right) in self.path.iter().zip(&self.indices) {
      cur = if right { poseidon::node(*sib, cur) } else { poseidon::node(cur, *sib) };
    }
    cur
  }

  pub fn public_values(&self) -> Vec<Scalar> {
    vec![poseidon::link(self.leaf, self.blind), self.root()]
  }

  pub fn synthesize_all<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;
    let blind = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(self.blind))?;
    let link = hash2_gadget(cs.namespace(|| "link"), TAG_LINK, &leaf, &blind)?;
    link.inputize(cs.namespace(|| "link input"))?;
    let root = synthesize_membership(cs, leaf, &self.path, &self.indices)?;
    root.inputize(cs.namespace(|| "merkle root"))
  }
}

/// Splits a combined witness into the two halves, linked by `blind`.
pub fn split(w: PopWitness, blind: Scalar) -> (SigCircuit, AccCircuit) {
  let acc = AccCircuit {
    leaf: poseidon::commitment(w.qx, w.qy),
    blind,
    path: w.path.clone(),
    indices: w.indices.clone(),
  };
  (SigCircuit { w, blind }, acc)
}

/// The Vega boilerplate: no shared/precommitted witness, no verifier challenges.
macro_rules! vega_circuit {
  ($ty:ty, $public:expr) => {
    impl VegaCircuit<Engine_> for $ty {
      fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok($public(self))
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
  };
}

vega_circuit!(PopCircuit, |c: &PopCircuit| c.w.public_values());
vega_circuit!(SigCircuit, |c: &SigCircuit| c.public_values());
vega_circuit!(AccCircuit, |c: &AccCircuit| c.public_values());
