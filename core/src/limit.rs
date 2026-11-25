//! `LimitCircuit`: the passkey-membership statement, at most `limit` times per epoch.
//!
//! An extension of `PopCircuit`, with its own keys: a deployment that doesn't limit anything
//! keeps proving with `PopCircuit` and never derives these.
//!
//! The holder has, next to the P-256 key, a random `secret` that only the device knows. Both are
//! committed in one leaf of a second tree (the limit tree) when the device enrolls:
//!
//!   leaf  = H_leaf( commitment(qx, qy), H_secret(secret) )
//!   token = H_token( H_epoch(secret, epoch), counter )        counter < limit
//!
//! The token is a PRF output: for one epoch a device has exactly `limit` of them, and without the
//! secret they look random and unrelated, across counters and across epochs. The verifier picks
//! `epoch` and `limit`, and refuses a token it has already seen in that epoch.
//!
//! The PRF is keyed with the secret and not with the public key, because public keys are public:
//! whoever has the key directory could try them all against a token.
//!
//! Private: everything `PopCircuit` keeps private, with the path in the limit tree, plus `secret`
//! and `counter`. Public: `[challenge_hi, challenge_lo, limit_root, epoch, limit, token]`.
//!
//! Checks: parts 1–3 of `PopCircuit` (challenge, signed message, ECDSA), then
//! 4. the leaf above is in the tree with the public root;
//! 5. `token` is the PRF at (`epoch`, `counter`) under that same secret;
//! 6. `0 <= counter < limit`, both at most `2^LIMIT_BITS`.

use crate::circuit::{synthesize_membership, synthesize_signature, vega_circuit, PopWitness};
use crate::poseidon::{self, hash2_gadget, TAG_COMMITMENT, TAG_EPOCH, TAG_LIMIT_LEAF, TAG_SECRET, TAG_TOKEN};
use crate::{Engine_, Scalar};
use bellpepper_core::{boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use ff::Field;
use vega_prover::traits::circuit::VegaCircuit;

/// Counters are `LIMIT_BITS` bits wide, so a limit is at most `MAX_LIMIT`.
pub const LIMIT_BITS: usize = 16;
pub const MAX_LIMIT: u32 = 1 << LIMIT_BITS;

/// All witness data for one limited proof. Built by `api::LimitInputs::witness`.
#[derive(Clone, Debug)]
pub struct LimitWitness {
  /// The assertion, with the Merkle path in the limit tree.
  pub pop: PopWitness,
  pub secret: Scalar,
  pub epoch: Scalar,
  pub counter: u32,
  pub limit: u32,
}

impl LimitWitness {
  /// Shape-only witness for setup; see `PopWitness::dummy`.
  pub fn dummy(depth: usize) -> Self {
    LimitWitness { pop: PopWitness::dummy(depth), secret: Scalar::ZERO, epoch: Scalar::ZERO, counter: 0, limit: 1 }
  }

  /// The leaf this witness's key and secret make.
  pub fn leaf(&self) -> Scalar {
    poseidon::limit_leaf(poseidon::commitment(self.pop.qx, self.pop.qy), poseidon::secret_commitment(self.secret))
  }

  /// The limit tree's root this witness's path leads to.
  pub fn root(&self) -> Scalar {
    self.pop.root_from(self.leaf())
  }

  pub fn token(&self) -> Scalar {
    poseidon::limit_token(self.secret, self.epoch, self.counter)
  }

  pub fn public_values(&self) -> Vec<Scalar> {
    let [hi, lo] = PopWitness::challenge_halves(&self.pop.challenge);
    vec![hi, lo, self.root(), self.epoch, Scalar::from(self.limit as u64), self.token()]
  }
}

#[derive(Clone, Debug)]
pub struct LimitCircuit {
  pub w: LimitWitness,
}

/// `value` as `LIMIT_BITS` boolean wires; returns their sum. A value that doesn't fit yields an
/// unsatisfied constraint where the sum is used.
fn alloc_limit_bits<CS: ConstraintSystem<Scalar>>(mut cs: CS, value: u64) -> Result<LinearCombination<Scalar>, SynthesisError> {
  let mut lc = LinearCombination::zero();
  for i in 0..LIMIT_BITS {
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some((value >> i) & 1 == 1))?;
    lc = lc + (Scalar::from(1u64 << i), bit.get_variable());
  }
  Ok(lc)
}

impl LimitCircuit {
  /// All constraints. Public inputs are allocated in the order of `public_values`.
  pub fn synthesize_all<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    let w = &self.w;
    let (qx, qy) = synthesize_signature(cs, &w.pop)?;

    // 4. The leaf commits to the key and the secret, and is in the limit tree.
    let secret = AllocatedNum::alloc(cs.namespace(|| "secret"), || Ok(w.secret))?;
    let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Scalar::ZERO))?;
    cs.enforce(|| "zero == 0", |lc| lc + zero.get_variable(), |lc| lc + CS::one(), |lc| lc);
    let key = hash2_gadget(cs.namespace(|| "commitment"), TAG_COMMITMENT, &qx, &qy)?;
    let secret_commitment = hash2_gadget(cs.namespace(|| "secret commitment"), TAG_SECRET, &secret, &zero)?;
    let leaf = hash2_gadget(cs.namespace(|| "limit leaf"), TAG_LIMIT_LEAF, &key, &secret_commitment)?;
    let root = synthesize_membership(cs, leaf, &w.pop.path, &w.pop.indices)?;
    root.inputize(cs.namespace(|| "limit root"))?;

    let epoch = AllocatedNum::alloc(cs.namespace(|| "epoch"), || Ok(w.epoch))?;
    epoch.inputize(cs.namespace(|| "epoch input"))?;
    let limit = AllocatedNum::alloc(cs.namespace(|| "limit"), || Ok(Scalar::from(w.limit as u64)))?;
    limit.inputize(cs.namespace(|| "limit input"))?;

    // 6. counter and limit - 1 - counter are both LIMIT_BITS wide, so 0 <= counter < limit as
    // integers: neither side can wrap around the field.
    let counter = AllocatedNum::alloc(cs.namespace(|| "counter"), || Ok(Scalar::from(w.counter as u64)))?;
    let counter_bits = alloc_limit_bits(cs.namespace(|| "counter bits"), w.counter as u64)?;
    cs.enforce(|| "counter range", |_| counter_bits, |lc| lc + CS::one(), |lc| lc + counter.get_variable());
    let rest = (w.limit as u64).wrapping_sub(1).wrapping_sub(w.counter as u64);
    let rest_bits = alloc_limit_bits(cs.namespace(|| "rest bits"), rest)?;
    cs.enforce(
      || "counter < limit",
      |_| rest_bits,
      |lc| lc + CS::one(),
      |lc| lc + limit.get_variable() - CS::one() - counter.get_variable(),
    );

    // 5. The token, under the secret in the leaf.
    let epoch_key = hash2_gadget(cs.namespace(|| "epoch key"), TAG_EPOCH, &secret, &epoch)?;
    let token = hash2_gadget(cs.namespace(|| "token"), TAG_TOKEN, &epoch_key, &counter)?;
    token.inputize(cs.namespace(|| "token input"))
  }
}

vega_circuit!(LimitCircuit, |c: &LimitCircuit| c.w.public_values());
