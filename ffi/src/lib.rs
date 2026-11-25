//! UniFFI surface for native (iOS) proving. Same statement and proof format as the browser
//! prover, so the server verifies the result with `proofType: "zk-webauthn-v2"`.
//!
//! Swift usage:
//! ```swift
//! let prover = try VegaProver()               // transparent setup; slow, do it once in the background
//! let out = try prover.prove(inputs: inputs)  // ProofOutput { proof, publicValues, proveMs }
//! ```

use pop_vega::api::{self, LimitInputs, PopInputs, ProverKey};
use pop_vega::{circuit::TREE_DEPTH, poseidon};
use std::sync::Arc;
use std::time::Instant;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VegaError {
  /// The assertion, key or Merkle path is malformed or out of the circuit's bounds.
  #[error("invalid input: {msg}")]
  InvalidInput { msg: String },
  /// Setup or proving failed inside the proof system.
  #[error("prover error: {msg}")]
  Prover { msg: String },
}

impl From<api::PopError> for VegaError {
  fn from(e: api::PopError) -> Self {
    match e {
      api::PopError::Input(msg) => VegaError::InvalidInput { msg },
      other => VegaError::Prover { msg: other.to_string() },
    }
  }
}

/// Prover inputs. Byte fields are base64url (no padding); Merkle path elements are the hex
/// strings `/v1/pubkey` returns.
#[derive(uniffi::Record)]
pub struct ProverInputs {
  /// The signed authenticatorData (37..=128 bytes).
  pub authenticator_data: String,
  /// The signed clientData JSON (at most 375 bytes); must start with
  /// `{"type":"webauthn.get","challenge":"<challenge>"` (the WebAuthn client-data prefix).
  pub client_data_json: String,
  /// DER signature (as returned by `SecKeyCreateSignature`) or raw 64-byte r||s.
  pub signature: String,
  /// `x` from `/v1/pubkey`.
  pub pub_key_x: String,
  /// `y` from `/v1/pubkey`.
  pub pub_key_y: String,
  /// The 32-byte challenge from `/verify/start`, base64url.
  pub challenge: String,
  /// `merkle.pathElements` from `/v1/pubkey` (20 entries).
  pub path_elements: Vec<String>,
  /// `merkle.pathIndices` from `/v1/pubkey` (20 entries, 0 or 1).
  pub path_indices: Vec<u32>,
}

impl ProverInputs {
  fn into_pop(self) -> Result<PopInputs, VegaError> {
    Ok(PopInputs {
      authenticator_data: self.authenticator_data,
      client_data_json: self.client_data_json,
      signature: self.signature,
      pub_key_x: self.pub_key_x,
      pub_key_y: self.pub_key_y,
      challenge: self.challenge,
      path_elements: self.path_elements,
      path_indices: self
        .path_indices
        .into_iter()
        .map(|i| u8::try_from(i).map_err(|_| VegaError::InvalidInput { msg: "path index must be 0 or 1".into() }))
        .collect::<Result<_, _>>()?,
    })
  }
}

/// What a limited proof takes on top of `ProverInputs` (whose path is the one in the limit tree).
#[derive(uniffi::Record)]
pub struct LimitParams {
  /// The device's secret (`limit_secret`), hex.
  pub secret: String,
  /// The epoch's label as the server names it; its field element is derived here.
  pub epoch_label: String,
  /// Which of the epoch's uses this is, from 0.
  pub counter: u32,
  /// How many uses the server allows per epoch.
  pub limit: u32,
}

#[derive(uniffi::Record)]
pub struct ProofOutput {
  /// Proof bytes; send base64-encoded as `proof`.
  pub proof: Vec<u8>,
  /// `[challenge_hi, challenge_lo, merkle_root]` as hex; informational (the server recomputes them).
  pub public_values: Vec<String>,
  /// Wall-clock proving time, for `clientProofTimeMs`.
  pub prove_ms: u64,
}

/// Holds the prover key. Construct once (setup derives the key from the circuit; it takes on
/// the order of a second and a few hundred MB) and reuse for every proof. Thread-safe.
#[derive(uniffi::Object)]
pub struct VegaProver {
  pk: ProverKey,
  setup_ms: u64,
}

#[uniffi::export]
impl VegaProver {
  #[uniffi::constructor]
  pub fn new() -> Result<Arc<Self>, VegaError> {
    let t = Instant::now();
    let (pk, _vk) = api::setup()?;
    Ok(Arc::new(VegaProver { pk, setup_ms: t.elapsed().as_millis() as u64 }))
  }

  /// How long setup took, in milliseconds.
  pub fn setup_ms(&self) -> u64 {
    self.setup_ms
  }

  /// Proves a signed assertion. CPU-bound (uses all cores); call off the main thread.
  pub fn prove(&self, inputs: ProverInputs) -> Result<ProofOutput, VegaError> {
    let inputs = inputs.into_pop()?;
    let witness = inputs.witness()?;
    let t = Instant::now();
    let out = api::prove(&self.pk, witness)?;
    Ok(ProofOutput { proof: out.proof, public_values: out.public_values, prove_ms: t.elapsed().as_millis() as u64 })
  }
}

/// `VegaProver` for the limit circuit: its own key, so make one only for a session with a limit.
#[derive(uniffi::Object)]
pub struct VegaLimitProver {
  pk: ProverKey,
  setup_ms: u64,
}

#[uniffi::export]
impl VegaLimitProver {
  #[uniffi::constructor]
  pub fn new() -> Result<Arc<Self>, VegaError> {
    let t = Instant::now();
    let (pk, _vk) = api::setup_limit(TREE_DEPTH)?;
    Ok(Arc::new(VegaLimitProver { pk, setup_ms: t.elapsed().as_millis() as u64 }))
  }

  /// How long setup took, in milliseconds.
  pub fn setup_ms(&self) -> u64 {
    self.setup_ms
  }

  /// Proves a signed assertion and its use number. CPU-bound; call off the main thread. Public
  /// values: `[challenge_hi, challenge_lo, limit_root, epoch, limit, token]`.
  pub fn prove(&self, inputs: ProverInputs, limit: LimitParams) -> Result<ProofOutput, VegaError> {
    let inputs = LimitInputs {
      pop: inputs.into_pop()?,
      secret: limit.secret,
      epoch: api::scalar_to_hex(&api::epoch_from_label(&limit.epoch_label)),
      counter: limit.counter,
      limit: limit.limit,
    };
    let witness = inputs.witness()?;
    let t = Instant::now();
    let out = api::prove_limit(&self.pk, witness)?;
    Ok(ProofOutput { proof: out.proof, public_values: out.public_values, prove_ms: t.elapsed().as_millis() as u64 })
  }
}

/// A new limit secret from 32 random bytes, hex. Keep it on the device.
#[uniffi::export]
pub fn limit_secret(random: Vec<u8>) -> Result<String, VegaError> {
  Ok(api::scalar_to_hex(&api::secret_from_random(&random)?))
}

/// What the device enrolls for its secret, hex.
#[uniffi::export]
pub fn limit_secret_commitment(secret: String) -> Result<String, VegaError> {
  Ok(api::scalar_to_hex(&poseidon::secret_commitment(api::scalar_from_hex(&secret)?)))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn proves_fixture() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/tests/vectors/fixture.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let i: PopInputs = serde_json::from_value(v["inputs"].clone()).unwrap();
    let inputs = || ProverInputs {
      authenticator_data: i.authenticator_data.clone(),
      client_data_json: i.client_data_json.clone(),
      signature: i.signature.clone(),
      pub_key_x: i.pub_key_x.clone(),
      pub_key_y: i.pub_key_y.clone(),
      challenge: i.challenge.clone(),
      path_elements: i.path_elements.clone(),
      path_indices: i.path_indices.iter().copied().map(u32::from).collect(),
    };
    let prover = VegaProver::new().unwrap();
    let out = prover.prove(inputs()).unwrap();
    let (_pk, vk) = api::setup().unwrap();
    assert_eq!(api::verify(&vk, &out.proof).unwrap(), out.public_values);

    let secret = limit_secret(vec![7; 32]).unwrap();
    assert!(limit_secret_commitment(secret.clone()).unwrap().starts_with("0x"));
    let limited = VegaLimitProver::new().unwrap();
    let params = |counter| LimitParams { secret: secret.clone(), epoch_label: "event/1".into(), counter, limit: 2 };
    let out = limited.prove(inputs(), params(1)).unwrap();
    let (_pk, vk) = api::setup_limit(TREE_DEPTH).unwrap();
    assert_eq!(api::verify(&vk, &out.proof).unwrap(), out.public_values);
    assert!(limited.prove(inputs(), params(2)).is_err());
  }
}
