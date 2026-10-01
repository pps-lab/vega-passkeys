//! UniFFI surface for native (iOS) proving. Same statement and proof format as the browser
//! prover, so the server verifies the result with `proofType: "zk-webauthn-v2"`.
//!
//! Swift usage:
//! ```swift
//! let prover = try VegaProver()               // transparent setup; slow, do it once in the background
//! let out = try prover.prove(inputs: inputs)  // ProofOutput { proof, publicValues, proveMs }
//! ```

use pop_vega::api::{self, PopInputs, ProverKey};
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
  /// The signed clientData JSON (at most 256 bytes); must contain the base64url challenge.
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
    let inputs = PopInputs {
      authenticator_data: inputs.authenticator_data,
      client_data_json: inputs.client_data_json,
      signature: inputs.signature,
      pub_key_x: inputs.pub_key_x,
      pub_key_y: inputs.pub_key_y,
      challenge: inputs.challenge,
      path_elements: inputs.path_elements,
      path_indices: inputs
        .path_indices
        .into_iter()
        .map(|i| u8::try_from(i).map_err(|_| VegaError::InvalidInput { msg: "path index must be 0 or 1".into() }))
        .collect::<Result<_, _>>()?,
    };
    let witness = inputs.witness()?;
    let t = Instant::now();
    let out = api::prove(&self.pk, witness)?;
    Ok(ProofOutput { proof: out.proof, public_values: out.public_values, prove_ms: t.elapsed().as_millis() as u64 })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn proves_fixture() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/tests/vectors/fixture.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let i: PopInputs = serde_json::from_value(v["inputs"].clone()).unwrap();
    let inputs = ProverInputs {
      authenticator_data: i.authenticator_data,
      client_data_json: i.client_data_json,
      signature: i.signature,
      pub_key_x: i.pub_key_x,
      pub_key_y: i.pub_key_y,
      challenge: i.challenge,
      path_elements: i.path_elements,
      path_indices: i.path_indices.into_iter().map(u32::from).collect(),
    };
    let prover = VegaProver::new().unwrap();
    let out = prover.prove(inputs).unwrap();
    let (_pk, vk) = api::setup().unwrap();
    assert_eq!(api::verify(&vk, &out.proof).unwrap(), out.public_values);
  }
}
