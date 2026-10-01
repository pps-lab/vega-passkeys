//! wasm-bindgen surface for the browser prover (`--target web`) and the Node verifier
//! (`--target nodejs`). Setup is transparent and deterministic, so each side derives its
//! key from the circuit at init instead of downloading it.

use pop_vega::api::{self, PopInputs, ProverKey, VerifierKey};
use pop_vega::poseidon;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

thread_local! {
  static PK: RefCell<Option<ProverKey>> = const { RefCell::new(None) };
  static VK: RefCell<Option<VerifierKey>> = const { RefCell::new(None) };
}

fn err(e: impl std::fmt::Display) -> JsError {
  JsError::new(&e.to_string())
}

#[wasm_bindgen(start)]
pub fn start() {
  console_error_panic_hook::set_once();
}

/// Derives the prover key. Idempotent.
#[wasm_bindgen(js_name = initProver)]
pub fn init_prover() -> Result<(), JsError> {
  if PK.with(|pk| pk.borrow().is_some()) {
    return Ok(());
  }
  let (pk, _vk) = api::setup().map_err(err)?;
  PK.with(|cell| *cell.borrow_mut() = Some(pk));
  Ok(())
}

/// Derives the verifier key. Idempotent.
#[wasm_bindgen(js_name = initVerifier)]
pub fn init_verifier() -> Result<(), JsError> {
  if VK.with(|vk| vk.borrow().is_some()) {
    return Ok(());
  }
  let (_pk, vk) = api::setup().map_err(err)?;
  VK.with(|cell| *cell.borrow_mut() = Some(vk));
  Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ProveResult {
  #[serde(with = "serde_bytes_compat")]
  proof: Vec<u8>,
  public_values: Vec<String>,
}

// Serialize the proof as a Uint8Array rather than a JS number array.
mod serde_bytes_compat {
  pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
  }
}

/// Proves a WebAuthn assertion (see `PopInputs` for the shape). Returns
/// `{ proof: Uint8Array, publicValues: string[] }`.
#[wasm_bindgen]
pub fn prove(inputs: JsValue) -> Result<JsValue, JsError> {
  init_prover()?;
  let inputs: PopInputs = serde_wasm_bindgen::from_value(inputs).map_err(err)?;
  let witness = inputs.witness().map_err(err)?;
  let out = PK.with(|pk| api::prove(pk.borrow().as_ref().expect("initialized"), witness)).map_err(err)?;
  let result = ProveResult { proof: out.proof, public_values: out.public_values };
  serde_wasm_bindgen::to_value(&result).map_err(err)
}

/// Verifies a proof; returns its public values `[challenge_hi, challenge_lo, root]`
/// as hex, or throws.
#[wasm_bindgen]
pub fn verify(proof: &[u8]) -> Result<Vec<String>, JsError> {
  init_verifier()?;
  VK.with(|vk| api::verify(vk.borrow().as_ref().expect("initialized"), proof)).map_err(err)
}

/// Public values a valid proof for this challenge (base64url) and root (hex) carries.
#[wasm_bindgen(js_name = expectedPublicValues)]
pub fn expected_public_values(challenge: &str, root: &str) -> Result<Vec<String>, JsError> {
  let challenge: [u8; 32] = api::b64url(challenge)
    .map_err(err)?
    .try_into()
    .map_err(|_| err("challenge must be 32 bytes"))?;
  Ok(api::expected_public_values(&challenge, &api::scalar_from_hex(root).map_err(err)?))
}

/// Poseidon commitment to a P-256 public key given as raw 32-byte coordinates.
#[wasm_bindgen]
pub fn commitment(x: &[u8], y: &[u8]) -> Result<String, JsError> {
  let coord = |b: &[u8]| -> Result<_, JsError> {
    let be: [u8; 32] = b.try_into().map_err(|_| err("coordinate must be 32 bytes"))?;
    poseidon::scalar_from_be_bytes(&be).ok_or_else(|| err("coordinate not below modulus"))
  };
  Ok(api::scalar_to_hex(&poseidon::commitment(coord(x)?, coord(y)?)))
}

/// Poseidon Merkle node over two hex field elements.
#[wasm_bindgen(js_name = merkleNode)]
pub fn merkle_node(left: &str, right: &str) -> Result<String, JsError> {
  let l = api::scalar_from_hex(left).map_err(err)?;
  let r = api::scalar_from_hex(right).map_err(err)?;
  Ok(api::scalar_to_hex(&poseidon::node(l, r)))
}
