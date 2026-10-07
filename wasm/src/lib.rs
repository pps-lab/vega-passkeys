//! wasm-bindgen surface for the browser prover (`--target web`) and the Node verifier
//! (`--target nodejs`). Setup is transparent and deterministic, so each side derives its
//! key from the circuit at init instead of downloading it.
//!
//! The circuit shape depends on the Merkle depth, so each side holds the key for one depth
//! at a time (a prover key is ~70 MB in memory) and re-derives it when the depth changes.

use pop_vega::api::{self, PopInputs, ProverKey, VerifierKey};
use pop_vega::circuit::TREE_DEPTH;
use pop_vega::poseidon;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

thread_local! {
  static PK: RefCell<Option<(usize, ProverKey)>> = const { RefCell::new(None) };
  static VK: RefCell<Option<(usize, VerifierKey)>> = const { RefCell::new(None) };
  // Split proof (benchmarks): the signature key is depth-independent.
  static SIG_PK: RefCell<Option<ProverKey>> = const { RefCell::new(None) };
  static ACC_PK: RefCell<Option<(usize, ProverKey)>> = const { RefCell::new(None) };
}

fn err(e: impl std::fmt::Display) -> JsError {
  JsError::new(&e.to_string())
}

/// `initThreadPool(n)`: spawns the rayon pool. Call once after `init()`, before proving.
#[cfg(feature = "threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen(start)]
pub fn start() {
  console_error_panic_hook::set_once();
}

/// Derives the prover key for a Merkle depth (default 20). Idempotent per depth.
#[wasm_bindgen(js_name = initProver)]
pub fn init_prover(depth: Option<usize>) -> Result<(), JsError> {
  let depth = depth.unwrap_or(TREE_DEPTH);
  if PK.with(|pk| matches!(&*pk.borrow(), Some((d, _)) if *d == depth)) {
    return Ok(());
  }
  // Drop the old key before deriving the new one, so both are never resident.
  PK.with(|cell| *cell.borrow_mut() = None);
  let (pk, _vk) = api::setup_with_depth(depth).map_err(err)?;
  PK.with(|cell| *cell.borrow_mut() = Some((depth, pk)));
  Ok(())
}

/// Derives the verifier key for a Merkle depth (default 20). Idempotent per depth.
#[wasm_bindgen(js_name = initVerifier)]
pub fn init_verifier(depth: Option<usize>) -> Result<(), JsError> {
  let depth = depth.unwrap_or(TREE_DEPTH);
  if VK.with(|vk| matches!(&*vk.borrow(), Some((d, _)) if *d == depth)) {
    return Ok(());
  }
  VK.with(|cell| *cell.borrow_mut() = None);
  let (_pk, vk) = api::setup_with_depth(depth).map_err(err)?;
  VK.with(|cell| *cell.borrow_mut() = Some((depth, vk)));
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

/// Proves a WebAuthn assertion (see `PopInputs` for the shape); the depth is the Merkle
/// path's length. Returns `{ proof: Uint8Array, publicValues: string[] }`.
#[wasm_bindgen]
pub fn prove(inputs: JsValue) -> Result<JsValue, JsError> {
  let inputs: PopInputs = serde_wasm_bindgen::from_value(inputs).map_err(err)?;
  let witness = inputs.witness().map_err(err)?;
  init_prover(Some(witness.path.len()))?;
  let out = PK.with(|pk| api::prove(&pk.borrow().as_ref().expect("initialized").1, witness)).map_err(err)?;
  let result = ProveResult { proof: out.proof, public_values: out.public_values };
  serde_wasm_bindgen::to_value(&result).map_err(err)
}

/// Verifies a proof for a Merkle depth (default 20); returns its public values
/// `[challenge_hi, challenge_lo, root]` as hex, or throws.
#[wasm_bindgen]
pub fn verify(proof: &[u8], depth: Option<usize>) -> Result<Vec<String>, JsError> {
  init_verifier(depth)?;
  VK.with(|vk| api::verify(&vk.borrow().as_ref().expect("initialized").1, proof)).map_err(err)
}

/// Derives the prover key for the signature half of the split proof. Idempotent.
#[wasm_bindgen(js_name = initSignatureProver)]
pub fn init_signature_prover() -> Result<(), JsError> {
  if SIG_PK.with(|pk| pk.borrow().is_some()) {
    return Ok(());
  }
  let (pk, _vk) = api::setup_signature().map_err(err)?;
  SIG_PK.with(|cell| *cell.borrow_mut() = Some(pk));
  Ok(())
}

/// Derives the prover key for the accumulator half at a Merkle depth. Idempotent per depth.
#[wasm_bindgen(js_name = initAccumulatorProver)]
pub fn init_accumulator_prover(depth: usize) -> Result<(), JsError> {
  if ACC_PK.with(|pk| matches!(&*pk.borrow(), Some((d, _)) if *d == depth)) {
    return Ok(());
  }
  ACC_PK.with(|cell| *cell.borrow_mut() = None);
  let (pk, _vk) = api::setup_accumulator(depth).map_err(err)?;
  ACC_PK.with(|cell| *cell.borrow_mut() = Some((depth, pk)));
  Ok(())
}

fn split_inputs(inputs: JsValue, blind: &str) -> Result<(pop_vega::circuit::SigCircuit, pop_vega::circuit::AccCircuit), JsError> {
  let inputs: PopInputs = serde_wasm_bindgen::from_value(inputs).map_err(err)?;
  let witness = inputs.witness().map_err(err)?;
  Ok(api::split(witness, api::scalar_from_hex(blind).map_err(err)?))
}

/// Proves the signature half of the split proof; `blind` (hex field element) must be the
/// one the accumulator half uses. Returns `{ proof, publicValues: [hi, lo, link] }`.
#[wasm_bindgen(js_name = proveSignature)]
pub fn prove_signature(inputs: JsValue, blind: &str) -> Result<JsValue, JsError> {
  let (sig, _) = split_inputs(inputs, blind)?;
  init_signature_prover()?;
  let out = SIG_PK.with(|pk| api::prove_signature(pk.borrow().as_ref().expect("initialized"), sig)).map_err(err)?;
  serde_wasm_bindgen::to_value(&ProveResult { proof: out.proof, public_values: out.public_values }).map_err(err)
}

/// Proves the accumulator half for the path in `inputs`. Returns
/// `{ proof, publicValues: [link, root] }`.
#[wasm_bindgen(js_name = proveAccumulator)]
pub fn prove_accumulator(inputs: JsValue, blind: &str) -> Result<JsValue, JsError> {
  let (_, acc) = split_inputs(inputs, blind)?;
  init_accumulator_prover(acc.path.len())?;
  let out = ACC_PK.with(|pk| api::prove_accumulator(&pk.borrow().as_ref().expect("initialized").1, acc)).map_err(err)?;
  serde_wasm_bindgen::to_value(&ProveResult { proof: out.proof, public_values: out.public_values }).map_err(err)
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
