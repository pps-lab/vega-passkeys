//! Prover/verifier entry points shared by the native tests, the setup binary and the
//! wasm bindings. Byte fields are base64url; field elements are `0x` big-endian hex.

use crate::circuit::{
  self as circuit, AccCircuit, PopCircuit, PopWitness, SigCircuit, CDJ_PREFIX, CHALLENGE_OFFSET, FLAGS_BYTE, MAX_AUTH_DATA,
  MAX_CDJ, MIN_AUTH_DATA, MIN_CDJ, TREE_DEPTH,
};
use crate::gadgets::CHALLENGE_B64_LEN;
use crate::poseidon::{scalar_from_be_bytes, scalar_to_be_bytes};
use crate::vendor::p256_ecc::p256_order;
use crate::{Engine_, Scalar};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use vega_prover::{
  traits::{circuit::VegaCircuit, snark::R1CSSNARKTrait},
  vega_sc_zkp::VegaZkSNARK,
};

pub type Snark = VegaZkSNARK<Engine_>;
pub type ProverKey = <Snark as R1CSSNARKTrait<Engine_>>::ProverKey;
pub type VerifierKey = <Snark as R1CSSNARKTrait<Engine_>>::VerifierKey;
pub type Prep = <Snark as R1CSSNARKTrait<Engine_>>::PrepSNARK;

#[derive(Debug, thiserror::Error)]
pub enum PopError {
  #[error("invalid input: {0}")]
  Input(String),
  #[error("proof system error: {0}")]
  Vega(String),
  #[error("serialization error: {0}")]
  Serde(String),
}

fn input_err(msg: impl Into<String>) -> PopError {
  PopError::Input(msg.into())
}

/// What the browser sends to the prover: a WebAuthn assertion plus the credential's
/// public key and Merkle path from `/v1/pubkey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PopInputs {
  pub authenticator_data: String,
  pub client_data_json: String,
  /// DER (as returned by WebAuthn) or raw 64-byte r||s.
  pub signature: String,
  pub pub_key_x: String,
  pub pub_key_y: String,
  /// The 32-byte server challenge.
  pub challenge: String,
  pub path_elements: Vec<String>,
  pub path_indices: Vec<u8>,
}

pub fn b64url(s: &str) -> Result<Vec<u8>, PopError> {
  URL_SAFE_NO_PAD
    .decode(s.trim_end_matches('='))
    .map_err(|e| input_err(format!("base64url: {e}")))
}

pub fn scalar_from_hex(s: &str) -> Result<Scalar, PopError> {
  let digits = s.strip_prefix("0x").unwrap_or(s);
  if digits.len() > 64 {
    return Err(input_err("field element longer than 32 bytes"));
  }
  let mut be = [0u8; 32];
  let padded = format!("{digits:0>64}");
  hex::decode_to_slice(&padded, &mut be).map_err(|e| input_err(format!("hex: {e}")))?;
  scalar_from_be_bytes(&be).ok_or_else(|| input_err("field element not below modulus"))
}

pub fn scalar_to_hex(s: &Scalar) -> String {
  format!("0x{}", hex::encode(scalar_to_be_bytes(s)))
}

fn scalar_from_32(bytes: &[u8]) -> Result<Scalar, PopError> {
  let be: [u8; 32] = bytes.try_into().map_err(|_| input_err("coordinate must be 32 bytes"))?;
  scalar_from_be_bytes(&be).ok_or_else(|| input_err("coordinate not below modulus"))
}

/// Parses an ECDSA signature: raw r||s (64 bytes) or DER SEQUENCE { INTEGER r, INTEGER s }.
pub fn parse_signature(sig: &[u8]) -> Result<(BigInt, BigInt), PopError> {
  if sig.len() == 64 {
    return Ok((BigInt::from_bytes_be(Sign::Plus, &sig[..32]), BigInt::from_bytes_be(Sign::Plus, &sig[32..])));
  }
  let bad = || input_err("malformed DER signature");
  let int = |buf: &[u8]| -> Result<(BigInt, usize), PopError> {
    if buf.len() < 2 || buf[0] != 0x02 {
      return Err(bad());
    }
    let len = buf[1] as usize;
    let body = buf.get(2..2 + len).ok_or_else(bad)?;
    Ok((BigInt::from_bytes_be(Sign::Plus, body), 2 + len))
  };
  if sig.len() < 2 || sig[0] != 0x30 || sig[1] as usize != sig.len() - 2 {
    return Err(bad());
  }
  let (r, used) = int(&sig[2..])?;
  let (s, used2) = int(&sig[2 + used..])?;
  if 2 + used + used2 != sig.len() {
    return Err(bad());
  }
  Ok((r, s))
}

fn sha256(data: &[u8]) -> [u8; 32] {
  use sha2::Digest;
  sha2::Sha256::digest(data).into()
}

impl PopInputs {
  pub fn witness(&self) -> Result<PopWitness, PopError> {
    let auth_data = b64url(&self.authenticator_data)?;
    let cdj = b64url(&self.client_data_json)?;
    let challenge: [u8; 32] = b64url(&self.challenge)?.try_into().map_err(|_| input_err("challenge must be 32 bytes"))?;
    if auth_data.len() < MIN_AUTH_DATA || auth_data.len() > MAX_AUTH_DATA {
      return Err(input_err(format!("authenticatorData must be {MIN_AUTH_DATA}..={MAX_AUTH_DATA} bytes")));
    }
    let flags = auth_data[FLAGS_BYTE];
    if flags & 0x01 == 0 {
      return Err(input_err("authenticatorData UP flag not set"));
    }
    if flags & 0x04 == 0 {
      return Err(input_err("authenticatorData UV flag not set"));
    }
    if cdj.len() > MAX_CDJ {
      return Err(input_err(format!("clientDataJSON longer than {MAX_CDJ} bytes")));
    }
    // The circuit checks these same byte positions; fail early with a readable reason.
    if cdj.len() < MIN_CDJ || !cdj.starts_with(CDJ_PREFIX) {
      return Err(input_err("clientDataJSON does not start with the webauthn.get challenge prefix"));
    }
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    debug_assert_eq!(challenge_b64.len(), CHALLENGE_B64_LEN);
    let value = &cdj[CHALLENGE_OFFSET..MIN_CDJ];
    if &value[..CHALLENGE_B64_LEN] != challenge_b64.as_bytes() || value[CHALLENGE_B64_LEN] != b'"' {
      return Err(input_err("clientDataJSON challenge does not match"));
    }

    let mut msg = auth_data;
    msg.extend_from_slice(&sha256(&cdj));

    let (r, s) = parse_signature(&b64url(&self.signature)?)?;
    let n = p256_order();
    if r <= BigInt::from(0) || r >= n || s <= BigInt::from(0) || s >= n {
      return Err(input_err("signature scalar out of range"));
    }
    let s_inv = s.modpow(&(&n - 2), &n);

    let depth = self.path_elements.len();
    if depth == 0 || self.path_indices.len() != depth {
      return Err(input_err("Merkle path and indices must be non-empty and of equal length"));
    }
    let mut path = vec![Scalar::from(0u64); depth];
    let mut indices = vec![false; depth];
    for i in 0..depth {
      path[i] = scalar_from_hex(&self.path_elements[i])?;
      indices[i] = match self.path_indices[i] {
        0 => false,
        1 => true,
        _ => return Err(input_err("path index must be 0 or 1")),
      };
    }

    Ok(PopWitness {
      challenge,
      msg,
      cdj,
      qx: scalar_from_32(&b64url(&self.pub_key_x)?)?,
      qy: scalar_from_32(&b64url(&self.pub_key_y)?)?,
      r,
      s,
      s_inv,
      path,
      indices,
    })
  }
}

/// Transparent setup for the default depth (`TREE_DEPTH`).
pub fn setup() -> Result<(ProverKey, VerifierKey), PopError> {
  setup_with_depth(TREE_DEPTH)
}

/// Transparent setup: derives the keys from the circuit shape alone, which is fixed by the
/// Merkle depth.
pub fn setup_with_depth(depth: usize) -> Result<(ProverKey, VerifierKey), PopError> {
  if depth == 0 {
    return Err(input_err("Merkle depth must be positive"));
  }
  setup_circuit(PopCircuit { w: PopWitness::dummy(depth) })
}

/// Setup for the signature half of the split proof (independent of the Merkle depth).
pub fn setup_signature() -> Result<(ProverKey, VerifierKey), PopError> {
  setup_circuit(SigCircuit::dummy())
}

/// Setup for the accumulator half of the split proof at a Merkle depth.
pub fn setup_accumulator(depth: usize) -> Result<(ProverKey, VerifierKey), PopError> {
  if depth == 0 {
    return Err(input_err("Merkle depth must be positive"));
  }
  setup_circuit(AccCircuit::dummy(depth))
}

fn setup_circuit<C: VegaCircuit<Engine_>>(c: C) -> Result<(ProverKey, VerifierKey), PopError> {
  Snark::setup(c).map_err(|e| PopError::Vega(format!("{e:?}")))
}

/// Proof plus its public values (`[challenge_hi, challenge_lo, merkle_root]` as hex).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOutput {
  pub proof: Vec<u8>,
  pub public_values: Vec<String>,
}

pub fn prove(pk: &ProverKey, w: PopWitness) -> Result<ProofOutput, PopError> {
  prove_circuit(pk, PopCircuit { w })
}

/// Splits a witness for the two-proof variant; `blind` hides the leaf in the shared link.
pub fn split(w: PopWitness, blind: Scalar) -> (SigCircuit, AccCircuit) {
  circuit::split(w, blind)
}

/// Proves the signature half; public values `[challenge_hi, challenge_lo, link]`.
pub fn prove_signature(pk: &ProverKey, c: SigCircuit) -> Result<ProofOutput, PopError> {
  prove_circuit(pk, c)
}

/// Proves the accumulator half; public values `[link, merkle_root]`.
pub fn prove_accumulator(pk: &ProverKey, c: AccCircuit) -> Result<ProofOutput, PopError> {
  prove_circuit(pk, c)
}

fn prove_circuit<C: VegaCircuit<Engine_>>(pk: &ProverKey, circuit: C) -> Result<ProofOutput, PopError> {
  let public_values = circuit
    .public_values()
    .map_err(|e| PopError::Vega(format!("{e:?}")))?
    .iter()
    .map(scalar_to_hex)
    .collect();
  let prep = Snark::prep_prove(pk, circuit.clone(), false).map_err(|e| PopError::Vega(format!("{e:?}")))?;
  let (snark, _prep) = Snark::prove(pk, circuit, prep, false).map_err(|e| PopError::Vega(format!("{e:?}")))?;
  let proof = bincode::serialize(&snark).map_err(|e| PopError::Serde(e.to_string()))?;
  Ok(ProofOutput { proof, public_values })
}

/// Verifies a proof and returns its public values as hex.
pub fn verify(vk: &VerifierKey, proof: &[u8]) -> Result<Vec<String>, PopError> {
  let snark: Snark = bincode::deserialize(proof).map_err(|e| PopError::Serde(e.to_string()))?;
  let io = snark.verify(vk).map_err(|e| PopError::Vega(format!("{e:?}")))?;
  Ok(io.iter().map(scalar_to_hex).collect())
}

/// Public values a verifier should expect for a given challenge and root.
pub fn expected_public_values(challenge: &[u8; 32], root: &Scalar) -> Vec<String> {
  let [hi, lo] = PopWitness::challenge_halves(challenge);
  vec![scalar_to_hex(&hi), scalar_to_hex(&lo), scalar_to_hex(root)]
}

pub fn serialize<T: Serialize>(v: &T) -> Result<Vec<u8>, PopError> {
  bincode::serialize(v).map_err(|e| PopError::Serde(e.to_string()))
}

pub fn deserialize<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T, PopError> {
  bincode::deserialize(b).map_err(|e| PopError::Serde(e.to_string()))
}
