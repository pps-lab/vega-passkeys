//! A realistic WebAuthn assertion signed with RustCrypto's `p256`, plus a Merkle path.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use pop_vega::api::{scalar_to_hex, PopInputs};
use pop_vega::circuit::TREE_DEPTH;
use pop_vega::{poseidon, Scalar};
use sha2::{Digest, Sha256};

pub struct Fixture {
  pub inputs: PopInputs,
  pub challenge: [u8; 32],
  pub root: Scalar,
}

pub fn fixture() -> Fixture {
  fixture_with(&[7u8; 32], [42u8; 32], 5)
}

pub fn fixture_with(sk: &[u8; 32], challenge: [u8; 32], leaf_index: u32) -> Fixture {
  fixture_with_flags(sk, challenge, leaf_index, 0x05) // UP | UV
}

pub fn fixture_with_flags(sk: &[u8; 32], challenge: [u8; 32], leaf_index: u32, flags: u8) -> Fixture {
  let signing_key = SigningKey::from_bytes(sk.into()).unwrap();
  let point = signing_key.verifying_key().to_encoded_point(false);
  let (x, y) = (point.x().unwrap().to_vec(), point.y().unwrap().to_vec());

  let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
  let cdj = format!(
    r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://verena.se","crossOrigin":false}}"#
  );
  let mut auth_data = Sha256::digest(b"verena.se").to_vec();
  auth_data.push(flags);
  auth_data.extend_from_slice(&[0, 0, 0, 1]);

  let mut msg = auth_data.clone();
  msg.extend_from_slice(&Sha256::digest(cdj.as_bytes()));
  let sig: Signature = signing_key.sign(&msg);

  // Path with distinct non-trivial siblings.
  let mut cur = poseidon::commitment(scalar(&x), scalar(&y));
  let mut path_elements = Vec::new();
  let mut path_indices = Vec::new();
  for level in 0..TREE_DEPTH {
    let sib = poseidon::node(Scalar::from(level as u64 + 1000), Scalar::from(3u64));
    let right = (leaf_index >> level) & 1 == 1;
    cur = if right { poseidon::node(sib, cur) } else { poseidon::node(cur, sib) };
    path_elements.push(scalar_to_hex(&sib));
    path_indices.push(right as u8);
  }

  Fixture {
    inputs: PopInputs {
      authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
      client_data_json: URL_SAFE_NO_PAD.encode(cdj.as_bytes()),
      signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
      pub_key_x: URL_SAFE_NO_PAD.encode(&x),
      pub_key_y: URL_SAFE_NO_PAD.encode(&y),
      challenge: challenge_b64,
      path_elements,
      path_indices,
    },
    challenge,
    root: cur,
  }
}

fn scalar(be: &[u8]) -> Scalar {
  poseidon::scalar_from_be_bytes(be.try_into().unwrap()).unwrap()
}
