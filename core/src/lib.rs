//! Vega proof that the holder of a registered passkey signed a WebAuthn challenge.
//!
//! Same statement as the Noir circuit in `circuits/src/main.nr`, re-expressed as
//! bellpepper R1CS over T-256 so P-256 ECDSA arithmetic is native. Public values are
//! `[challenge_hi, challenge_lo, merkle_root]`.

pub mod api;
pub mod circuit;
pub mod gadgets;
pub mod poseidon;
#[rustfmt::skip]
mod poseidon_constants;
pub mod vendor;

use vega_prover::{provider::T256HyraxEngine, traits::Engine};

/// The proving engine: Spartan + Hyrax over T-256, whose scalar field is P-256's base field.
pub type Engine_ = T256HyraxEngine;
/// The circuit's native field.
pub type Scalar = <Engine_ as Engine>::Scalar;
