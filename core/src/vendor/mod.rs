//! Gadgets vendored from sirosfoundation/zk-cred-vega v0.0.5 (BSD-2-Clause, see
//! `LICENSE-zk-cred-vega`), which in turn ports parts of microsoft/Nova (MIT) and
//! bellman-bignat (MIT). That crate is marked experimental and unaudited; its ECDSA
//! gadget had two critical soundness bugs found and fixed in review (see `ecdsa.rs`).
//!
//! Local changes: module paths, and `sha256_var::sha256_var_sized_with_selector`.
#![allow(dead_code, clippy::all)]

pub mod ecdsa;
pub mod gadget_utils;
pub mod nonnative;
pub mod p256_ecc;
pub mod sha256_var;
