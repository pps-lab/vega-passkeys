//! Prints the combined circuit's verifier-key digest at a depth (default 20). Two builds
//! that print the same digest prove the same R1CS, so this guards refactors of the
//! deployed circuit. Usage: cargo run --release --example vk_digest [depth]
use pop_vega::api;
use vega_prover::traits::snark::DigestHelperTrait;

fn main() {
  let depth = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);
  let (_pk, vk) = api::setup_with_depth(depth).unwrap();
  println!("depth {depth} vk digest {:?}", vk.digest().unwrap());
}
