use pop_vega::api;
use std::io::Write;
fn main() {
  let (pk, vk) = api::setup().unwrap();
  println!("sizes: {:?}", pk.sizes());
  let pkb = api::serialize(&pk).unwrap();
  let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
  e.write_all(&pkb).unwrap();
  println!("pk {} gz {}", pkb.len(), e.finish().unwrap().len());
  let (_pk2, vk2) = api::setup().unwrap();
  use vega_prover::traits::snark::DigestHelperTrait;
  println!("vk digest deterministic: {}", vk.digest().unwrap() == vk2.digest().unwrap());
}
