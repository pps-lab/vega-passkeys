//! Writes tests/vectors/fixture.json: prover inputs plus the expected root, for the
//! JS-side tests and benchmarks.
#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
  let f = common::fixture();
  let json = serde_json::json!({
    "inputs": f.inputs,
    "root": pop_vega::api::scalar_to_hex(&f.root),
  });
  std::fs::create_dir_all("tests/vectors").unwrap();
  std::fs::write("tests/vectors/fixture.json", serde_json::to_string_pretty(&json).unwrap()).unwrap();
  println!("wrote tests/vectors/fixture.json");
}
