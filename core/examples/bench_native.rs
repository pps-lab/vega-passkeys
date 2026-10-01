//! Native timings for vega/bench/compare.sh: setup, prove (N runs), verify, sizes.
//! Usage: cargo run --release --example bench_native [runs]
#[path = "../tests/common/mod.rs"]
mod common;

use pop_vega::api;
use std::time::Instant;

fn main() {
  let runs: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5);
  let threads = std::env::var("RAYON_NUM_THREADS")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
  let t = Instant::now();
  let (pk, vk) = api::setup().unwrap();
  let setup_ms = t.elapsed().as_secs_f64() * 1e3;
  let f = common::fixture();

  let mut prove_ms = Vec::new();
  let mut out = None;
  for _ in 0..runs {
    let t = Instant::now();
    out = Some(api::prove(&pk, f.inputs.witness().unwrap()).unwrap());
    prove_ms.push(t.elapsed().as_secs_f64() * 1e3);
  }
  let out = out.unwrap();
  let t = Instant::now();
  api::verify(&vk, &out.proof).unwrap();
  let verify_ms = t.elapsed().as_secs_f64() * 1e3;
  prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

  println!("vega  threads={threads} setup={setup_ms:.0}ms prove_median={:.0}ms prove_min={:.0}ms verify={verify_ms:.0}ms proof={}B pk={}B vk={}B",
    prove_ms[runs / 2], prove_ms[0], out.proof.len(),
    api::serialize(&pk).unwrap().len(), api::serialize(&vk).unwrap().len());
}
