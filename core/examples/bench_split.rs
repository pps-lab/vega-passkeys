//! Native timings per Merkle depth for the combined proof and the split pair (signature +
//! accumulator): setup, prove and verify. Verification is the relying party's cost, so this
//! is where benchmark tables take it from.
//!
//! Usage: cargo run --release --example bench_split -- [runs] [depth...] > results.json
//! (defaults: 10 runs, depths 20 22 24 26 28). RAYON_NUM_THREADS limits the thread pool.
#[path = "../tests/common/mod.rs"]
mod common;

use pop_vega::{api, Scalar};
use std::time::Instant;

fn stats(mut xs: Vec<f64>) -> String {
  let mean = xs.iter().sum::<f64>() / xs.len() as f64;
  let samples = xs.iter().map(|x| format!("{x:.3}")).collect::<Vec<_>>().join(",");
  xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
  let n = xs.len();
  let median = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
  format!(r#"{{"mean":{mean:.3},"median":{median:.3},"min":{:.3},"max":{:.3},"samples":[{samples}]}}"#, xs[0], xs[n - 1])
}

fn time<T>(runs: usize, mut f: impl FnMut() -> T) -> (Vec<f64>, T) {
  let mut out = None;
  let xs = (0..runs)
    .map(|_| {
      let t = Instant::now();
      out = Some(f());
      t.elapsed().as_secs_f64() * 1e3
    })
    .collect();
  (xs, out.unwrap())
}

fn main() {
  let mut args = std::env::args().skip(1);
  let runs: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
  let mut depths: Vec<usize> = args.filter_map(|s| s.parse().ok()).collect();
  if depths.is_empty() {
    depths = vec![20, 22, 24, 26, 28];
  }
  let threads = rayon_threads();

  // The signature half does not depend on the depth: one key for all of them.
  let (setup_sig, (sig_pk, sig_vk)) = time(1, || api::setup_signature().unwrap());
  let mut rows = Vec::new();
  for depth in depths {
    let f = common::fixture_at_depth(&[7u8; 32], [42u8; 32], 5, depth);
    let w = f.inputs.witness().unwrap();
    let (sig, acc) = api::split(w.clone(), Scalar::from(0x5eed_u64));

    let (setup_pop, (pk, vk)) = time(1, || api::setup_with_depth(depth).unwrap());
    let (setup_acc, (acc_pk, acc_vk)) = time(1, || api::setup_accumulator(depth).unwrap());

    let (prove, out) = time(runs, || api::prove(&pk, w.clone()).unwrap());
    let (prove_sig, sig_out) = time(runs, || api::prove_signature(&sig_pk, sig.clone()).unwrap());
    let (prove_acc, acc_out) = time(runs, || api::prove_accumulator(&acc_pk, acc.clone()).unwrap());

    let (verify, _) = time(runs, || api::verify(&vk, &out.proof).unwrap());
    let (verify_sig, sp) = time(runs, || api::verify(&sig_vk, &sig_out.proof).unwrap());
    let (verify_acc, ap) = time(runs, || api::verify(&acc_vk, &acc_out.proof).unwrap());
    assert_eq!(sp[2], ap[0], "split proofs must share the link");

    eprintln!(
      "depth {depth}: combined prove {:.0} verify {:.1} ms | sig prove {:.0} verify {:.1} | acc prove {:.0} verify {:.1}",
      median(&prove), median(&verify), median(&prove_sig), median(&verify_sig), median(&prove_acc), median(&verify_acc)
    );
    rows.push(format!(
      concat!(
        r#"{{"device":"native","prover":"vega","platform":"{platform}","threads":{threads},"iterations":{runs},"merklePathLength":{depth},"#,
        r#""setupMs":{setup_pop:.3},"signatureSetupMs":{setup_sig:.3},"accumulatorSetupMs":{setup_acc:.3},"#,
        r#""proofMs":{prove},"signatureProofMs":{prove_sig},"accumulatorProofMs":{prove_acc},"#,
        r#""verificationMs":{verify},"signatureVerificationMs":{verify_sig},"accumulatorVerificationMs":{verify_acc},"#,
        r#""proofBytes":{pb},"signatureProofBytes":{sb},"accumulatorProofBytes":{ab}}}"#
      ),
      platform = std::env::consts::ARCH,
      threads = threads,
      runs = runs,
      depth = depth,
      setup_pop = setup_pop[0],
      setup_sig = setup_sig[0],
      setup_acc = setup_acc[0],
      prove = stats(prove),
      prove_sig = stats(prove_sig),
      prove_acc = stats(prove_acc),
      verify = stats(verify),
      verify_sig = stats(verify_sig),
      verify_acc = stats(verify_acc),
      pb = out.proof.len(),
      sb = sig_out.proof.len(),
      ab = acc_out.proof.len(),
    ));
  }
  println!("[\n{}\n]", rows.join(",\n"));
}

fn median(xs: &[f64]) -> f64 {
  let mut s = xs.to_vec();
  s.sort_by(|a, b| a.partial_cmp(b).unwrap());
  s[s.len() / 2]
}

fn rayon_threads() -> usize {
  std::env::var("RAYON_NUM_THREADS")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}
