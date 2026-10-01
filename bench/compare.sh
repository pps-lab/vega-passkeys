#!/bin/sh
# Native Noir/UltraHonk vs Vega on the same signed WebAuthn assertion.
# Needs nargo + bb matching circuits/target/pop_circuit.json (currently nargo 1.0.0-beta.21,
# bb from bbup) on PATH or in ~/.nargo/bin and ~/.bb. Usage: vega/bench/compare.sh [runs]
set -eu
RUNS=${1:-5}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NARGO=${NARGO:-$(command -v nargo || echo "$HOME/.nargo/bin/nargo")}
BB=${BB:-$(command -v bb || echo "$HOME/.bb/bb")}
OUT=$(mktemp -d)
# generate_test_vector.mjs rewrites Prover.toml and `nargo execute` recompiles the artifact
# (debug metadata only); put both back afterwards.
cp "$ROOT/circuits/Prover.toml" "$ROOT/circuits/target/pop_circuit.json" "$OUT/"
restore() {
  cp "$OUT/Prover.toml" "$ROOT/circuits/Prover.toml"
  cp "$OUT/pop_circuit.json" "$ROOT/circuits/target/pop_circuit.json"
  rm -rf "$OUT" "$ROOT/circuits/target/bench_witness.gz"
}
trap restore EXIT

ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

echo "== test vector"
(cd "$ROOT/vega/core" && cargo run -q --release --example gen_vector)
(cd "$ROOT/circuits/prover" && node ../generate_test_vector.mjs ../../vega/core/tests/vectors/fixture.json > /dev/null)

echo "== noir ($("$NARGO" --version | head -1), bb $("$BB" --version))"
cd "$ROOT/circuits"
t=$(ms); "$NARGO" execute bench_witness > /dev/null; echo "noir  execute (witness) $(( $(ms) - t ))ms"
t=$(ms); "$BB" write_vk -b target/pop_circuit.json -o "$OUT/vk" > /dev/null 2>&1; echo "noir  write_vk $(( $(ms) - t ))ms"
i=0
while [ $i -lt "$RUNS" ]; do
  t=$(ms); "$BB" prove -b target/pop_circuit.json -w target/bench_witness.gz -k "$OUT/vk/vk" -o "$OUT/proof" > /dev/null 2>&1
  echo "noir  prove run $((i + 1)) $(( $(ms) - t ))ms"
  i=$((i + 1))
done
t=$(ms); "$BB" verify -k "$OUT/vk/vk" -p "$OUT/proof/proof" -i "$OUT/proof/public_inputs" > /dev/null 2>&1 && echo "noir  verify $(( $(ms) - t ))ms (ok)"
echo "noir  proof=$(wc -c < "$OUT/proof/proof" | tr -d ' ')B vk=$(wc -c < "$OUT/vk/vk" | tr -d ' ')B"

echo "== vega"
(cd "$ROOT/vega/core" && cargo run -q --release --example bench_native "$RUNS")
