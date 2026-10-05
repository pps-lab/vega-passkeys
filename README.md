# Vega prover

The passkey-membership proof from `circuits/` (Noir), re-implemented on
[microsoft/vega-prover](https://github.com/microsoft/vega-prover). Vega is Spartan with Hyrax
commitments over the T-256 curve. T-256's scalar field equals P-256's base field, so the
WebAuthn ECDSA-P256 check is native arithmetic in the circuit rather than emulated.

The Noir prover stays in the repo for comparison. Select it in the widget with `?prover=noir`.

## Statement

The statement is the same as `circuits/src/main.nr`. Everything below is private except the
challenge and the root.

1. `base64url(challenge)` appears in `clientDataJSON` at a private offset, inside its real length.
2. The signed message is `authenticatorData ‖ SHA-256(clientDataJSON)`. The hash is placed using
   the same one-hot length wires that the SHA-256 gadget hashes with. The authenticatorData flags
   byte must have UV (`0x04`) set.
3. ECDSA-P256 verifies over `SHA-256(message)` under the private key `(qx, qy)`.
4. `commitment(qx, qy)` is a leaf of a depth-20 Merkle tree with the public root.

Public values: `[challenge_hi, challenge_lo, merkle_root]`.

Differences from the Noir circuit:

- Poseidon runs over the P-256 base field, with t = 3, an x⁷ S-box, R_F = 8 and R_P = 48. BN254
  Poseidon2 isn't native here, and x⁵ isn't a permutation on this field.
  - `scripts/poseidon_params.py` generates the constants. It reproduces the circomlib BN254
    constants exactly.
  - Domain tags separate commitments from nodes.
  - `merkle.js` uses the same Rust code through wasm, so the server tree and the circuit cannot
    drift apart.
- The key commitment is no longer a public input; the server never checked it.
- UV is enforced in-circuit (the Noir circuit checks no flags). BS is not checked.

## Layout

| Path | What |
|---|---|
| `core/src/circuit.rs` | `PopCircuit` (bellpepper R1CS, about 260K constraints) |
| `core/src/gadgets.rs` | base64url, one-hot selection, digest→BigNat |
| `core/src/poseidon.rs` | native and in-circuit Poseidon |
| `core/src/vendor/` | ECDSA-P256, P-256 point ops, BigNat and variable-length SHA-256 from [sirosfoundation/zk-cred-vega](https://github.com/sirosfoundation/zk-cred-vega) (BSD-2). That code is unaudited. |
| `core/src/api.rs` | input parsing, setup, prove, verify |
| `wasm/` | wasm-bindgen API: `initProver`, `prove`, `initVerifier`, `verify`, `commitment`, `merkleNode`, `expectedPublicValues` |
| `patches/` | applied to the pinned vega-prover (`web-time` instead of `std::time::Instant`, which panics in browsers) |

## Build and test

```sh
npm run build:vega                          # fetch + patch vega-prover, build pkg/node and pkg/web
cd vega/core && cargo test --release        # circuit positive/negative tests, prove/verify roundtrip
npm run test:vega                           # merkle.js tree ↔ circuit root, Node wasm prove/verify
vega/bench/compare.sh 5                     # native Noir (nargo + bb) vs Vega, same assertion
open http://localhost:3000/bench.html       # in-browser comparison (keep the tab in front)
```

Setup is transparent and deterministic. Prover and verifier each derive their key from the circuit
at startup, so no key files are shipped. The serialized keys would be about 69 MB each, or 3.9 MB
gzipped for the prover key.

## Results (Apple Silicon, 2026-10-01)

All runs prove the same signed assertion.

| | Noir / UltraHonk | Vega |
|---|---|---|
| Native prove, all cores | ~500 ms (+110 ms witness) | ~110 ms |
| Native prove, 1 thread | ~2.2 s | ~245 ms |
| Native verify | ~25 ms | ~25 ms |
| Node wasm, 1 thread: setup / prove / verify | — | 0.8 s / 1.0 s / 0.2 s |
| Proof size | 14.6 KB | 78 KB |
| Verifier memory (Node) | — | ~470 MB RSS |

Notes:

- Noir native numbers come from the `bb` CLI, so they include process start-up and loading.
- Measured in Chrome from a background tab: setup 4.1 s, prove 4.7 s. Background tabs are
  throttled about 3.5× (a plain JS loop runs 3.5× slower than in Node), so expect roughly 1–1.5 s
  in a foreground tab.
- No browser Noir number yet. The committed circuit was compiled with nargo 1.0.0-beta.21, but the
  widget uses `noir_js` 1.0.0-beta.5 / bb.js 0.72, which can't deserialize it ("Failed to
  deserialize circuit"). This was already the case before the Vega work.
- Vega's prep-state reuse makes re-proving the *same* witness about 40% faster. It doesn't help a
  new assertion, because the ECDSA/Poseidon witness changes completely.

## Caveats

- vega-prover is v0.1.0 and unaudited. The vendored gadgets are experimental and unaudited too:
  their own review found two critical ECDSA bugs, now fixed. Get the circuit reviewed before it
  protects real users.
- The Poseidon parameters skip the reference script's invariant-subspace check on the MDS matrix.
- The Noir path's proofs fail the server's root check, because its tree is BN254 Poseidon2.
- The verifier key takes about 470 MB in Node on Fly's 1 GB VM.
