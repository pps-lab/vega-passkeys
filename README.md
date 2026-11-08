# Vega passkey prover

A zero-knowledge proof that the holder of a registered passkey signed a WebAuthn challenge,
built on [microsoft/vega-prover](https://github.com/microsoft/vega-prover). Vega is Spartan with
Hyrax commitments over the T-256 curve. T-256's scalar field equals P-256's base field, so the
WebAuthn ECDSA-P256 check is native arithmetic in the circuit rather than emulated.

This repository is the single source for the Vega prover. Two projects use it as a git submodule
mounted at `vega/`:

- **proof-of-person** (verena.se): the widget's prover and the server's verifier (combined proof,
  single-threaded wasm), and the iOS app's on-device prover (`ffi/`).
- **zk-passkeys**: the browser benchmark (`browser-prover/`, split proof, multithreaded wasm) and
  the paper tables. Its Noir circuits are the reference implementation Vega is compared against.

## Statement

Everything below is private except the challenge and the root.

1. `clientDataJSON` is `{"type":"webauthn.get","challenge":"` ‖ `base64url(challenge)` ‖ `"` ‖ …,
   with the closing quote inside its real length. WebAuthn fixes the member order of the client
   data serialization, so the prefix is a constant and the challenge always starts at byte 36.
2. The signed message is `authenticatorData ‖ SHA-256(clientDataJSON)`. The hash is placed using
   the same one-hot length wires that the SHA-256 gadget hashes with. The authenticatorData flags
   byte must have UP (`0x01`) and UV (`0x04`) set.
3. ECDSA-P256 verifies over `SHA-256(message)` under the private key `(qx, qy)`.
4. `commitment(qx, qy)` is a leaf of a Merkle tree with the public root. The depth is the path
   length and is fixed at setup; the deployment uses 20.

It comes in two forms (`core/src/circuit.rs`):

| | Circuit | Public values | Constraints (depth 20) |
|---|---|---|---|
| Combined | `PopCircuit`: 1–4 | `[challenge_hi, challenge_lo, merkle_root]` | 280,811 |
| Split, signature | `SigCircuit`: 1–3 and the link | `[challenge_hi, challenge_lo, link]` | 275,260 |
| Split, accumulator | `AccCircuit`: 4 for the leaf inside the link | `[link, merkle_root]` | 6,131 |

The split pair mirrors the Noir signature + accumulator circuits. The halves are joined by
`link = H_link(commitment(qx, qy), blind)` with a fresh random `blind`, which hides the leaf. A
verifier accepts the pair if both proofs verify and their `link` values are equal. The signature
half doesn't depend on the tree, so it can be proven while the Merkle path is still being fetched.
Each Vega proof carries a large fixed overhead, so the pair is about 150 KB, against 80 KB for the
combined proof.

Differences from the Noir circuits:

- Poseidon runs over the P-256 base field, with t = 3, an x⁷ S-box, R_F = 8 and R_P = 48. BN254
  Poseidon2 isn't native here, and x⁵ isn't a permutation on this field.
  - `core/scripts/poseidon_params.py` generates the constants. It reproduces the circomlib BN254
    constants exactly.
  - Domain tags separate commitments, nodes and links.
  - proof-of-person's `merkle.js` uses the same Rust code through wasm, so the server tree and the
    circuit can't drift apart.
- The key commitment is not a public input in the combined proof.
- The `webauthn.get` prefix and the exact challenge value are enforced; the Noir circuits accept
  the challenge at any private offset. UP and UV are enforced in-circuit (the Noir circuits check
  no flags). BS is not checked.

## Layout

| Path | What |
|---|---|
| `core/src/circuit.rs` | `PopCircuit`, `SigCircuit`, `AccCircuit` (bellpepper R1CS) |
| `core/src/gadgets.rs` | base64url, one-hot selection, digest→BigNat |
| `core/src/poseidon.rs` | native and in-circuit Poseidon |
| `core/src/vendor/` | ECDSA-P256, P-256 point ops, BigNat and variable-length SHA-256 from [sirosfoundation/zk-cred-vega](https://github.com/sirosfoundation/zk-cred-vega) (BSD-2). That code is unaudited. |
| `core/src/api.rs` | input parsing, setup, prove, verify, for both forms |
| `core/examples/` | `bench_split` (native benchmark), `bench_native`, `vk_digest` (circuit fingerprint), `gen_vector`, `keyinfo` |
| `wasm/` | wasm-bindgen API. Combined: `initProver`, `prove`, `initVerifier`, `verify`. Split: `initSignatureProver`, `proveSignature`, `initAccumulatorProver`, `proveAccumulator`. Helpers: `commitment`, `merkleNode`, `expectedPublicValues`. Feature `threads` adds `initThreadPool`. |
| `ffi/` | UniFFI Swift bindings and the iOS build (see `ffi/IOS_INTEGRATION.md`) |
| `patches/` | applied to the pinned vega-prover (`web-time` instead of `std::time::Instant`, which panics in browsers) |

## Build and test

```sh
./scripts/fetch-vega-prover.sh                     # pinned vega-prover + patches into third_party/
cd core && cargo test --release                    # circuit tests (both forms, several depths), prove/verify roundtrips
cargo run --release --example vk_digest            # combined-circuit fingerprint at depth 20 (see below)
cargo run --release --example bench_split -- 10 > native.json   # native setup/prove/verify per depth
```

The wasm builds are driven by the projects that use them (proof-of-person: `npm run build:vega`;
zk-passkeys: `browser-prover`'s `npm run build:vega`):

- **Single-threaded** (default): `wasm-pack build --release --target web|nodejs` in `wasm/`.
- **Multithreaded** (`--features threads`): rayon over a `wasm-bindgen-rayon` worker pool. Needs
  nightly Rust with `rust-src` (`-Z build-std`), atomics plus shared, imported memory, the TLS
  exports, and a cross-origin-isolated page. See `build:vega-mt` in zk-passkeys'
  `browser-prover/package.json` for the exact flags.

Setup is transparent and deterministic. Prover and verifier each derive their key from the circuit
at startup, so no key files are shipped. The serialized combined keys would be about 69 MB each,
or 3.9 MB gzipped for the prover key.

**Changing the deployed circuit.** Any change to `PopCircuit`'s constraints changes verena.se's
keys, and the server, widget and iOS app must then update together. `vk_digest` at depth 20 must
print `[85, 242, 198, 120, 90, 190, 145, 207, …]` unless that is intended.

## Results (Apple M5 Pro)

Native (`bench_split`, all cores, depth 20): combined 146 ms prove / 25 ms verify; signature half
125 / 24 ms; accumulator half 39 / 15 ms. Browser and per-depth results are in zk-passkeys
(`browser-prover/README.md`, `scripts/plots/`).

## Caveats

- vega-prover is v0.1.0 and unaudited. The vendored gadgets are experimental and unaudited too:
  their own review found two critical ECDSA bugs, now fixed. Get the circuit reviewed before it
  protects real users.
- The Poseidon parameters skip the reference script's invariant-subspace check on the MDS matrix.
- The verifier key takes about 470 MB in Node on Fly's 1 GB VM.
- Multithreading in wasm stops paying off early (at depth 20 in Chrome: 946 ms on 1 thread,
  383 ms on 8), so most of the remaining prover time is serial.
