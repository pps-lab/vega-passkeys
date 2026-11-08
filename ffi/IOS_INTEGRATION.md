# On-device ZK proof (Path B) — iOS integration

Goal: the app proves "a registered key signed this challenge" on-device and submits the proof. The
server then authenticates the session without learning which credential signed. This is the only iOS
auth path (the server-verified `/verify/appattest` endpoint has been removed).

## 1. Build setup

The app lives in this repo at `ios/`. `ios/Verena.xcodeproj` has a `PopVega` static-library target
that both the app and the App Clip depend on. Its first build phase runs `vega/ffi/build-xcode.sh`:
cargo builds the prover for the platform being built and UniFFI generates the Swift bindings into
`$BUILT_PRODUCTS_DIR/PopVegaFFI/`, compiled as module `PopVega`. Prover changes are picked up on the
next Xcode build. A build with nothing changed costs about 2 s.

- Needs Rust and `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
- Static arm64 libraries only: device and Apple-silicon simulators. Intel simulators are not supported.
- About 6 MB is added to the linked binary.
- `vega/ffi/build-ios.sh` still builds a standalone `PopVega` Swift Package (`vega/ffi/out/PopVega`)
  for use outside this repo.

## 2. API

```swift
import PopVega

let prover = try VegaProver()                 // setup: ~0.4 s on M-series, a few hundred MB; do it ONCE
let out = try prover.prove(inputs: inputs)    // ~0.25 s on M-series; CPU-bound, all cores
// out.proof: Data, out.publicValues: [String], out.proveMs: UInt64; prover.setupMs()
// throws VegaError.InvalidInput(msg:) or VegaError.Prover(msg:)
```

```swift
public struct ProverInputs {
  var authenticatorData: String   // base64url (no padding) of the signed authData, 37...128 bytes
  var clientDataJson: String      // base64url of the signed clientData, ≤ 256 bytes, must contain the challenge string
  var signature: String           // base64url of the DER signature from SecKeyCreateSignature
  var pubKeyX: String             // `x` from the /v1/pubkeys entry (already base64url, pass through)
  var pubKeyY: String             // `y` from the /v1/pubkeys entry
  var challenge: String           // the challenge string from /verify/start, as-is (base64url of 32 bytes)
  var pathElements: [String]      // read from /v1/pubkeys `levels` (20 hex strings), see step 4
  var pathIndices: [UInt32]       // (index >> i) & 1 (20 × 0/1)
}
```

## 3. Lifecycle

- Wrap the prover in an `actor` (e.g. `ProofService`) that lazily creates **one** `VegaProver` and
  keeps it for the process lifetime. `VegaProver` is thread-safe and `Sendable`.
- Start creating it in a background task as soon as an auth flow begins: App Clip invocation, or
  the auth screen appearing. Setup then overlaps with the network calls and Face ID. Never create
  it on the main thread.
- Call `prove` from a detached task (`Task.detached(priority: .userInitiated)`), not the main actor.

## 4. Auth flow

Steps 1–3 are unchanged: create the session, `POST /widget/:id/verify/start` → `challenge`, then
`signAssertion(challenge:)` → `(authData, clientData, signatureDER)`. Then:

```
4. GET /v1/pubkeys
     -> { root, depth, zeros: [hex × 21], keys: [[credentialId, x, y], ...], levels: [[hex, ...] × 20] }
   let index = keys.firstIndex { $0[0] == credentialId }   // x, y = keys[index][1], keys[index][2]
   for i in 0..<depth:  pathElements[i] = levels[i][(index >> i) ^ 1] ?? zeros[i]   // nil past the end
                        pathIndices[i]  = (index >> i) & 1
5. let inputs = ProverInputs(
       authenticatorData: base64url(authData),
       clientDataJson:    base64url(clientData),
       signature:         base64url(signatureDER),
       pubKeyX: x, pubKeyY: y,
       challenge: challenge,
       pathElements: pathElements,
       pathIndices:  pathIndices)
   let out = try await proofService.prove(inputs)
6. POST /widget/:id/verify/appattest/proof
     Content-Type: application/json
     { "proofType": "zk-webauthn-v2",
       "proof": out.proof.base64EncodedString(),     // standard base64 (not url-safe) — ~107 KB
       "clientProofTimeMs": out.proveMs }
     -> { verified: true, appattest: true, proof: { token, expiresAt } }
```

`base64url(_:)` is standard base64 with `+`→`-`, `/`→`_`, and `=` padding stripped.

Step 4 downloads every registered key and selects ours on the device, so the server can't tell which
credential is about to prove (a stand-in for PIR). No hashing is needed: the tree levels are served.
The older `GET /v1/pubkey/<credentialId>` (returns `x`, `y` and `merkle.pathElements/pathIndices`
directly) still works but reveals the credential to the server; switch away from it.

## 5. Constraints and errors

- The circuit limits are authData 37–128 bytes and clientData ≤ 256 bytes. The current synthetic
  37-byte authData and `{"type":"webauthn.get","challenge":"<challenge>"}` clientData fit.
- authData byte 32 (flags) must have UP (`0x01`) and UV (`0x04`) set; the app uses `0x05`.
  Otherwise `prove` throws `InvalidInput`.
- The challenge must base64url-decode to exactly 32 bytes, and clientData must start with
  `{"type":"webauthn.get","challenge":"` followed by exactly the challenge string and a closing
  quote (the WebAuthn client-data serialization). Anything else throws `InvalidInput`.
- Don't call `prove` with stale data. Fetch `/v1/pubkeys` after `verify/start`, because the root
  must match the server's tree at verification time.
- Handle server responses:
  - 400 `Merkle root mismatch`: the tree changed between fetch and submit. Refetch and re-prove
    once.
  - 400 `Challenge mismatch` / `Session expired`: restart the flow.

## 6. Verify and measure

- On a real device, log `prover.setupMs()` and `out.proveMs`. Watch the Xcode memory gauge during
  setup, especially in the App Clip. Report the numbers together with the device model.
- The server logs `Vega proof verified in …ms (client proof generation: …ms)` per proof.
- A self-contained check: the proof-of-person repo's `vega/core/tests/vectors/fixture.json` is a
  valid input set. Proving it must give `publicValues[2] == fixture.root`.
