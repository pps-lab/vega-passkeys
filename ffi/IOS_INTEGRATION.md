# On-device ZK proof (Path B) — iOS integration

Goal: the app proves "a registered key signed this challenge" on-device and submits the proof. The
server then authenticates the session without learning which credential signed. This replaces the
Path A POST (`/verify/appattest`); signing is unchanged.

## 1. Add the package

The prover is a prebuilt local Swift Package, built in the proof-of-person repo:

```
~/Projects/proofofperson/proof-of-person/vega/ffi/out/PopVega
```

- Add it with File → Add Package Dependencies… → Add Local…. Link the `PopVega` library to **both**
  the app target and the App Clip target.
- No extra linker flags are needed.
- It contains static arm64 libraries for device and Apple-silicon simulators. Intel simulators are
  not supported.
- Minimum deployment target is iOS 16.
- About 6 MB is added to the linked binary.
- To rebuild after prover changes: `vega/ffi/build-ios.sh` in the proof-of-person repo. It needs
  Rust and `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.

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
  var pubKeyX: String             // /v1/pubkey `x` (already base64url, pass through)
  var pubKeyY: String             // /v1/pubkey `y`
  var challenge: String           // the challenge string from /verify/start, as-is (base64url of 32 bytes)
  var pathElements: [String]      // /v1/pubkey `merkle.pathElements` (20 hex strings)
  var pathIndices: [UInt32]       // /v1/pubkey `merkle.pathIndices` (20 × 0/1)
}
```

## 3. Lifecycle

- Wrap the prover in an `actor` (e.g. `ProofService`) that lazily creates **one** `VegaProver` and
  keeps it for the process lifetime. `VegaProver` is thread-safe and `Sendable`.
- Start creating it in a background task as soon as an auth flow begins: App Clip invocation, or
  the auth screen appearing. Setup then overlaps with the network calls and Face ID. Never create
  it on the main thread.
- Call `prove` from a detached task (`Task.detached(priority: .userInitiated)`), not the main actor.

## 4. Auth flow (replaces Path A's last step)

Steps 1–3 are unchanged: create the session, `POST /widget/:id/verify/start` → `challenge`, then
`signAssertion(challenge:)` → `(authData, clientData, signatureDER)`. Then:

```
4. GET /v1/pubkey/<credentialId>
     -> { x, y, commitment, merkle: { root, pathElements, pathIndices, ... } }
5. let inputs = ProverInputs(
       authenticatorData: base64url(authData),
       clientDataJson:    base64url(clientData),
       signature:         base64url(signatureDER),
       pubKeyX: resp.x, pubKeyY: resp.y,
       challenge: challenge,
       pathElements: resp.merkle.pathElements,
       pathIndices:  resp.merkle.pathIndices.map(UInt32.init))
   let out = try await proofService.prove(inputs)
6. POST /widget/:id/verify/appattest/proof
     Content-Type: application/json
     { "proofType": "zk-webauthn-v2",
       "proof": out.proof.base64EncodedString(),     // standard base64 (not url-safe) — ~107 KB
       "clientProofTimeMs": out.proveMs }
     -> { verified: true, appattest: true, proof: { token, expiresAt } }   // same as Path A
```

`base64url(_:)` is standard base64 with `+`→`-`, `/`→`_`, and `=` padding stripped. The existing
Path A code already has one.

## 5. Constraints and errors

- The circuit limits are authData 37–128 bytes and clientData ≤ 256 bytes. The current synthetic
  37-byte authData and `{"challenge":"<challenge>"}` clientData fit.
- The challenge must base64url-decode to exactly 32 bytes and appear verbatim in clientData.
  Anything else throws `InvalidInput`.
- Don't call `prove` with stale data. Fetch `/v1/pubkey` after `verify/start`, because the root
  must match the server's tree at verification time.
- Handle server responses:
  - 400 `Merkle root mismatch`: the tree changed between fetch and submit. Refetch and re-prove
    once.
  - 400 `Challenge mismatch` / `Session expired`: restart the flow.
- During rollout, keep Path A behind a debug flag as a fallback. Don't fall back silently in
  production: Path A reveals which credential authenticated.

## 6. Verify and measure

- On a real device, log `prover.setupMs()` and `out.proveMs`. Watch the Xcode memory gauge during
  setup, especially in the App Clip. Report the numbers together with the device model.
- The server logs `Vega proof verified in …ms (client proof generation: …ms)` per proof.
- A self-contained check: the proof-of-person repo's `vega/core/tests/vectors/fixture.json` is a
  valid input set. Proving it must give `publicValues[2] == fixture.root`.
