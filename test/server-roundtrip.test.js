// Hash-consistency + roundtrip: a Merkle tree built by merkle.js (server side) must have
// the root the Vega circuit computes from a path out of that tree. Proves in Node wasm.
// Run: npm run build:vega && npm run test:vega
const assert = require('assert');
const path = require('path');
const merkle = require('../../merkle.js');
const vega = require('../pkg/node/pop_vega.js');
const fixture = require('../core/tests/vectors/fixture.json');

const b64url = (s) => Buffer.from(s, 'base64url');

(async () => {
  const x = b64url(fixture.inputs.pubKeyX);
  const y = b64url(fixture.inputs.pubKeyY);
  const ours = await merkle.computeKeyCommitment(x, y);

  // Put the fixture key at index 3 among other leaves.
  const others = [];
  for (let i = 0; i < 6; i++) others.push(vega.merkleNode('0x' + (i + 1).toString(16), '0x07'));
  const leaves = [others[0], others[1], others[2], ours, others[3], others[4], others[5]];
  const tree = await merkle.buildMerkleTree(leaves);
  const mp = merkle.getMerkleProof(tree, 3);

  const inputs = { ...fixture.inputs, pathElements: mp.pathElements, pathIndices: mp.pathIndices };
  let t = performance.now();
  const out = vega.prove(inputs);
  console.log(`prove ${(performance.now() - t).toFixed(0)}ms, proof ${out.proof.length} bytes`);

  vega.initVerifier();
  t = performance.now();
  const publics = vega.verify(out.proof);
  console.log(`verify ${(performance.now() - t).toFixed(0)}ms`);
  assert.deepStrictEqual(publics, vega.expectedPublicValues(fixture.inputs.challenge, tree.root));

  // Same proof against a different root or challenge must not match.
  const otherTree = await merkle.buildMerkleTree(leaves.slice(0, 4));
  assert.notDeepStrictEqual(publics, vega.expectedPublicValues(fixture.inputs.challenge, otherTree.root));
  assert.notDeepStrictEqual(publics, vega.expectedPublicValues('A'.repeat(43), tree.root));

  const corrupted = Buffer.from(out.proof);
  corrupted[corrupted.length >> 1] ^= 1;
  assert.throws(() => vega.verify(corrupted));

  console.log(`ok (${path.basename(__filename)})`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
