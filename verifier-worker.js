// Vega verifier in a worker thread. Deriving the verifier key takes seconds (tens of seconds on
// a shared CPU) and each verify is CPU-bound, so neither may run on the server's event loop.
// Protocol: parent → { id, proof: Uint8Array }; worker → { ready, ms } once, then
// { id, ok, publicValues | error }. Messages sent before the key is ready queue up.
const { parentPort } = require('worker_threads');
const vega = require('./pkg/node/pop_vega.js');

const start = Date.now();
vega.initVerifier();
parentPort.postMessage({ ready: true, ms: Date.now() - start });

parentPort.on('message', ({ id, proof }) => {
  try {
    parentPort.postMessage({ id, ok: true, publicValues: vega.verify(proof) });
  } catch (e) {
    parentPort.postMessage({ id, ok: false, error: e && e.message ? e.message : String(e) });
  }
});
