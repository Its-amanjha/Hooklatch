import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { finishQualification, validateCorpus, validateCacheReceipt } from './provider-conformance.mjs';

const corpus = JSON.parse(readFileSync(new URL('../../tests/conformance/phase10-provider-cases.json', import.meta.url)));

validateCorpus(corpus);

for (const mutation of [
  (copy) => { copy.cases[0].timestampConfig.mode = 'unreviewed'; },
  (copy) => { copy.cases[0].timestampConfig.unit = 'furlongs'; },
  (copy) => { copy.cases[0].headers['webhook-id'] = 42; },
  (copy) => { copy.cases.find((row) => row.id.includes('stale')).timestampConfig.relativeOffset = 0; },
  (copy) => { copy.cases.pop(); copy.casesCount -= 1; },
]) {
  const copy = structuredClone(corpus);

  mutation(copy);
  assert.throws(() => validateCorpus(copy), /Corpus validation/);
}

assert.throws(() => validateCacheReceipt({ schemaVersion: 1 }, {}), /lock|receipt/i);

const receipt = JSON.parse(readFileSync(new URL('../../notes/phase-10/gemini-sdk-cache/receipt.json', import.meta.url)));
const lock = JSON.parse(readFileSync(new URL('../../notes/phase-10/gemini-sdk-cache/package-lock.json', import.meta.url)));

validateCacheReceipt(receipt, lock);

const changedLock = structuredClone(lock);

changedLock.packages['node_modules/standardwebhooks'].version = '0.0.0';

assert.throws(() => validateCacheReceipt(receipt, changedLock), /graph mismatch/);

const events = [];

const snapshot = () => {
  events.push('integrity');

  return { ok: true };
};

await finishQualification({
  cleanup: () => events.push('cleanup'),
  integrity: snapshot,
  publish: () => events.push('publish'),
});

assert.deepEqual(events, ['cleanup', 'integrity', 'publish']);

for (const failure of ['cleanup', 'integrity']) {
  let published = false;

  await assert.rejects(finishQualification({
    cleanup: () => { if (failure === 'cleanup') throw new Error('cleanup failed'); },
    integrity: () => ({ ok: failure !== 'integrity' }),
    publish: () => { published = true; },
  }), /cleanup|integrity/i);
  assert.equal(published, false);
}

console.log('PASS: frozen corpus mutations, missing provenance, cleanup/integrity failures and publication ordering');
