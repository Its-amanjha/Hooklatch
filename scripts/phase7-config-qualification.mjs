#!/usr/bin/env node
/** Standalone Phase7 tooling. Selftests are harness evidence, never provider qualification. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fork, spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { executeSdkCase } from './phase7-config/worker.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const WORKSPACE_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const WORKER_SOURCE_PATH = path.join(WORKSPACE_ROOT, 'scripts/phase7-config/worker.mjs');

const EXPECTED_19_PROVIDERS = ['stripe', 'github', 'shopify', 'standard-webhooks',
  'clerk', 'svix', 'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana', 'polar', 'linear'];

const REQUIRED_CLI_FLAGS = ['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode'];
const PINNED_GRAFANA_COLON_DIGEST = 'f6cdebb3d45820628f1a70ffe07a4074d9127cc57f20fe59a0010391c2ab5714';
const APIS = ['verify', 'verifyRequest', 'createVerifier'];
const RUNTIMES = ['node', 'worker'];
const MAX_REPORT_BYTES = 131072;

function isObject(value) {
  return Object.prototype.toString.call(value) === '[object Object]';
}

function isCallable(value) {
  return Object.prototype.toString.call(value) === '[object Function]'
    || Object.prototype.toString.call(value) === '[object AsyncFunction]';
}

function within(root, target) {
  const relative = path.relative(root, target);

  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function requireCheck(condition, category) {
  if (!condition) throw new Error(category);
}

async function withTimeout(promise, ms) {
  let timer;

  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('operation-timeout')), ms);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

function buildExecutableCaseCatalogue() {
  const cases = new Map();

  const grafanaSecret = 'CANARY_SECRET_GRAFANA_99';

  const grafanaBody = '{"status":"firing","alerts":[{"rule":"cpu_high"}]}';

  const grafanaRawBody = Buffer.from(grafanaBody, 'utf8');

  const grafanaBodySig = crypto.createHmac('sha256', grafanaSecret).update(grafanaBody).digest('hex');

  // 1. Grafana Body Valid
  cases.set('grafana-body-valid', {
    id: 'grafana-body-valid',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body' },
    },
    headers: { 'x-grafana-alerting-signature': grafanaBodySig },
    rawBody: grafanaRawBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
  });

  // 2. Grafana Body Invalid Signature
  cases.set('grafana-body-invalid-sig', {
    id: 'grafana-body-invalid-sig',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body' },
    },
    headers: { 'x-grafana-alerting-signature': '0'.repeat(64) },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 3. Grafana Body Custom Header
  cases.set('grafana-body-custom-header', {
    id: 'grafana-body-custom-header',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body', signatureHeader: 'x-custom-sig' },
    },
    headers: { 'x-custom-sig': grafanaBodySig },
    rawBody: grafanaRawBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
  });

  // 4. Grafana Body Reserved Header (rejected)
  cases.set('grafana-body-reserved-header', {
    id: 'grafana-body-reserved-header',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body', signatureHeader: 'authorization' },
    },
    headers: { authorization: grafanaBodySig },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      expectedError: 'invalid-options',
    },
  });

  // 5. Grafana Body With Timestamp Header Forbidden
  cases.set('grafana-body-with-timestamp-header', {
    id: 'grafana-body-with-timestamp-header',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body', timestampHeader: 'x-ts' },
    },
    headers: { 'x-grafana-alerting-signature': grafanaBodySig, 'x-ts': '1700000000' },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      expectedError: 'invalid-options',
    },
  });

  // 6. Grafana Body Default Rescue Rejection
  cases.set('grafana-body-rescue-rejection', {
    id: 'grafana-body-rescue-rejection',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'body', signatureHeader: 'x-custom-sig' },
    },
    headers: { 'x-grafana-alerting-signature': grafanaBodySig },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'missing-signature',
    },
  });

  // 7. Grafana Timestamped Valid (colon separator)
  const grafanaTimestamp = '1700000000';

  const grafanaTimestampedPayload = `${grafanaTimestamp}:${grafanaBody}`;

  const grafanaTimestampedSig = crypto
    .createHmac('sha256', grafanaSecret)
    .update(grafanaTimestampedPayload)
    .digest('hex');

  cases.set('grafana-timestamped-valid', {
    id: 'grafana-timestamped-valid',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1700000050,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: 1700000000, authenticatedFields: ['timestamp'] },
    },
  });

  // 8. Grafana Timestamped Inclusive Past 300s
  cases.set('grafana-timestamped-inclusive-past-300', {
    id: 'grafana-timestamped-inclusive-past-300',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1700000300,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: { ok: true },
  });

  // 9. Grafana Timestamped Inclusive Future 300s
  cases.set('grafana-timestamped-inclusive-future-300', {
    id: 'grafana-timestamped-inclusive-future-300',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1699999700,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: { ok: true },
  });

  // 10. Grafana Timestamped Expired Past 301s
  cases.set('grafana-timestamped-expired-past-301', {
    id: 'grafana-timestamped-expired-past-301',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1700000301,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-expired',
    },
  });

  // 11. Grafana Timestamped Future 301s
  cases.set('grafana-timestamped-future-301', {
    id: 'grafana-timestamped-future-301',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1699999699,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-future',
    },
  });

  // 12. Grafana Timestamped Zero Tolerance Success
  cases.set('grafana-timestamped-zero-tolerance-success', {
    id: 'grafana-timestamped-zero-tolerance-success',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      toleranceSeconds: 0,
      now: 1700000000,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: { ok: true },
  });

  // 13. Grafana Timestamped Zero Tolerance Past Reject
  cases.set('grafana-timestamped-zero-tolerance-past-reject', {
    id: 'grafana-timestamped-zero-tolerance-past-reject',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      toleranceSeconds: 0,
      now: 1700000001,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-expired',
    },
  });

  // 14. Grafana Timestamped Zero Tolerance Future Reject
  cases.set('grafana-timestamped-zero-tolerance-future-reject', {
    id: 'grafana-timestamped-zero-tolerance-future-reject',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      toleranceSeconds: 0,
      now: 1699999999,
    },
    headers: {
      'x-grafana-alerting-signature': grafanaTimestampedSig,
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-future',
    },
  });

  // 15. Grafana Timestamped Bad MAC Before Stale (MAC check precedes freshness)
  cases.set('grafana-timestamped-bad-mac-before-stale', {
    id: 'grafana-timestamped-bad-mac-before-stale',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
      now: 1700000301,
    },
    headers: {
      'x-grafana-alerting-signature': '0'.repeat(64),
      'x-grafana-timestamp': grafanaTimestamp,
    },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 16. Grafana Collision Headers
  cases.set('grafana-collision-headers', {
    id: 'grafana-collision-headers',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', signatureHeader: 'x-sig', timestampHeader: 'X-SIG' },
    },
    headers: { 'x-sig': grafanaTimestampedSig },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      expectedError: 'invalid-options',
    },
  });

  // 17. Grafana Timestamped Missing Timestamp Header
  cases.set('grafana-timestamped-missing-timestamp', {
    id: 'grafana-timestamped-missing-timestamp',
    provider: 'grafana',
    options: {
      provider: 'grafana',
      secrets: [grafanaSecret],
      providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
    },
    headers: { 'x-grafana-alerting-signature': grafanaTimestampedSig },
    rawBody: grafanaRawBody,
    expected: {
      ok: false,
      reason: 'missing-timestamp',
    },
  });

  // 18. Polar Current Valid
  const polarRawKey = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');

  const polarSecretCurrent = `whsec_${polarRawKey.toString('base64')}`;

  const polarId = 'msg_polar_123';

  const polarTimestamp = '1700000000';

  const polarBody = '{"type":"order.created"}';

  const polarRawBody = Buffer.from(polarBody, 'utf8');

  const polarPayload = `${polarId}.${polarTimestamp}.${polarBody}`;

  const polarCurrentSig = crypto.createHmac('sha256', polarRawKey).update(polarPayload).digest('base64');

  cases.set('polar-current-valid', {
    id: 'polar-current-valid',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1700000020,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: polarId, timestamp: 1700000000, authenticatedFields: ['eventId', 'timestamp'] },
    },
  });

  // 19. Polar Current Inclusive Past 300s
  cases.set('polar-current-inclusive-past-300', {
    id: 'polar-current-inclusive-past-300',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1700000300,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: { ok: true },
  });

  // 20. Polar Current Inclusive Future 300s
  cases.set('polar-current-inclusive-future-300', {
    id: 'polar-current-inclusive-future-300',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1699999700,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: { ok: true },
  });

  // 21. Polar Current Expired Past 301s
  cases.set('polar-current-expired-past-301', {
    id: 'polar-current-expired-past-301',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1700000301,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-expired',
    },
  });

  // 22. Polar Current Future 301s
  cases.set('polar-current-future-301', {
    id: 'polar-current-future-301',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1699999699,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-future',
    },
  });

  // 23. Polar Current Zero Tolerance Success
  cases.set('polar-current-zero-tolerance-success', {
    id: 'polar-current-zero-tolerance-success',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      toleranceSeconds: 0,
      now: 1700000000,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: { ok: true },
  });

  // 24. Polar Current Zero Tolerance Past Reject
  cases.set('polar-current-zero-tolerance-past-reject', {
    id: 'polar-current-zero-tolerance-past-reject',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      toleranceSeconds: 0,
      now: 1700000001,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-expired',
    },
  });

  // 25. Polar Current Zero Tolerance Future Reject
  cases.set('polar-current-zero-tolerance-future-reject', {
    id: 'polar-current-zero-tolerance-future-reject',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      toleranceSeconds: 0,
      now: 1699999999,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      reason: 'timestamp-future',
    },
  });

  // 26. Polar Current Bad MAC Before Stale
  cases.set('polar-current-bad-mac-before-stale', {
    id: 'polar-current-bad-mac-before-stale',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarSecretCurrent],
      providerOptions: { secretMode: 'current' },
      now: 1700000301,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${crypto.createHmac('sha256', 'independent-wrong-key').update(polarPayload).digest('base64')}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 27. Polar Current Invalid Base64 Secret
  cases.set('polar-current-invalid-secret', {
    id: 'polar-current-invalid-secret',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: ['whsec_not_valid_base64_!@#$'],
      providerOptions: { secretMode: 'current' },
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      expectedError: 'invalid-secret',
    },
  });

  // 28. Polar Legacy Valid
  const polarLegacySecret = 'whsec_literal_utf8_secret_with_whsec_prefix';

  const polarLegacySig = crypto
    .createHmac('sha256', Buffer.from(polarLegacySecret, 'utf8'))
    .update(polarPayload)
    .digest('base64');

  cases.set('polar-legacy-valid', {
    id: 'polar-legacy-valid',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarLegacySecret],
      providerOptions: { secretMode: 'legacy' },
      now: 1700000020,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarLegacySig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: polarId, timestamp: 1700000000, authenticatedFields: ['eventId', 'timestamp'] },
    },
  });

  // 29. Polar Legacy No Prefix Valid
  const polarLegacyNoPrefix = 'literal_utf8_secret_without_prefix';

  const polarLegacyNoPrefixSig = crypto
    .createHmac('sha256', Buffer.from(polarLegacyNoPrefix, 'utf8'))
    .update(polarPayload)
    .digest('base64');

  cases.set('polar-legacy-no-prefix', {
    id: 'polar-legacy-no-prefix',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: [polarLegacyNoPrefix],
      providerOptions: { secretMode: 'legacy' },
      now: 1700000020,
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarLegacyNoPrefixSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: true,
    },
  });

  // 30. Polar Wrong Mode Reject (Current mode with non-base64 literal)
  cases.set('polar-wrong-mode-reject', {
    id: 'polar-wrong-mode-reject',
    provider: 'polar',
    options: {
      provider: 'polar',
      secrets: ['whsec_literal_utf8_not_valid_base64_!!!'],
      providerOptions: { secretMode: 'current' },
    },
    headers: {
      'webhook-id': polarId,
      'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${polarCurrentSig}`,
    },
    rawBody: polarRawBody,
    expected: {
      ok: false,
      expectedError: 'invalid-secret',
    },
  });

  for (const def of cases.values()) {
    if (def.expected.ok && !def.expected.identity) {
      def.expected.identity = def.provider === 'grafana'
        ? { deliveryId: null, eventId: null, timestamp: 1700000000, authenticatedFields: ['timestamp'] }
        : { deliveryId: null, eventId: polarId, timestamp: 1700000000, authenticatedFields: ['eventId', 'timestamp'] };
    }
  }

  const cloneCase = (id, baseId, scenario) => {
    const base = cases.get(baseId);
    cases.set(id, { ...base, id, scenario });
  };

  for (const [prefix, baseId] of [
    ['grafana-body', 'grafana-body-valid'], ['grafana-timestamped', 'grafana-timestamped-valid'],
    ['polar-current', 'polar-current-valid'], ['polar-legacy', 'polar-legacy-valid'],
  ]) {
    for (const scenario of ['config-snapshot', 'secret-snapshot', 'byte-snapshot']) {
      cloneCase(`${prefix}-${scenario}`, baseId, scenario);
    }
  }

  cases.set('grafana-wrong-layout', {
    ...cases.get('grafana-timestamped-valid'), id: 'grafana-wrong-layout',
    headers: { 'x-grafana-alerting-signature': grafanaBodySig, 'x-grafana-timestamp': grafanaTimestamp },
    expected: { ok: false, reason: 'invalid-signature' },
  });
  cases.set('polar-current-mac-in-legacy', {
    ...cases.get('polar-current-valid'), id: 'polar-current-mac-in-legacy',
    options: { ...cases.get('polar-current-valid').options, providerOptions: { secretMode: 'legacy' } },
    expected: { ok: false, reason: 'invalid-signature' },
  });
  cases.set('polar-legacy-mac-in-current', {
    ...cases.get('polar-current-valid'), id: 'polar-legacy-mac-in-current',
    headers: { 'webhook-id': polarId, 'webhook-timestamp': polarTimestamp,
      'webhook-signature': `v1,${crypto.createHmac('sha256', polarSecretCurrent).update(polarPayload).digest('base64')}` },
    expected: { ok: false, reason: 'invalid-signature' },
  });
  cases.set('setup-invalid-secret-before-read', {
    id: 'setup-invalid-secret-before-read', provider: 'github', scenario: 'setup-before-read',
    options: { provider: 'github', secrets: [''] }, rawBody: new Uint8Array(), headers: {},
    expected: { expectedError: 'invalid-secret' },
  });

  cases.set('setup-grafana-config-before-read', {
    id: 'setup-grafana-config-before-read', provider: 'grafana', scenario: 'setup-before-read',
    options: { provider: 'grafana', secrets: [grafanaSecret], providerOptions: { mode: 'invalid' } },
    rawBody: new Uint8Array(), headers: {}, expected: { expectedError: 'invalid-options' },
  });
  cases.set('setup-polar-config-before-read', {
    id: 'setup-polar-config-before-read', provider: 'polar', scenario: 'setup-before-read',
    options: { provider: 'polar', secrets: [polarSecretCurrent], providerOptions: { secretMode: 'invalid' } },
    rawBody: new Uint8Array(), headers: {}, expected: { expectedError: 'invalid-options' },
  });

  return cases;
}

const REQUIRED_CASE_IDS = [
  'grafana-body-valid',
  'grafana-body-invalid-sig',
  'grafana-body-custom-header',
  'grafana-body-reserved-header',
  'grafana-body-with-timestamp-header',
  'grafana-body-rescue-rejection',
  'grafana-timestamped-valid',
  'grafana-timestamped-inclusive-past-300',
  'grafana-timestamped-inclusive-future-300',
  'grafana-timestamped-expired-past-301',
  'grafana-timestamped-future-301',
  'grafana-timestamped-zero-tolerance-success',
  'grafana-timestamped-zero-tolerance-past-reject',
  'grafana-timestamped-zero-tolerance-future-reject',
  'grafana-timestamped-bad-mac-before-stale',
  'grafana-collision-headers',
  'grafana-timestamped-missing-timestamp',
  'polar-current-valid',
  'polar-current-inclusive-past-300',
  'polar-current-inclusive-future-300',
  'polar-current-expired-past-301',
  'polar-current-future-301',
  'polar-current-zero-tolerance-success',
  'polar-current-zero-tolerance-past-reject',
  'polar-current-zero-tolerance-future-reject',
  'polar-current-bad-mac-before-stale',
  'polar-current-invalid-secret',
  'polar-legacy-valid',
  'polar-legacy-no-prefix',
  'polar-wrong-mode-reject',
  'grafana-body-config-snapshot', 'grafana-body-secret-snapshot', 'grafana-body-byte-snapshot',
  'grafana-timestamped-config-snapshot', 'grafana-timestamped-secret-snapshot', 'grafana-timestamped-byte-snapshot',
  'polar-current-config-snapshot', 'polar-current-secret-snapshot', 'polar-current-byte-snapshot',
  'polar-legacy-config-snapshot', 'polar-legacy-secret-snapshot', 'polar-legacy-byte-snapshot',
  'grafana-wrong-layout', 'polar-current-mac-in-legacy', 'polar-legacy-mac-in-current',
  'setup-invalid-secret-before-read', 'setup-grafana-config-before-read', 'setup-polar-config-before-read',
];

function allowedKeys(value, keys) {
  return isObject(value) && Object.keys(value).every((key) => keys.includes(key));
}

function exactIdentity(actual, expected) {
  if (!allowedKeys(actual, ['deliveryId', 'eventId', 'timestamp', 'authenticatedFields'])) return false;

  if (actual.deliveryId !== expected.deliveryId || actual.eventId !== expected.eventId
    || actual.timestamp !== expected.timestamp || !Array.isArray(actual.authenticatedFields)) return false;

  return actual.authenticatedFields.length === expected.authenticatedFields.length
    && actual.authenticatedFields.every((field, index) => field === expected.authenticatedFields[index]);
}

function classifyVerificationResult(def, outcome) {
  const fail = (reason) => ({ pass: false, reason });

  if (!isObject(outcome)) return fail('malformed-result');

  if (outcome.isInfrastructureFailure) return fail('infrastructure-failure');

  if (def.expected.expectedError) {
    if (!allowedKeys(outcome, ['isHooklatchError', 'errorCode', 'bodyPulls', 'bodyUsed'])
      || outcome.isHooklatchError !== true || outcome.errorCode !== def.expected.expectedError) {
      return fail('setup-error-identity-or-code');
    }

    if (def.scenario === 'setup-before-read'
      && (outcome.bodyPulls !== 0 || outcome.bodyUsed !== false)) return fail('body-read-before-setup');

    return { pass: true };
  }

  if (!allowedKeys(outcome, ['ok', 'provider', 'reason', 'identity', 'bytes', 'snapshotSourceChanged'])
    || outcome.provider !== def.provider || outcome.ok !== def.expected.ok) return fail('verification-shape');

  if (!def.expected.ok) {
    return outcome.reason === def.expected.reason ? { pass: true } : fail('failure-reason');
  }

  if (outcome.reason !== undefined || !exactIdentity(outcome.identity, def.expected.identity)) return fail('identity');

  if (!Array.isArray(outcome.bytes) || outcome.bytes.length !== def.rawBody.length
    || !outcome.bytes.every((byte, index) => Number.isInteger(byte) && byte >= 0 && byte <= 255
      && byte === def.rawBody[index])) return fail('preserved-bytes');

  if (def.scenario === 'byte-snapshot' && outcome.snapshotSourceChanged !== true) return fail('mutation-not-observed');

  return { pass: true };
}

function apisFor(id) {
  return ['setup-invalid-secret-before-read', 'setup-grafana-config-before-read', 'setup-polar-config-before-read'].includes(id)
    ? ['verifyRequest'] : APIS;
}

function requiredKeys() {
  const keys = new Set();

  for (const id of REQUIRED_CASE_IDS) {
    for (const runtime of RUNTIMES) {
      for (const api of apisFor(id)) keys.add(`${id}::${runtime}::${api}`);
    }
  }

  return keys;
}

function validateBatchCoverage(catalogue, results) {
  const required = requiredKeys();
  const failures = [];

  if (catalogue.size !== REQUIRED_CASE_IDS.length
    || REQUIRED_CASE_IDS.some((id) => !catalogue.has(id))) failures.push('catalogue-inventory');

  for (const key of required) {
    if (!results.has(key)) failures.push(`missing:${key}`);
  }

  for (const [key, outcome] of results) {
    const def = catalogue.get(key.split('::')[0]);

    if (!required.has(key) || !def) failures.push('extra-result');
    else {
      const classification = classifyVerificationResult(def, outcome);

      if (!classification.pass) failures.push(`${key}:${classification.reason}`);
    }
  }

  return { valid: failures.length === 0, failures };
}

function wireCase(def, api) {
  return { options: def.options, headers: def.headers, bytes: Array.from(def.rawBody), scenario: def.scenario, api };
}

async function inspectProviderReadiness(root) {
  const missing = [];

  try {
    const providers = await import(pathToFileURL(path.join(root, 'dist/providers/index.js')).href);

    if (!Array.isArray(providers.SUPPORTED_PROVIDERS)
      || providers.SUPPORTED_PROVIDERS.length !== EXPECTED_19_PROVIDERS.length
      || EXPECTED_19_PROVIDERS.some((id, index) => providers.SUPPORTED_PROVIDERS[index] !== id)) {
      missing.push('exact-ordered-19-provider-registry');
    }

    const output = execFileSync(process.execPath, [path.join(root, 'dist/cli/index.js'), '--help'], {
      cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: MAX_REPORT_BYTES,
      windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
    });

    if (REQUIRED_CLI_FLAGS.some((flag) => !output.includes(flag))) missing.push('built-cli-flags');

    // Declarations are a readiness check, not a semantic TypeScript qualification.
    const declarations = fs.readFileSync(path.join(root, 'dist/types.d.ts'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');

    const publicTypes = fs.readFileSync(path.join(root, 'dist/index.d.ts'), 'utf8');

    if (!/\b(?:type|interface)\s+GrafanaOptions\b/.test(declarations)
      || !/\b(?:type|interface)\s+PolarOptions\b/.test(declarations)
      || !publicTypes.includes('GrafanaOptions') || !publicTypes.includes('PolarOptions')) missing.push('public-option-types');
  } catch {
    missing.push('built-artifact-readiness-error');
  }

  return { ready: missing.length === 0, missing };
}

/** Only directories allocated under the parent-owned private scratch root are removed. */
class Resources {
  constructor(root) {
    this.root = fs.realpathSync(root);
    this.directories = [];
    this.links = [];
    this.workers = new Set();
    this.errors = [];
    this.uncertain = false;
  }
  directory(prefix) {
    const created = fs.mkdtempSync(path.join(this.root, prefix));
    requireCheck(within(this.root, created), 'allocation-containment');
    this.directories.push(created);

    return created;
  }
  async dispose(runtime) {
    try {
      await withTimeout(runtime.dispose(), 5000);
      this.workers.delete(runtime);
    } catch {
      this.uncertain = true;
      this.errors.push('worker-disposal');
    }
  }
  async cleanup() {
    for (const runtime of this.workers) await this.dispose(runtime);

    for (const link of this.links) {
      try {
        requireCheck(within(this.root, link), 'link-containment');
        const stat = fs.lstatSync(link, { throwIfNoEntry: false });

        if (stat) {
          requireCheck(stat.isSymbolicLink(), 'link-identity');
          fs.unlinkSync(link);
          requireCheck(!fs.lstatSync(link, { throwIfNoEntry: false }), 'link-retained');
        }
      } catch {
        this.uncertain = true;
        this.errors.push('link-cleanup');
      }
    }

    if (!this.uncertain) {
      for (const directory of this.directories) {
        try {
          requireCheck(within(this.root, directory) && !containsLink(directory), 'directory-containment');
          fs.rmSync(directory, { recursive: true, force: true });
        } catch {
          this.errors.push('directory-cleanup');
        }
      }
    }

    return { ok: this.errors.length === 0 && !this.uncertain, retained: this.uncertain, errors: this.errors };
  }
}

function containsLink(directory) {
  const stat = fs.lstatSync(directory, { throwIfNoEntry: false });

  if (!stat) return false;

  if (stat.isSymbolicLink()) return true;

  if (!stat.isDirectory()) return false;

  return fs.readdirSync(directory).some((name) => containsLink(path.join(directory, name)));
}

async function createRuntime(resources) {
  requireCheck(process.env.ESBUILD_WORKER_THREADS === '0', 'synchronous-bundler-policy');
  const esbuild = await import('esbuild');

  // buildSync launches a synchronous one-shot child; no persistent esbuild service.
  // The owning runner child is externally bounded, including blocked synchronous work.
  const built = esbuild.buildSync({
    entryPoints: [WORKER_SOURCE_PATH], bundle: true, write: false, platform: 'neutral',
    format: 'esm', target: 'es2022', conditions: ['workerd', 'worker', 'browser'], logLevel: 'silent',
  });

  const directory = resources.directory('worker-');
  const scriptPath = path.join(directory, 'worker.mjs');
  fs.writeFileSync(scriptPath, built.outputFiles[0].text);
  const { Miniflare } = await import('miniflare');

  try {
    const runtime = new Miniflare({ modules: true, modulesRoot: directory, scriptPath,
      compatibilityDate: '2025-01-01', compatibilityFlags: [] });

    resources.workers.add(runtime);

    return runtime;
  } catch {
    resources.uncertain = true;
    throw new Error('runtime-construction');
  }
}

async function workerCase(runtime, def, api) {
  try {
    return await withTimeout((async () => {
      const response = await runtime.dispatchFetch('https://qualification.test/case', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(wireCase(def, api)),
      });

      requireCheck(response.status === 200, 'worker-http-status');
      const body = await response.text();
      requireCheck(Buffer.byteLength(body) <= MAX_REPORT_BYTES, 'worker-body-limit');

      return JSON.parse(body);
    })(), 5000);
  } catch {
    return { isInfrastructureFailure: true, errorCategory: 'worker-response' };
  }
}

async function runQualification(resources) {
  const sdk = await import(pathToFileURL(path.join(WORKSPACE_ROOT, 'dist/index.js')).href);
  requireCheck(APIS.every((api) => isCallable(sdk[api])) && isCallable(sdk.HooklatchError), 'sdk-exports');
  const catalogue = buildExecutableCaseCatalogue();
  const results = new Map();
  const runtime = await createRuntime(resources);

  for (const [id, def] of catalogue) {
    for (const api of apisFor(id)) {
      try {
        const outcome = await withTimeout(executeSdkCase(sdk, wireCase(def, api), api), 5000);
        results.set(`${id}::node::${api}`, outcome);
      } catch {
        // A timer bounds waiting, not execution. The outer process deadline owns
        // termination; retain scratch if work might still be active.
        resources.uncertain = true;
        results.set(`${id}::node::${api}`, { isInfrastructureFailure: true });
        throw new Error('node-execution-timeout');
      }

      const outcome = await workerCase(runtime, def, api);
      results.set(`${id}::worker::${api}`, outcome);

      if (outcome.isInfrastructureFailure) {
        resources.uncertain = true;
        throw new Error('worker-response-infrastructure');
      }
    }
  }

  return { ok: validateBatchCoverage(catalogue, results).valid,
    kind: 'actual-public-api-qualification', cases: catalogue.size, executions: results.size,
    validation: validateBatchCoverage(catalogue, results) };
}

function successfulOutcome(def) {
  return { ok: true, provider: def.provider, identity: def.expected.identity, bytes: Array.from(def.rawBody) };
}

async function runSelfTests(resources) {
  const controls = [];

  async function control(id, action) {
    try {
      await action();
      controls.push({ id, passed: true });
    } catch {
      controls.push({ id, passed: false, category: 'control-failed' });
    }
  }

  const catalogue = buildExecutableCaseCatalogue();
  const valid = catalogue.get('grafana-timestamped-valid');
  await control('pinned-colon-anchor', () => {
    const digest = crypto.createHmac('sha256', valid.options.secrets[0])
      .update(`1700000000:${Buffer.from(valid.rawBody).toString('utf8')}`).digest('hex');

    assert.equal(digest, PINNED_GRAFANA_COLON_DIGEST);
  });
  await control('strict-success-shape', () => {
    assert.equal(classifyVerificationResult(valid, successfulOutcome(valid)).pass, true);

    for (const field of ['provider', 'identity', 'bytes']) {
      const outcome = successfulOutcome(valid);
      delete outcome[field];
      assert.equal(classifyVerificationResult(valid, outcome).pass, false);
    }

    const outcome = successfulOutcome(valid);
    outcome.identity = { ...valid.expected.identity };
    delete outcome.identity.authenticatedFields;
    assert.equal(classifyVerificationResult(valid, outcome).pass, false);
    outcome.identity = { ...valid.expected.identity, timestamp: 0 };
    assert.equal(classifyVerificationResult(valid, outcome).pass, false);
    outcome.identity = valid.expected.identity;
    outcome.bytes[0] ^= 1;
    assert.equal(classifyVerificationResult(valid, outcome).pass, false);
  });
  await control('same-ok-reason-and-provider', () => {
    const def = catalogue.get('grafana-body-invalid-sig');
    assert.equal(classifyVerificationResult(def, { ok: false, provider: 'grafana', reason: 'missing-signature' }).pass, false);
    assert.equal(classifyVerificationResult(def, { ok: false, provider: 'polar', reason: 'invalid-signature' }).pass, false);
    assert.equal(classifyVerificationResult(def, { ok: true, provider: 'grafana' }).pass, false);
    assert.equal(classifyVerificationResult(def, { isInfrastructureFailure: true }).pass, false);
  });
  await control('setup-error-contract', () => {
    const def = catalogue.get('grafana-body-reserved-header');
    assert.equal(classifyVerificationResult(def, { error: 'invalid-options' }).pass, false);
    assert.equal(classifyVerificationResult(def, { errorCode: 'invalid-options' }).pass, false);
    assert.equal(classifyVerificationResult(def, { isHooklatchError: true, errorCode: 'invalid-secret' }).pass, false);
  });
  await control('missing-extra-and-removed-catalogue', () => {
    const results = new Map();

    for (const key of requiredKeys()) {
      const def = catalogue.get(key.split('::')[0]);
      let outcome;

      if (def.expected.expectedError) outcome = { isHooklatchError: true, errorCode: def.expected.expectedError };
      else if (def.expected.ok) outcome = successfulOutcome(def);
      else outcome = { ok: false, provider: def.provider, reason: def.expected.reason };

      if (def.scenario === 'setup-before-read') Object.assign(outcome, { bodyPulls: 0, bodyUsed: false });

      if (def.scenario === 'byte-snapshot') outcome.snapshotSourceChanged = true;
      results.set(key, outcome);
    }

    assert.equal(validateBatchCoverage(catalogue, results).valid, true);
    const removedKey = requiredKeys().values().next().value;
    const removed = results.get(removedKey);
    results.delete(removedKey);
    assert.equal(validateBatchCoverage(catalogue, results).valid, false);
    results.set(removedKey, removed);
    results.set('unexpected::node::verify', { ok: true });
    assert.equal(validateBatchCoverage(catalogue, results).valid, false);
    results.delete('unexpected::node::verify');
    const incomplete = new Map(catalogue);
    incomplete.delete('grafana-body-valid');
    assert.equal(validateBatchCoverage(incomplete, results).valid, false);
  });
  await control('comment-only-built-readiness', async () => {
    const root = resources.directory('readiness-');
    fs.mkdirSync(path.join(root, 'dist/providers'), { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), '{"type":"module"}');
    fs.writeFileSync(path.join(root, 'dist/providers/index.js'),
      `/* export const SUPPORTED_PROVIDERS = ${JSON.stringify(EXPECTED_19_PROVIDERS)}; */\nexport const SUPPORTED_PROVIDERS = [];`);
    assert.equal((await inspectProviderReadiness(root)).ready, false);
  });
  const sdk = await import(pathToFileURL(path.join(WORKSPACE_ROOT, 'dist/index.js')).href);
  const baselineBody = new Uint8Array([0, 255, 128, 123, 10, 125]);
  const baselineSecret = 'synthetic-baseline-key';

  const baseline = {
    id: 'baseline-github-control', provider: 'github', options: { provider: 'github', secrets: [baselineSecret] },
    headers: { 'x-hub-signature-256': `sha256=${crypto.createHmac('sha256', baselineSecret).update(baselineBody).digest('hex')}` },
    rawBody: baselineBody, expected: { ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } },
  };

  const runtime = await createRuntime(resources);
  const runtimeEvidence = { stage: 'dispatch', httpStatus: null, userAgent: 'not-observed', hasProcess: null, hasBuffer: null };

  await control('actual-workerd-runtime', async () => {
    const facts = await withTimeout((async () => {
      const response = await runtime.dispatchFetch('https://qualification.test/runtime');
      runtimeEvidence.stage = 'response';
      runtimeEvidence.httpStatus = response.status;
      assert.equal(response.status, 200);

      return response.json();
    })(), 5000);

    runtimeEvidence.stage = 'identity';
    runtimeEvidence.userAgent = facts.userAgent === 'Cloudflare-Workers' ? 'Cloudflare-Workers' : 'other';
    runtimeEvidence.hasProcess = facts.hasProcess;
    runtimeEvidence.hasBuffer = facts.hasBuffer;
    assert.equal(facts.userAgent, 'Cloudflare-Workers');
    assert.equal(facts.hasProcess, false);
    assert.equal(facts.hasBuffer, false);
  });
  await control('actual-baseline-sdk-six-paths', async () => {
    for (const api of APIS) {
      assert.equal(classifyVerificationResult(baseline, await executeSdkCase(sdk, wireCase(baseline, api), api)).pass, true);
      assert.equal(classifyVerificationResult(baseline, await workerCase(runtime, baseline, api)).pass, true);
    }
  });
  await control('actual-corrupt-mac-execution', async () => {
    const corrupt = { ...baseline, headers: { 'x-hub-signature-256': 'sha256=' + '0'.repeat(64) } };
    const expected = { ...corrupt, expected: { ok: false, reason: 'invalid-signature' } };

    for (const api of APIS) {
      for (const outcome of [await executeSdkCase(sdk, wireCase(corrupt, api), api), await workerCase(runtime, corrupt, api)]) {
        assert.equal(classifyVerificationResult(baseline, outcome).pass, false);
        assert.equal(classifyVerificationResult(expected, outcome).pass, true);
      }
    }
  });
  await control('actual-invalid-secret-before-body-pull', async () => {
    const def = catalogue.get('setup-invalid-secret-before-read');
    const node = await executeSdkCase(sdk, wireCase(def, 'verifyRequest'), 'verifyRequest');
    const worker = await workerCase(runtime, def, 'verifyRequest');
    assert.equal(classifyVerificationResult(def, node).pass, true);
    assert.equal(classifyVerificationResult(def, worker).pass, true);
  });
  await control('actual-baseline-secret-and-byte-snapshots', async () => {
    for (const scenario of ['secret-snapshot', 'byte-snapshot']) {
      const def = { ...baseline, scenario };

      for (const api of APIS) {
        assert.equal(classifyVerificationResult(def, await executeSdkCase(sdk, wireCase(def, api), api)).pass, true);
        assert.equal(classifyVerificationResult(def, await workerCase(runtime, def, api)).pass, true);
      }
    }
  });
  await control('dangling-junction-cleanup', () => {
    const directory = resources.directory('links-');
    const target = path.join(directory, 'target');
    const link = path.join(directory, 'link');
    fs.mkdirSync(target);
    fs.symlinkSync(target, link, 'junction');
    resources.links.push(link);
    fs.rmdirSync(target);
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true);
  });

  return { ok: controls.every((item) => item.passed), kind: 'harness-controls-on-baseline-sdk', controls,
    newProviderQualification: 'NOT-RUN', runtimeEvidence };
}

function workspaceHashes() {
  const names = execFileSync('git', ['ls-files', '-z'], {
    cwd: WORKSPACE_ROOT, encoding: 'utf8', timeout: 10000, maxBuffer: 5242880, windowsHide: true,
  }).split('\0');

  const hashes = {};

  for (const name of names) {
    if (name === '') continue;
    hashes[name] = crypto.createHash('sha256').update(fs.readFileSync(path.join(WORKSPACE_ROOT, name))).digest('hex');
  }

  return hashes;
}

function integrity(before) {
  try {
    const after = workspaceHashes();

    return { intact: Object.keys(before).length === Object.keys(after).length
      && Object.entries(before).every(([name, hash]) => after[name] === hash), files: Object.keys(before).length,
      before: crypto.createHash('sha256').update(JSON.stringify(before)).digest('hex'),
      after: crypto.createHash('sha256').update(JSON.stringify(after)).digest('hex') };
  } catch {
    return { intact: false, category: 'integrity-read' };
  }
}

/** No shell interpolation. Deadline failure retains scratch even when tree kill succeeds. */
function ownedChild(mode, root, timeoutMs) {
  return new Promise((resolve) => {
    let report;
    let bytes = 0;
    const diagnosticCategories = new Set();
    let timedOut = false;
    let closed = false;
    let fallback;

    const child = fork(SCRIPT_PATH, ['--qualification-internal', mode, root ?? ''], {
      cwd: WORKSPACE_ROOT, windowsHide: true, detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'], serialization: 'json',
      env: { ...process.env, ESBUILD_WORKER_THREADS: '0' },
    });

    const finish = (result) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      clearTimeout(fallback);
      resolve(result);
    };

    const terminate = () => {
      if (timedOut || closed) return;
      timedOut = true;

      if (process.platform === 'win32') {
        spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
          windowsHide: true, timeout: 10000, stdio: 'ignore', shell: false,
        });
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Absence is checked by close below. */ }
      }

      fallback = setTimeout(() => {
        child.unref();
        child.stdout.destroy();
        child.stderr.destroy();

        if (child.connected) child.disconnect();
        finish({ ok: false, closed: false, timedOut: true, category: 'unconfirmed-child-termination' });
      }, 5000);
    };

    const timer = setTimeout(terminate, timeoutMs);
    child.on('message', (message) => {
      // One bounded report is accepted; IPC objects never contain SDK exception text.
      if (report !== undefined || Buffer.byteLength(JSON.stringify(message)) > MAX_REPORT_BYTES) terminate();
      else report = message;
    });

    const discard = (chunk) => {
      bytes += chunk.length;
      const text = chunk.toString('utf8');

      for (const [marker, category] of [['ReferenceError', 'reference-error'], ['SyntaxError', 'syntax-error'],
        ['TypeError', 'type-error'], ['ERR_', 'node-runtime-error'], ['workerd', 'worker-runtime-output']]) {
        if (text.includes(marker)) diagnosticCategories.add(category);
      }

      if (bytes > MAX_REPORT_BYTES) terminate();
    };

    child.stdout.on('data', discard);
    child.stderr.on('data', discard);
    child.on('error', () => {
      if (child.pid) terminate();
      else finish({ ok: false, closed: true, category: 'child-startup' });
    });
    child.on('close', (code, signal) => finish({ ok: code === 0 && !timedOut && isObject(report),
      closed: true, timedOut, report, exitCode: code, signal, pid: child.pid,
      diagnosticCategories: [...diagnosticCategories], category: timedOut ? 'child-deadline' : 'child-exit' }));
  });
}

async function internalMain(mode, root) {
  if (mode === 'readiness') return inspectProviderReadiness(WORKSPACE_ROOT);
  requireCheck(root && within(fs.realpathSync(os.tmpdir()), fs.realpathSync(root)), 'scratch-containment');
  const resources = new Resources(root);
  let result;
  let cleanup;

  try {
    result = mode === 'self-test' ? await runSelfTests(resources) : await runQualification(resources);
  } catch {
    result = { ok: false, category: 'execution-failure' };
  } finally {
    cleanup = await resources.cleanup();
  }

  return { result, cleanup };
}

function usage() {
  process.stdout.write('Usage: node scripts/phase7-config-qualification.mjs [--json] [--self-test] [--help]\n'
    + 'Exit0: checks and cleanup passed;1: failure;2: usage;3: StageB not ready.\n'
    + 'Selftests exercise harness controls and the accepted baseline SDK, not new provider support.\n');
}

async function main() {
  const args = process.argv.slice(2);

  if (args.some((arg) => !['--json', '--self-test', '--help', '-h'].includes(arg))
    || new Set(args).size !== args.length) {
    usage();

    return 2;
  }

  if (args.includes('--help') || args.includes('-h')) {
    usage();

    return 0;
  }

  const before = workspaceHashes();
  const selfTest = args.includes('--self-test');
  let root;
  let child;
  let result;
  let cleanup = { ok: true, retained: false };
  let exitCode = 1;

  try {
    if (!selfTest) {
      const readiness = await ownedChild('readiness', undefined, 15000);

      if (!readiness.ok) {
        result = { status: 'FAILED', category: 'readiness-infrastructure' };
      } else if (!readiness.report.ready) {
        result = { status: 'BLOCKED', readiness: readiness.report };
        exitCode = 3;
      }
    }

    if (!result) {
      const tempBase = fs.realpathSync(os.tmpdir());
      root = fs.mkdtempSync(path.join(tempBase, 'hooklatch-phase7-runtime-'));
      requireCheck(within(tempBase, root), 'owned-root-containment');
      child = await ownedChild(selfTest ? 'self-test' : 'qualification', root, selfTest ? 120000 : 180000);
      result = child.ok ? child.report.result : { ok: false, category: child.category,
        childExitCode: child.exitCode, childSignal: child.signal, childPid: child.pid, diagnosticCategories: child.diagnosticCategories };

      if (child.ok && child.report.cleanup?.ok === true && child.report.cleanup.retained === false) {
        requireCheck(!containsLink(root), 'remaining-link');
        fs.rmSync(root, { recursive: true, force: true });
        cleanup = { ok: !fs.existsSync(root), retained: false };
      } else cleanup = { ok: false, retained: true, category: 'owned-child-or-resource-cleanup' };
      exitCode = child.ok && result.ok && cleanup.ok ? 0 : 1;
    }
  } catch {
    result = { ok: false, category: 'runner-failure' };
    cleanup = { ok: root === undefined, retained: root !== undefined };
    exitCode = 1;
  }

  const byteIntegrity = integrity(before);

  if (!byteIntegrity.intact || !cleanup.ok) exitCode = 1;

  const report = { mode: selfTest ? 'self-test' : 'qualification',
    status: exitCode === 0 ? 'PASSED' : exitCode === 3 ? 'BLOCKED' : 'FAILED',
    exitCode, result, cleanup, byteIntegrity };

  if (cleanup.retained) report.retainedScratch = root;

  if (args.includes('--json')) process.stdout.write(JSON.stringify(report) + '\n');
  else process.stdout.write(`${report.status}: exit ${exitCode}\n`);

  return exitCode;
}

if (process.argv[2] === '--qualification-internal' && isCallable(process.send)) {
  internalMain(process.argv[3], process.argv[4]).then((report) => {
    requireCheck(Buffer.byteLength(JSON.stringify(report)) <= MAX_REPORT_BYTES, 'report-limit');
    process.send(report, () => {
      process.exitCode = 0;
      process.disconnect();
    });
  }).catch(() => {
    process.send({ result: { ok: false, category: 'internal-failure' }, cleanup: { ok: false, retained: true } },
      () => {
        process.exitCode = 1;
        process.disconnect();
      });
  });
} else {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    process.stderr.write('Qualification runner infrastructure failure.\n');
    process.exitCode = 1;
  });
}
