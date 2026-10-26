#!/usr/bin/env node
/**
 * Phase 10 / Big Pickle - generated handler runtime matrix.
 *
 *   node scripts/phase10/generated-handlers-runtime.mjs [--runtime current|both|node24|node22]
 *                                                       [--keep-temp]
 *   node scripts/phase10/generated-handlers-runtime.mjs --controls
 *
 * What this proves:
 *
 * - The installed CLI is packed offline from this checkout and installed into a
 *   checked OS-temp consumer. Providers come from the BUILT registry
 *   (`dist/providers/index.js`), never a shadow generation table, and must equal
 *   the frozen 21-provider order before any temp allocation.
 * - 21 providers x 4 frameworks are generated through the installed CLI
 *   (84 primary handlers; Grafana primary mode `body` is explicit) plus 8
 *   configured variants (Grafana custom timestamped and Polar legacy, x4).
 * - Every generated file runs through its real framework surface: a real Express
 *   HTTP server, a real Hono `app.fetch`, the exported Next.js `POST` with a real
 *   `Request`, and the exported Cloudflare `fetch` in real workerd (neutral
 *   esbuild bundle, empty Node compatibility flags). No framework mock, no copied
 *   template and no direct `verify()` substitution.
 * - Per primary handler: valid receipt (identity deep-equal and exact bytes where
 *   the adapter surfaces them), body-tamper rejection with the consumer callback
 *   proven not to run, and a 4097-byte body against `maxBodyBytes` 4096 that must
 *   return 413 before authentication. 84 x 3 = 252 executions per runtime.
 * - Per configured variant: valid receipt and wrong-layout/wrong-era rejection.
 *   8 x 2 = 16 executions per runtime. Matrix minimum is 268 per runtime.
 * - Signatures are re-signed at wall-clock time immediately before each request
 *   because generated templates inject no clock. Historical fixture timestamps
 *   are never replayed and no tolerance is widened or freshness-checked away.
 *   Paddle's 5 second window and WorkOS's 180 second window therefore hold for
 *   real; the signer recipes themselves are first proven byte-exact against the
 *   accepted fixture anchors for all 21 providers.
 * - Controls, not just happy paths: the Express surface mounts the real generated
 *   middleware against a wrong exported handler, a wrong secret, a malformed
 *   signature and a wrong fal account, and asserts that secret/canary values are
 *   never echoed. The receipt and registry assertions are themselves fed known-bad
 *   input, and the bounded child runner is proven to detect a real crash and a
 *   real hang. A re-run after the forced kill proves the runner still reports.
 * - Matrix PASS is printed only after dependency-junction cleanup, linked-package
 *   content integrity, tracked-file/dist integrity and temp-workspace removal succeed.
 *   A failed run retains its temp workspace for diagnosis; cleanup failure is a
 *   run failure, and no junction is ever removed recursively over its target.
 *
 * What this does NOT prove: semantic TypeScript compilation (existing gates own
 * that), HTTP response bodies beyond receipt/rejection status, or any example
 * project. Next.js and Cloudflare receipt assertions use the only fields those
 * generated templates surface (`received`, `bytes`); exactness there is proven by
 * MAC acceptance over the transmitted bytes plus the returned byte length.
 *
 * Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 BLOCKED (registry/build/runtime not the
 * reviewed 21-provider Node22/24 target). BLOCKED is never reported as a pass.
 */

import { execFileSync, spawn } from 'node:child_process';
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { EventEmitter } from 'node:events';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { build as esbuildBuild } from 'esbuild';

/* ------------------------------------------------------------------ *
 * Frozen expectations
 * ------------------------------------------------------------------ */

const OWNER = 'big-pickle';
const BASE_SHA = '4b748a2142789590de56b0f15afc6975afc54657';
const RUNTIME_MANIFEST = 'tasks/phase-10/workspace.json';
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Registry order is the reviewed 21-provider tail; this is an assertion only. */
const EXPECTED_PROVIDERS = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
  'razorpay',
  'paddle',
  'lemon-squeezy',
  'dodo-payments',
  'gitlab',
  'replicate',
  'workos',
  'sentry',
  'doppler',
  'sanity',
  'grafana',
  'polar',
  'linear',
  'vercel',
  'fal',
];

const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'];
const BODY_LIMIT = 4096;
const OVERFLOW_BYTES = 4097;
const PRIMARY_CASES_PER_HANDLER = 3;
const CONFIGURED_CASES_PER_HANDLER = 2;
const MINIMUM_EXECUTIONS_PER_RUNTIME = 268;
const COMPATIBILITY_DATE = '2026-08-06';
const CHILD_TIMEOUT_MS = 360_000;
const HANG_CONTROL_TIMEOUT_MS = 1_500;

const PRIMARY_SECRET_ENVS = {
  stripe: 'STRIPE_WEBHOOK_SECRET',
  github: 'GITHUB_WEBHOOK_SECRET',
  shopify: 'SHOPIFY_WEBHOOK_SECRET',
  'standard-webhooks': 'STANDARD_WEBHOOKS_SECRET',
  clerk: 'CLERK_WEBHOOK_SIGNING_SECRET',
  svix: 'SVIX_WEBHOOK_SECRET',
  razorpay: 'RAZORPAY_WEBHOOK_SECRET',
  paddle: 'PADDLE_WEBHOOK_SECRET',
  'lemon-squeezy': 'LEMON_SQUEEZY_WEBHOOK_SECRET',
  'dodo-payments': 'DODO_WEBHOOK_SECRET',
  gitlab: 'GITLAB_WEBHOOK_SECRET',
  replicate: 'REPLICATE_WEBHOOK_SECRET',
  workos: 'WORKOS_WEBHOOK_SECRET',
  sentry: 'SENTRY_WEBHOOK_SECRET',
  doppler: 'DOPPLER_WEBHOOK_SECRET',
  sanity: 'SANITY_WEBHOOK_SECRET',
  grafana: 'GRAFANA_WEBHOOK_SECRET',
  polar: 'POLAR_WEBHOOK_SECRET',
  linear: 'LINEAR_WEBHOOK_SECRET',
  vercel: 'VERCEL_WEBHOOK_SECRET',
  fal: 'FAL_WEBHOOK_PUBLIC_KEYS',
};

const FAL_EXPECTED_USER_ENV = 'FAL_WEBHOOK_USER_ID';

/** Standard Webhooks v1 family: canonical headers and default (current) mode. */
const STANDARD_FAMILY = {
  'standard-webhooks': { id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature' },
  clerk: { id: 'svix-id', timestamp: 'svix-timestamp', signature: 'svix-signature' },
  svix: { id: 'svix-id', timestamp: 'svix-timestamp', signature: 'svix-signature' },
  'dodo-payments': { id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature' },
  gitlab: { id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature' },
  replicate: { id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature' },
  polar: { id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature' },
};

/** Fixture anchor used to prove each signer recipe before any live request. */
const ANCHOR_CASES = {
  stripe: 'happy-path',
  github: 'reference-vector-2026-10-18',
  shopify: 'happy-path',
  'standard-webhooks': 'reference-vector-sign-works',
  clerk: 'branded-reference-vector',
  svix: 'branded-reference-vector',
  razorpay: 'signed-body-with-unsigned-event-id',
  paddle: 'published-vector-p1',
  'lemon-squeezy': 'signed-body-with-event-name-header',
  'dodo-payments': 'positive-baseline',
  gitlab: 'positive-baseline',
  replicate: 'positive-baseline',
  workos: 'positive-baseline',
  sentry: 'positive-baseline',
  doppler: 'positive-baseline',
  sanity: 'positive-baseline',
  grafana: 'positive-body-default-header',
  polar: 'positive-current-baseline',
  linear: 'positive-baseline',
  vercel: 'positive-baseline',
  fal: 'positive-baseline',
};

/** Configured variants: 2 descriptors x 4 frameworks = 8 handlers. */
const CONFIGURED_VARIANTS = [
  {
    key: 'grafana-timestamped',
    provider: 'grafana',
    filePrefix: 'grafana',
    secretEnv: 'GRAFANA_WEBHOOK_SECRET',
    signer: { provider: 'grafana', mode: 'timestamped', signatureHeader: 'x-acme-signature', timestampHeader: 'x-acme-timestamp' },
    cliArgs: ['--grafana-mode', 'timestamped', '--signature-header', 'x-acme-signature', '--timestamp-header', 'x-acme-timestamp'],
  },
  {
    key: 'polar-legacy',
    provider: 'polar',
    filePrefix: 'polar',
    secretEnv: 'POLAR_LEGACY_WEBHOOK_SECRET',
    signer: { provider: 'polar', mode: 'legacy' },
    cliArgs: ['--polar-secret-mode', 'legacy', '--secret-env', 'POLAR_LEGACY_WEBHOOK_SECRET'],
  },
];

const CANARIES = {
  body: 'PHASE10_LONG_BODY_CANARY_0123456789',
  key: 'PHASE10_KEY_CANARY_abcdefghijklmnop',
  signature: 'PHASE10_SIGNATURE_CANARY_abcdefghijklmnop',
  account: 'PHASE10_ACCOUNT_CANARY_abcdefghijklmnop',
};

/* ------------------------------------------------------------------ *
 * Assertions and byte helpers
 * ------------------------------------------------------------------ */

class HarnessError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HarnessError';
  }
}

class BlockedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BlockedError';
  }
}

function fail(message) {
  throw new HarnessError(message);
}

function blocked(message) {
  throw new BlockedError(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

/**
 * Decode a parsed field as a string. `Object.prototype.toString` stays valid
 * across realms and avoids narrowing an unparsed value with `typeof`; a
 * non-string value is rejected rather than coerced.
 */
function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

function sha256hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function hmacSha256(keyBytes, parts) {
  const hmac = createHmac('sha256', keyBytes);

  for (const part of parts) hmac.update(part);

  return hmac.digest();
}

function utf8(value) {
  return Buffer.from(value, 'utf8');
}

function literalKey(secret) {
  assert(secret.length > 0, 'A literal signing secret must be nonempty.');

  return utf8(secret);
}

function standardKey(secret) {
  const encoded = secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret;
  const bytes = Buffer.from(encoded, 'base64');

  assert(bytes.length >= 24 && bytes.length <= 64, 'A Standard Webhooks key must decode to 24..64 bytes.');

  return bytes;
}

function base64Url(bytes) {
  return bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function canonicalIdentity(deliveryId, eventId, timestamp, authenticatedFields) {
  return { deliveryId, eventId, timestamp, authenticatedFields };
}

function plainHeaders(pairs) {
  const headers = {};

  for (const [name, value] of Object.entries(pairs)) {
    if (value !== undefined && value !== null) headers[name] = value;
  }

  return headers;
}

/* ------------------------------------------------------------------ *
 * Signer recipes (proven against fixture anchors before any live run)
 * ------------------------------------------------------------------ */

function secTimestamp(context, nowMs) {
  return context.timestampSec === undefined ? Math.floor(nowMs / 1000) : context.timestampSec;
}

function msTimestamp(context, nowMs) {
  return context.timestampMs === undefined ? nowMs : context.timestampMs;
}

function standardHeaders(names, id, timestamp, signature) {
  return plainHeaders({
    [names.id]: id,
    [names.timestamp]: timestamp,
    [names.signature]: `v1,${signature.toString('base64')}`,
  });
}

function standardSignedContent(id, timestamp, body) {
  return [utf8(`${id}.${timestamp}.`), body];
}

const SIGNERS = {
  stripe(profile, body, context, nowMs) {
    const timestamp = String(secTimestamp(context, nowMs));
    const signature = hmacSha256(literalKey(profile.secret), [utf8(`${timestamp}.`), body]).toString('hex');

    return {
      headers: plainHeaders({ 'stripe-signature': `t=${timestamp},v1=${signature}`, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, Number(timestamp), ['timestamp']),
    };
  },

  github(profile, body, context) {
    const deliveryId = context.deliveryId ?? `hlt-phase10-${randomUUID()}`;
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({
        'x-hub-signature-256': `sha256=${signature}`,
        'x-github-delivery': deliveryId,
        'x-github-event': 'phase10',
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(deliveryId, null, null, []),
    };
  },

  shopify(profile, body, context) {
    const deliveryId = context.deliveryId ?? randomUUID();
    const eventId = context.eventId ?? randomUUID();
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('base64');

    return {
      headers: plainHeaders({
        'x-shopify-hmac-sha256': signature,
        'x-shopify-webhook-id': deliveryId,
        'x-shopify-event-id': eventId,
        'x-shopify-topic': 'phase10/runtime',
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(deliveryId, eventId, null, []),
    };
  },

  'standard-webhooks': standardFamilySigner,
  clerk: standardFamilySigner,
  svix: standardFamilySigner,
  'dodo-payments': standardFamilySigner,
  gitlab: standardFamilySigner,
  replicate: standardFamilySigner,

  razorpay(profile, body, context) {
    const eventId = context.eventId ?? `evt_phase10_${randomUUID()}`;
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({
        'x-razorpay-signature': signature,
        'x-razorpay-event-id': eventId,
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, eventId, null, []),
    };
  },

  paddle(profile, body, context, nowMs) {
    const timestamp = String(secTimestamp(context, nowMs));
    const signature = hmacSha256(literalKey(profile.secret), [utf8(`${timestamp}:`), body]).toString('hex');

    return {
      headers: plainHeaders({
        'paddle-signature': `ts=${timestamp};h1=${signature}`,
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, null, Number(timestamp), ['timestamp']),
    };
  },

  'lemon-squeezy'(profile, body) {
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({
        'x-signature': signature,
        'x-event-name': 'phase10_runtime',
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  workos(profile, body, context, nowMs) {
    const timestamp = String(msTimestamp(context, nowMs));
    const signature = hmacSha256(literalKey(profile.secret), [utf8(`${timestamp}.`), body]).toString('hex');

    return {
      headers: plainHeaders({
        'workos-signature': `t=${timestamp},v1=${signature}`,
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, null, Number(timestamp) / 1000, ['timestamp']),
    };
  },

  sentry(profile, body) {
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({ 'sentry-hook-signature': signature, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  doppler(profile, body) {
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({ 'x-doppler-signature': `sha256=${signature}`, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  sanity(profile, body, context, nowMs) {
    const timestamp = String(msTimestamp(context, nowMs));

    assert(Number(timestamp) >= 1609459200000, 'Sanity timestamps must be real millisecond values.');
    const digest = hmacSha256(literalKey(profile.secret), [utf8(`${timestamp}.`), body]);

    return {
      headers: plainHeaders({
        'sanity-webhook-signature': `t=${timestamp},v1=${base64Url(digest)}`,
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, null, Number(timestamp) / 1000, ['timestamp']),
    };
  },

  grafana(profile, body, context, nowMs) {
    const signatureHeader = profile.signatureHeader ?? 'x-grafana-alerting-signature';

    if (profile.mode === 'timestamped') {
      const timestamp = String(secTimestamp(context, nowMs));
      const timestampHeader = profile.timestampHeader ?? 'x-grafana-alerting-timestamp';
      const signature = hmacSha256(literalKey(profile.secret), [utf8(`${timestamp}:`), body]).toString('hex');

      return {
        headers: plainHeaders({
          [signatureHeader]: signature,
          [timestampHeader]: timestamp,
          'content-type': 'application/json',
        }),
        identity: canonicalIdentity(null, null, Number(timestamp), ['timestamp']),
      };
    }

    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({ [signatureHeader]: signature, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  polar(profile, body, context, nowMs) {
    const id = context.messageId ?? `msg_phase10_${randomUUID()}`;
    const timestamp = String(secTimestamp(context, nowMs));
    const key = profile.mode === 'legacy' ? literalKey(profile.secret) : standardKey(profile.secret);
    const signature = hmacSha256(key, standardSignedContent(id, timestamp, body));

    return {
      headers: plainHeaders({
        ...standardHeaders(STANDARD_FAMILY.polar, id, timestamp, signature),
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, id, Number(timestamp), ['eventId', 'timestamp']),
    };
  },

  linear(profile, body) {
    const signature = hmacSha256(literalKey(profile.secret), [body]).toString('hex');

    return {
      headers: plainHeaders({ 'linear-signature': signature, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  vercel(profile, body) {
    const signature = createHmac('sha1', literalKey(profile.secret)).update(body).digest('hex');

    return {
      headers: plainHeaders({ 'x-vercel-signature': signature, 'content-type': 'application/json' }),
      identity: canonicalIdentity(null, null, null, []),
    };
  },

  fal(profile, body, context, nowMs) {
    const requestId = context.requestId ?? randomUUID();
    const userId = context.userId ?? profile.expectedUserId;
    const timestamp = String(secTimestamp(context, nowMs));
    const message = utf8([requestId, userId, timestamp, sha256hex(body)].join('\n'));
    const signature = cryptoSign(null, message, profile.privateKey).toString('hex');

    return {
      headers: plainHeaders({
        'x-fal-webhook-signature': signature,
        'x-fal-webhook-request-id': requestId,
        'x-fal-webhook-user-id': userId,
        'x-fal-webhook-timestamp': timestamp,
        'content-type': 'application/json',
      }),
      identity: canonicalIdentity(null, null, Number(timestamp), ['timestamp']),
    };
  },
};

function standardFamilySigner(profile, body, context, nowMs) {
  const names = STANDARD_FAMILY[profile.provider];

  assert(names !== undefined, `No Standard Webhooks header family for ${profile.provider}.`);
  const id = context.messageId ?? `msg_phase10_${randomUUID()}`;
  const timestamp = String(secTimestamp(context, nowMs));
  const key = profile.mode === 'legacy' ? literalKey(profile.secret) : standardKey(profile.secret);
  const signature = hmacSha256(key, standardSignedContent(id, timestamp, body));

  return {
    headers: plainHeaders({
      ...standardHeaders(names, id, timestamp, signature),
      'content-type': 'application/json',
    }),
    identity: canonicalIdentity(null, id, Number(timestamp), ['eventId', 'timestamp']),
  };
}

function signFor(profile, body, context) {
  const signer = SIGNERS[profile.provider];

  assert(signer !== undefined, `No signer recipe for ${profile.provider}.`);

  return signer(profile, body, context, context.nowMs);
}

/* ------------------------------------------------------------------ *
 * Fixture anchor proof
 * ------------------------------------------------------------------ */

function signedHeaderNames(provider, fixtureHeaders) {  if (STANDARD_FAMILY[provider] !== undefined) {
    const names = STANDARD_FAMILY[provider];

    return [names.id, names.timestamp, names.signature];
  }

  const single = {
    stripe: ['stripe-signature'],
    github: ['x-hub-signature-256'],
    shopify: ['x-shopify-hmac-sha256'],
    razorpay: ['x-razorpay-signature'],
    paddle: ['paddle-signature'],
    'lemon-squeezy': ['x-signature'],
    workos: ['workos-signature'],
    sentry: ['sentry-hook-signature'],
    doppler: ['x-doppler-signature'],
    sanity: ['sanity-webhook-signature'],
    linear: ['linear-signature'],
    vercel: ['x-vercel-signature'],
  };

  if (provider === 'grafana') {
    return Object.keys(fixtureHeaders).filter((name) => name.endsWith('-signature') || name.endsWith('-timestamp'));
  }

  return single[provider] ?? [];
}

function assertIdentitiesMatch(label, produced, expected) {
  const fields = ['deliveryId', 'eventId', 'timestamp'];

  for (const field of fields) {
    if (expected[field] === 'unsigned-or-null') {
      assert(produced[field] !== null, `${label} identity ${field} should be present.`);
      continue;
    }

    assert(
      deepEqual(produced[field], expected[field]),
      `${label} identity ${field} mismatch: expected ${JSON.stringify(expected[field])} but produced ${JSON.stringify(produced[field])}.`,
    );
  }

  assert(
    deepEqual(produced.authenticatedFields, expected.authenticatedFields),
    `${label} authenticatedFields mismatch.`,
  );
}

function readFixture(provider) {
  const file = join(REPO_ROOT, 'tests', 'fixtures', `${provider}.json`);

  assert(existsSync(file), `Missing fixture file for ${provider}.`);

  return JSON.parse(readFileSync(file, 'utf8'));
}

function anchorContext(provider, fixtureCase) {
  const headers = fixtureCase.request.headers;
  const options = fixtureCase.options;
  const context = { nowMs: (options.now ?? 1700000000) * 1000 };

  if (provider === 'sanity' || provider === 'workos') {
    context.timestampMs = Number(String(headers[provider === 'sanity' ? 'sanity-webhook-signature' : 'workos-signature']).split(',')[0].slice(2));
  } else if (provider === 'fal') {
    context.timestampSec = Number(headers['x-fal-webhook-timestamp']);
    context.requestId = headers['x-fal-webhook-request-id'];
    context.userId = headers['x-fal-webhook-user-id'];
  } else if (provider === 'paddle') {
    context.timestampSec = Number(String(headers['paddle-signature']).split(';')[0].slice(3));
  } else if (provider === 'stripe') {
    context.timestampSec = Number(String(headers['stripe-signature']).split(',')[0].slice(2));
  } else if (provider === 'grafana') {
    const timestamp = headers['x-grafana-alerting-timestamp'];

    if (timestamp !== undefined) context.timestampSec = Number(timestamp);
  } else if (STANDARD_FAMILY[provider] !== undefined) {
    const names = STANDARD_FAMILY[provider];

    context.messageId = headers[names.id];
    context.timestampSec = Number(headers[names.timestamp]);
  }

  if (provider === 'github') context.deliveryId = headers['x-github-delivery'];

  if (provider === 'shopify') {
    context.deliveryId = headers['x-shopify-webhook-id'];
    context.eventId = headers['x-shopify-event-id'];
  }

  if (provider === 'razorpay') context.eventId = headers['x-razorpay-event-id'];

  return context;
}

function falSpki(rawPublicKey) {
  return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawPublicKey]);
}

async function proveAnchors(providers) {
  const proof = [];

  assert(providers.length === EXPECTED_PROVIDERS.length, 'Anchor proof must cover the reviewed provider count.');

  for (const provider of providers) {
    const fixture = readFixture(provider);
    const fixtureCase = fixture.cases.find((item) => item.id === ANCHOR_CASES[provider]);

    assert(fixtureCase !== undefined, `Fixture ${provider} has no anchor case ${ANCHOR_CASES[provider]}.`);
    assert(fixtureCase.expected.ok === true, `Fixture anchor ${provider} is not a positive case.`);

    const body = Buffer.from(fixtureCase.request.bodyBase64, 'base64');
    const context = anchorContext(provider, fixtureCase);

    if (provider === 'fal') {
      const rawPublic = Buffer.from(fixtureCase.options.publicKeysBase64url[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      const publicKey = createPublicKey({ key: falSpki(rawPublic), format: 'der', type: 'spki' });
      const headers = fixtureCase.request.headers;

      const message = utf8([
        headers['x-fal-webhook-request-id'],
        headers['x-fal-webhook-user-id'],
        headers['x-fal-webhook-timestamp'],
        sha256hex(body),
      ].join('\n'));

      const fixtureSignature = Buffer.from(headers['x-fal-webhook-signature'], 'hex');
      const accepted = cryptoVerify(null, message, publicKey, fixtureSignature);
      const tampered = cryptoVerify(null, Buffer.concat([message, utf8('.')]), publicKey, fixtureSignature);

      assert(accepted === true, 'fal anchor signature did not verify against its pinned public key.');
      assert(tampered === false, 'fal anchor signature verified a mutated message.');
      assert(publicKey.asymmetricKeyType === 'ed25519', 'fal anchor key is not Ed25519.');

      const pair = generateKeyPairSync('ed25519');
      const exported = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
      const probeBody = utf8('{"phase10":"fal-roundtrip"}');

      const probe = signFor(
        { provider: 'fal', privateKey: pair.privateKey, expectedUserId: 'usr_phase10_roundtrip' },
        probeBody,
        { nowMs: 1792742400000, userId: 'usr_phase10_roundtrip' },
      );

      const probeMessage = utf8([
        probe.headers['x-fal-webhook-request-id'],
        probe.headers['x-fal-webhook-user-id'],
        probe.headers['x-fal-webhook-timestamp'],
        sha256hex(probeBody),
      ].join('\n'));

      const roundTrip = cryptoVerify(
        null,
        probeMessage,
        createPublicKey({ key: falSpki(exported), format: 'der', type: 'spki' }),
        Buffer.from(probe.headers['x-fal-webhook-signature'], 'hex'),
      );

      assert(roundTrip === true, 'The fal signer round-trip signature did not verify.');
      proof.push({ provider, anchor: ANCHOR_CASES[provider], mode: 'ed25519-verify-and-roundtrip' });
      continue;
    }

    const profile = { provider, secret: fixtureCase.options.secrets[0] };

    if (provider === 'grafana') {
      profile.mode = fixtureCase.options.providerOptions.mode;
    }

    if (provider === 'polar') {
      profile.mode = fixtureCase.options.providerOptions?.secretMode ?? 'current';
    }

    const produced = signFor(profile, body, context);

    for (const name of signedHeaderNames(provider, fixtureCase.request.headers)) {
      assert(
        produced.headers[name] === fixtureCase.request.headers[name],
        `${provider} anchor mismatch for header ${name}: expected ${fixtureCase.request.headers[name]} but produced ${produced.headers[name]}.`,
      );
    }

    assertIdentitiesMatch(provider, produced.identity, fixtureCase.expected.identity);

    proof.push({ provider, anchor: ANCHOR_CASES[provider], mode: 'byte-exact-headers' });
  }

  assert(proof.length === EXPECTED_PROVIDERS.length, 'Anchor proof did not cover every provider.');

  return proof;
}

/* ------------------------------------------------------------------ *
 * Preflight, registry and installed-package workspace
 * ------------------------------------------------------------------ */


function gitOutput(args) {
  return execFileSync('git', ['-C', REPO_ROOT, ...args], { encoding: 'utf8', timeout: 60_000 }).trim();
}


/**
 * Registry drift is an environment problem, not a failed assertion: the reviewed
 * 21-provider Node22/24 target is not the one under test, so the harness refuses
 * to report a pass and exits BLOCKED instead.
 */
function assertExactRegistry(providers) {
  if (!Array.isArray(providers)) blocked('The built registry did not expose a provider array.');

  if (providers.length !== EXPECTED_PROVIDERS.length) {
    blocked(`Registry has ${providers.length} providers; the reviewed target is ${EXPECTED_PROVIDERS.length}.`);
  }

  for (let index = 0; index < EXPECTED_PROVIDERS.length; index += 1) {
    if (providers[index] !== EXPECTED_PROVIDERS[index]) {
      blocked(`Registry order mismatch at index ${index}: expected ${EXPECTED_PROVIDERS[index]} but found ${String(providers[index])}.`);
    }
  }
}

function preflight(runtimeChoice) {
  const currentMajor = Number(process.versions.node.split('.')[0]);

  const labels = runtimeChoice === 'both' ? ['node24', 'node22']
    : runtimeChoice === 'current' ? [`node${currentMajor}`] : [runtimeChoice];

  const manifestPath = join(REPO_ROOT, RUNTIME_MANIFEST);
  const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : {};
  const runtimes = [];

  for (const label of labels) {
    if (label !== 'node22' && label !== 'node24') blocked('This matrix qualifies Node22/24 only.');

    const executable = process.env[`PHASE10_${label.toUpperCase()}`]
      ?? (label === `node${currentMajor}` ? process.execPath : manifest.runtimes?.[label]);

    if (!isString(executable) || !existsSync(executable)) blocked(`Runtime ${label} missing; set PHASE10_${label.toUpperCase()}.`);

    const version = execFileSync(executable, ['--version'], { encoding: 'utf8', timeout: 10000 }).trim();

    assert(version.startsWith('v' + label.slice(4) + '.'), 'Runtime executable version disagrees with selection.');
    runtimes.push({ label, executable, version });
  }

  return { runtimes, head: gitOutput(['rev-parse', 'HEAD']), branch: gitOutput(['branch', '--show-current']) };
}

function requireBuildArtifacts() {
  for (const file of [join('dist', 'index.js'), join('dist', 'cli', 'index.js'), join('dist', 'providers', 'index.js')]) {
    if (!existsSync(join(REPO_ROOT, file))) blocked(`Missing build artifact ${file}; run npm run build first.`);
  }
}

async function loadRegistryProviders() {
  const registry = await import(pathToFileURL(join(REPO_ROOT, 'dist', 'providers', 'index.js')).href);
  const providers = registry.SUPPORTED_PROVIDERS;

  assertExactRegistry(providers);

  return providers;
}

function fingerprintTree(root) {
  const entries = [];

  const walk = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      const full = join(directory, name);
      const stat = lstatSync(full);

      if (stat.isSymbolicLink()) entries.push(`${relative(root, full)}:link:${readlinkSync(full)}`);
      else if (stat.isDirectory()) walk(full);
      else entries.push(`${relative(root, full)}:${sha256hex(readFileSync(full))}`);
    }
  };

  walk(root);

  return sha256hex(utf8(entries.join('\n')));
}

function createWorkspace() {
  const root = resolve(mkdtempSync(join(tmpdir(), 'hooklatch-phase10-big-pickle-')));
  const tempRoot = resolve(tmpdir()).toLowerCase();

  assert(
    root.toLowerCase().startsWith(tempRoot) && !root.toLowerCase().startsWith(REPO_ROOT.toLowerCase()),
    'Temporary workspace must live under the OS temp directory, never inside the repository.',
  );

  const workspace = {
    root,
    packDir: join(root, 'pack'),
    consumerRoot: join(root, 'consumer'),
    specsDir: join(root, 'specs'),
    resultsDir: join(root, 'results'),
    npmCache: join(root, 'npm-cache'),
    junctions: [],
    dependencyStats: [],
    children: [],
  };

  for (const directory of [workspace.packDir, workspace.consumerRoot, workspace.specsDir, workspace.resultsDir, workspace.npmCache]) {
    mkdirSync(directory, { recursive: true });
  }

  mkdirSync(join(workspace.consumerRoot, 'node_modules'), { recursive: true });
  writeFileSync(
    join(workspace.consumerRoot, 'package.json'),
    `${JSON.stringify({ name: 'hooklatch-phase10-consumer', version: '1.0.0', private: true, type: 'module' }, null, 2)}\n`,
  );

  return workspace;
}

function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath !== undefined) candidates.push(process.env.npm_execpath);
  candidates.push(
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  assert(found !== undefined, 'npm CLI is unavailable: neither npm_execpath nor the Node install tree provides npm-cli.js.');

  return found;
}

function npmEnvironment(workspace) {
  return {
    ...process.env,
    npm_config_cache: workspace.npmCache,
    NPM_CONFIG_OFFLINE: 'true',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
    NPM_CONFIG_PROGRESS: 'false',
  };
}

function runNpm(workspace, npmCli, args, cwd, label) {
  try {
    return execFileSync(process.execPath, [npmCli, ...args], {
      cwd,
      encoding: 'utf8',
      env: npmEnvironment(workspace),
      timeout: 300_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = [error.stdout, error.stderr]
      .filter((part) => isString(part) && part.trim().length > 0)
      .join('\n');

    return fail(`${label} failed with status ${String(error.status)}${detail.length > 0 ? `:\n${detail}` : ''}`);
  }
}

function packAndInstall(workspace) {
  const npmCli = locateNpmCli();

  const packed = runNpm(
    workspace,
    npmCli,
    ['pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', workspace.packDir],
    REPO_ROOT,
    'npm pack',
  );

  const entries = JSON.parse(packed);

  assert(Array.isArray(entries) && entries.length === 1, 'npm pack did not describe exactly one archive.');
  const tarball = join(workspace.packDir, entries[0].filename);

  assert(existsSync(tarball), `npm pack did not create ${tarball}.`);

  runNpm(
    workspace,
    npmCli,
    ['install', tarball, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps'],
    workspace.consumerRoot,
    'npm install',
  );

  const installedManifest = join(workspace.consumerRoot, 'node_modules', 'hooklatch', 'package.json');

  assert(existsSync(installedManifest), 'The packed package was not installed into the temporary consumer.');
  assert(
    JSON.parse(readFileSync(installedManifest, 'utf8')).name === 'hooklatch',
    'The installed package is not hooklatch.',
  );

  return tarball;
}

function linkPinnedDependency(workspace, readOnlyRoot, name) {
  const target = resolve(join(readOnlyRoot, name));
  const link = join(workspace.consumerRoot, 'node_modules', name);
  const manifest = join(target, 'package.json');

  assert(existsSync(manifest), `Pinned dependency ${name} is missing at ${target}.`);

  const before = fingerprintTree(target);

  workspace.junctions.push({ link, target, label: name });
  symlinkSync(target, link, 'junction');
  workspace.dependencyStats.push({ label: name, target, fingerprint: before });

  assert(existsSync(link), `Junction for ${name} was not created.`);
  const actual = readlinkSync(link).replace(/^\\\\\?\\/, '');

  assert(
    resolve(actual).toLowerCase() === target.toLowerCase(),
    `Junction for ${name} points at ${actual} instead of ${target}.`,
  );
}

/* ------------------------------------------------------------------ *
 * Generation through the installed CLI, transpilation and bundling
 * ------------------------------------------------------------------ */

function fileNameFor(provider, framework) {
  if (framework === 'nextjs') return 'route.ts';

  if (framework === 'cloudflare') return `${provider}.cloudflare.ts`;

  if (framework === 'hono') return `${provider}.hono.ts`;

  return `${provider}.express.ts`;
}

function exportNameFor(provider, framework) {
  const identifier = provider.replaceAll('-', '_');

  if (framework === 'express') return `${identifier}ExpressWebhook`;

  if (framework === 'hono') return `${identifier}HonoWebhook`;

  if (framework === 'nextjs') return 'POST';

  return 'fetch';
}

function runInstalledCli(cliPath, args, cwd, label) {
  try {
    execFileSync(process.execPath, [cliPath, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 120_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = [error.stdout, error.stderr]
      .filter((part) => isString(part) && part.trim().length > 0)
      .join('\n');

    fail(`${label} failed with status ${String(error.status)}${detail.length > 0 ? `:\n${detail}` : ''}`);
  }
}

function generateHandlers(workspace, providers) {
  const cliPath = join(workspace.consumerRoot, 'node_modules', 'hooklatch', 'dist', 'cli', 'index.js');

  assert(existsSync(cliPath), 'The installed package does not expose dist/cli/index.js.');

  const handlers = [];

  for (const framework of FRAMEWORKS) {
    for (const provider of providers) {
      const outRelative = `gen/${framework}/${provider}`;

      const args = [
        'init',
        'webhook',
        '--provider',
        provider,
        '--framework',
        framework,
        '--out',
        outRelative,
        '--body-limit',
        String(BODY_LIMIT),
      ];

      if (provider === 'grafana') args.push('--grafana-mode', 'body');

      if (provider === 'fal') args.push('--public-key-env', 'FAL_WEBHOOK_PUBLIC_KEYS', '--expected-user-env', 'FAL_WEBHOOK_USER_ID');

      runInstalledCli(cliPath, args, workspace.consumerRoot, `generation ${provider}/${framework}`);

      handlers.push({
        kind: 'primary',
        key: provider,
        provider,
        framework,
        sourcePath: join(workspace.consumerRoot, outRelative, fileNameFor(provider, framework)),
      });
    }

    for (const variant of CONFIGURED_VARIANTS) {
      const outRelative = `gen-configured/${variant.key}/${framework}`;

      runInstalledCli(
        cliPath,
        [
          'init',
          'webhook',
          '--provider',
          variant.provider,
          '--framework',
          framework,
          '--out',
          outRelative,
          '--body-limit',
          String(BODY_LIMIT),
          ...variant.cliArgs,
        ],
        workspace.consumerRoot,
        `generation ${variant.key}/${framework}`,
      );

      handlers.push({
        kind: 'configured',
        key: variant.key,
        provider: variant.provider,
        framework,
        sourcePath: join(workspace.consumerRoot, outRelative, fileNameFor(variant.provider, framework)),
      });
    }
  }

  const primary = handlers.filter((handler) => handler.kind === 'primary');

  assert(
    primary.length === providers.length * FRAMEWORKS.length,
    `Expected ${providers.length * FRAMEWORKS.length} primary handlers but generated ${primary.length}.`,
  );
  assert(
    handlers.length === providers.length * FRAMEWORKS.length + CONFIGURED_VARIANTS.length * FRAMEWORKS.length,
    'Configured handler count is wrong.',
  );

  for (const handler of handlers) {
    assert(existsSync(handler.sourcePath), `The CLI did not create ${handler.sourcePath}.`);
    const source = readFileSync(handler.sourcePath, 'utf8');

    assert(source.includes(`provider: '${handler.provider}'`), `Generated ${handler.provider}/${handler.framework} does not bind its provider.`);
    assert(source.includes(`maxBodyBytes: ${BODY_LIMIT}`), `Generated ${handler.provider}/${handler.framework} does not carry the body limit.`);
    assert(
      source.includes(`export const ${exportNameFor(handler.provider, handler.framework)}`),
      `Generated ${handler.provider}/${handler.framework} does not export ${exportNameFor(handler.provider, handler.framework)}.`,
    );
    assert(source.includes(`from 'hooklatch/${handler.framework}'`), `Generated ${handler.provider}/${handler.framework} does not import its adapter.`);

    handler.transpiledPath = join(workspace.consumerRoot, 'run', handler.framework, `${handler.key}.mjs`);
  }

  return handlers;
}

function transpileHandlers(workspace, handlers) {
  const transpiled = [];

  for (const handler of handlers) {
    const source = readFileSync(handler.sourcePath, 'utf8');

    const output = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
        isolatedModules: true,
      },
      fileName: handler.sourcePath,
    }).outputText;

    assert(output.length > 0, `TypeScript produced no output for ${handler.key}/${handler.framework}.`);
    assert(
      output.includes(`export const ${exportNameFor(handler.provider, handler.framework)}`),
      `Transpiled ${handler.key}/${handler.framework} lost its exported handler.`,
    );

    mkdirSync(dirname(handler.transpiledPath), { recursive: true });
    writeFileSync(handler.transpiledPath, output);

    transpiled.push({ ...handler, moduleUrl: pathToFileURL(handler.transpiledPath).href });
  }

  return transpiled;
}

function cloudflareWrapperSource(targetSpecifier) {
  return `import generated from '${targetSpecifier}';

let jsonCalls = 0;
let lastPayload = null;
const originalJson = Response.json;

Response.json = function phase10InstrumentedJson(...args) {
  jsonCalls += 1;
  lastPayload = args[0] === undefined ? null : args[0];
  return originalJson.apply(Response, args);
};

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;

    if (path === '/__phase10/reset') {
      jsonCalls = 0;
      lastPayload = null;
      return new Response('ok');
    }

    if (path === '/__phase10/stats') {
      return new Response(JSON.stringify({ jsonCalls, lastPayload }), {
        headers: { 'content-type': 'application/json' },
      });
    }

    return generated.fetch(request, env, ctx);
  },
};
`;
}

async function bundleCloudflareHandlers(workspace, handlers) {
  for (const handler of handlers) {
    if (handler.framework !== 'cloudflare') continue;

    const directory = join(workspace.consumerRoot, 'run', 'cloudflare-bundles', handler.key);
    const wrapperPath = join(directory, 'worker.mjs');
    const target = relative(directory, handler.transpiledPath).replaceAll('\\', '/');

    mkdirSync(directory, { recursive: true });
    writeFileSync(wrapperPath, cloudflareWrapperSource(target));

    const outfile = join(directory, 'worker.bundle.mjs');

    await esbuildBuild({
      entryPoints: [wrapperPath],
      outfile,
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      target: 'es2022',
      absWorkingDir: workspace.consumerRoot,
      logLevel: 'silent',
      sourcemap: false,
      legalComments: 'none',
    });

    const bundled = readFileSync(outfile, 'utf8');

    assert(bundled.length > 0, `Empty Cloudflare bundle for ${handler.key}.`);
    assert(!/from\s*["']node:/.test(bundled), `Cloudflare bundle for ${handler.key} imports a node: builtin.`);
    assert(!/require\(\s*["']node:/.test(bundled), `Cloudflare bundle for ${handler.key} requires a node: builtin.`);
    assert(!/\bprocess\s*\./.test(bundled), `Cloudflare bundle for ${handler.key} references process.`);

    handler.bundlePath = outfile;
  }
}

/* ------------------------------------------------------------------ *
 * Runtime specs
 * ------------------------------------------------------------------ */

function deterministicBytes(label) {
  return Buffer.from(sha256hex(utf8(`hlt-phase10-${label}`)), 'hex');
}

function secretValueFor(provider) {
  if (STANDARD_FAMILY[provider] !== undefined) return `whsec_${deterministicBytes(provider).toString('base64')}`;

  return `hlt_phase10_${provider.replaceAll('-', '_')}_literal_secret_0001`;
}

function createFalCredentials() {
  const pair = generateKeyPairSync('ed25519');
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  const raw = spki.subarray(spki.length - 32);

  assert(raw.length === 32, 'Ed25519 SPKI export did not end in a 32-byte public key.');

  return {
    publicKeyBase64Url: base64Url(raw),
    privateKeyBase64: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    expectedUserId: 'usr_phase10_big_pickle',
  };
}

function configuredVariantFor(key) {
  return CONFIGURED_VARIANTS.find((variant) => variant.key === key);
}

function profileFor(handler, fal) {
  const provider = handler.provider;

  if (provider === 'fal') {
    return { provider, privateKeyBase64: fal.privateKeyBase64, expectedUserId: fal.expectedUserId };
  }

  if (provider === 'grafana') {
    const variant = configuredVariantFor(handler.key);

    if (variant !== undefined) {
      return {
        provider,
        secret: secretValueFor(provider),
        mode: 'timestamped',
        signatureHeader: variant.signer.signatureHeader,
        timestampHeader: variant.signer.timestampHeader,
      };
    }

    return { provider, secret: secretValueFor(provider), mode: 'body' };
  }

  if (provider === 'polar') {
    return { provider, secret: secretValueFor(provider), mode: handler.kind === 'configured' ? 'legacy' : 'current' };
  }

  if (STANDARD_FAMILY[provider] !== undefined) return { provider, secret: secretValueFor(provider), mode: 'current' };

  return { provider, secret: secretValueFor(provider) };
}

function envFor(handler, fal) {
  if (handler.provider === 'fal') {
    return [
      { name: 'FAL_WEBHOOK_PUBLIC_KEYS', value: fal.publicKeyBase64Url },
      { name: FAL_EXPECTED_USER_ENV, value: fal.expectedUserId },
    ];
  }

  const variant = configuredVariantFor(handler.key);
  const name = variant === undefined ? PRIMARY_SECRET_ENVS[handler.provider] : variant.secretEnv;

  assert(isString(name) && name.length > 0, `No secret environment name for ${handler.provider}.`);

  return [{ name, value: secretValueFor(handler.provider) }];
}

async function writeRuntimeSpec(workspace, runtimeLabel, framework, handlers, fal) {
  const entries = handlers
    .filter((handler) => handler.framework === framework)
    .map((handler) => {
      const environment = envFor(handler, fal);

      return {
        key: handler.key,
        kind: handler.kind,
        provider: handler.provider,
        framework: handler.framework,
        exportName: exportNameFor(handler.provider, handler.framework),
        moduleUrl: handler.moduleUrl,
        bundlePath: handler.framework === 'cloudflare' ? handler.bundlePath : null,
        route: `/webhooks/${handler.key}`,
        env: environment,
        profile: profileFor(handler, fal),
      };
    });

  const specPath = join(workspace.specsDir, `${runtimeLabel}-${framework}.json`);
  const outputPath = join(workspace.resultsDir, `${runtimeLabel}-${framework}.json`);

  writeFileSync(
    specPath,
    `${JSON.stringify({ schemaVersion: 1, runtimeLabel, framework, bodyLimit: BODY_LIMIT, consumerRoot: workspace.consumerRoot, entries, outputPath }, null, 2)}\n`,
  );

  return { specPath, outputPath, framework, runtimeLabel };
}

/* ------------------------------------------------------------------ *
 * Child-mode request cases
 * ------------------------------------------------------------------ */

function validBodyFor(entry) {
  return utf8(
    JSON.stringify({
      phase10: entry.key,
      provider: entry.provider,
      framework: entry.framework,
      kind: entry.kind,
      payload: 'valid-receipt',
    }),
  );
}

function tamperBody(body) {
  // Appended whitespace keeps the JSON valid while changing the raw bytes, so
  // the rejection can only come from the MAC computed over the original body.
  return Buffer.concat([body, utf8(' ')]);
}

function overflowBody() {
  const unit = utf8(`${CANARIES.body}:`);
  const body = Buffer.alloc(OVERFLOW_BYTES);

  for (let index = 0; index < OVERFLOW_BYTES; index += 1) body[index] = unit[index % unit.length];

  return body;
}

function signRequest(entry, body, profileOverride) {
  const profile = profileOverride ?? entry.profile;
  const context = { nowMs: Date.now() };

  if (profile.provider === 'fal') context.userId = profile.expectedUserId;

  const signed = signFor(profile, body, context);

  return { headers: signed.headers, identity: signed.identity };
}

function forbiddenValues(entry) {
  const values = [CANARIES.body, CANARIES.key, CANARIES.signature, CANARIES.account];

  for (const variable of entry.env) values.push(variable.value);

  if (entry.profile.secret !== undefined) values.push(entry.profile.secret);

  return values.filter((value) => value.length > 8);
}

function checkReceipt(label, outcome, sentBody, framework, expectedIdentity) {
  assert(outcome.status === 200, `${label}: expected 200 but received ${outcome.status} (${outcome.text}).`);
  assert(outcome.downstream === 1, `${label}: the consumer callback ran ${outcome.downstream} times instead of once.`);
  assert(outcome.json !== null, `${label}: the consumer did not return JSON.`);
  assert(outcome.json.received === true, `${label}: the consumer did not confirm a verified event.`);
  assert(
    outcome.json.bytes === sentBody.length,
    `${label}: verified byte length ${String(outcome.json.bytes)} does not equal ${sentBody.length}.`,
  );

  if (framework === 'express' || framework === 'hono') {
    assertIdentitiesMatch(label, outcome.json.identity, expectedIdentity);
    assert(
      outcome.json.bodyBase64 === sentBody.toString('base64'),
      `${label}: the verified raw bytes differ from the transmitted body.`,
    );
  }
}

function checkRejection(label, outcome, expectedStatus, forbidden) {
  assert(
    outcome.status === expectedStatus,
    `${label}: expected ${expectedStatus} but received ${outcome.status} (${outcome.text}).`,
  );
  assert(outcome.downstream === 0, `${label}: the consumer callback ran despite a rejection.`);

  for (const value of forbidden) {
    assert(!outcome.text.includes(value), `${label}: the rejection response echoed a secret or canary value.`);
  }
}

async function runCases(spec, invoke) {
  const cases = [];

  for (const entry of spec.entries) {
    const label = `${entry.key}/${spec.framework}`;
    const body = validBodyFor(entry);
    const signed = signRequest(entry, body);
    const valid = await invoke(entry.route, signed.headers, body);

    checkReceipt(`${label}/valid`, valid, body, spec.framework, signed.identity);
    cases.push({ entry: entry.key, kind: entry.kind, case: 'valid', status: valid.status });

    if (entry.kind === 'primary') {
      // Sign the untouched body, then transmit the same bytes plus a trailing
      // space, so only the raw-byte MAC can reject this request.
      const tamperHeaders = signRequest(entry, body).headers;
      const tampered = await invoke(entry.route, tamperHeaders, tamperBody(body));

      checkRejection(`${label}/tamper`, tampered, 400, forbiddenValues(entry));
      cases.push({ entry: entry.key, kind: entry.kind, case: 'tamper', status: tampered.status });

      const overflow = await invoke(entry.route, { 'content-type': 'application/json' }, overflowBody());

      checkRejection(`${label}/overflow`, overflow, 413, forbiddenValues(entry));
      cases.push({ entry: entry.key, kind: entry.kind, case: 'overflow', status: overflow.status });
      continue;
    }

    const wrongProfile = entry.provider === 'grafana'
      ? { ...entry.profile, mode: 'body' }
      : { ...entry.profile, mode: 'current' };

    const wrongSigned = signRequest(entry, body, wrongProfile);
    const wrong = await invoke(entry.route, wrongSigned.headers, body);

    checkRejection(`${label}/wrong-layout`, wrong, 400, forbiddenValues(entry));
    cases.push({ entry: entry.key, kind: entry.kind, case: 'wrong-layout', status: wrong.status });
  }

  return cases;
}

/* ------------------------------------------------------------------ *
 * Express child surface
 * ------------------------------------------------------------------ */

function listen(app) {
  return new Promise((resolvePromise, rejectPromise) => {
    const server = app.listen(0, '127.0.0.1', () => resolvePromise(server));

    server.on('error', rejectPromise);
  });
}

function closeServer(server) {
  return new Promise((resolvePromise) => server.close(() => resolvePromise()));
}

async function runExpress(spec) {
  const requireConsumer = createRequire(join(spec.consumerRoot, 'noop.cjs'));
  const expressModule = await import(pathToFileURL(requireConsumer.resolve('express')).href);
  const express = expressModule.default ?? expressModule;
  const app = express();
  const routes = new Map();

  const mount = (route, middleware) => {
    assert(middleware !== undefined && middleware !== null, `Express middleware for ${route} is missing.`);
    routes.set(route, { calls: 0 });
    app.post(route, middleware, (request, response) => {
      const record = routes.get(route);

      record.calls += 1;
      const verified = request.webhook;

      response.status(200).json({
        received: true,
        bytes: verified.rawBody.byteLength,
        identity: verified.identity,
        bodyBase64: Buffer.from(verified.rawBody).toString('base64'),
      });
    });
  };

  for (const entry of spec.entries) {
    const module = await import(entry.moduleUrl);

    mount(entry.route, module[entry.exportName]);
  }

  const controlRoutes = await mountExpressControls(spec, mount);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}`;

  const invoke = async (route, headers, body) => {
    const record = routes.get(route);

    record.calls = 0;
    const response = await fetch(base + route, { method: 'POST', headers, body });
    const text = await response.text();
    let json = null;

    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    return { status: response.status, text, json, downstream: record.calls };
  };

  try {
    const cases = await runCases(spec, invoke);
    const controls = await runExpressControls(spec, controlRoutes, invoke);

    return { cases, controls };
  } finally {
    await closeServer(server);
  }
}

function findEntry(spec, predicate, label) {
  const entry = spec.entries.find(predicate);

  assert(entry !== undefined, `Required ${label} handler is missing from the runtime matrix.`);

  return entry;
}

async function mountExpressControls(spec, mount) {
  const github = findEntry(spec, (entry) => entry.provider === 'github', 'github');
  const doppler = findEntry(spec, (entry) => entry.provider === 'doppler', 'doppler');
  const fal = findEntry(spec, (entry) => entry.provider === 'fal', 'fal');
  const githubModule = await import(github.moduleUrl);
  const dopplerModule = await import(doppler.moduleUrl);
  const falModule = await import(fal.moduleUrl);

  mount('/__controls/binding-positive', githubModule[github.exportName]);
  mount('/__controls/binding-negative', dopplerModule[doppler.exportName]);
  mount('/__controls/wrong-secret', githubModule[github.exportName]);
  mount('/__controls/malformed-signature', githubModule[github.exportName]);
  mount('/__controls/wrong-account', falModule[fal.exportName]);

  const savedUser = process.env.FAL_WEBHOOK_USER_ID;
  let canaryModule;

  process.env.FAL_WEBHOOK_USER_ID = CANARIES.account;

  try {
    canaryModule = await import(`${fal.moduleUrl}?phase10=wrong-account`);
  } finally {
    if (savedUser === undefined) delete process.env.FAL_WEBHOOK_USER_ID;
    else process.env.FAL_WEBHOOK_USER_ID = savedUser;
  }

  assert(
    canaryModule[fal.exportName] !== falModule[fal.exportName],
    'The wrong-account control module was not re-imported with the canary environment.',
  );
  mount('/__controls/wrong-account-canary', canaryModule[fal.exportName]);

  return { github, fal };
}

async function runExpressControls(spec, controlRoutes, invoke) {
  const controls = [];
  const { github, fal } = controlRoutes;
  const githubBody = validBodyFor(github);
  const githubSigned = signRequest(github, githubBody);

  const positive = await invoke('/__controls/binding-positive', githubSigned.headers, githubBody);

  checkReceipt('control/binding-positive', positive, githubBody, 'express', githubSigned.identity);
  controls.push({ control: 'binding-positive', status: positive.status, detected: true });

  const negative = await invoke('/__controls/binding-negative', githubSigned.headers, githubBody);

  checkRejection('control/binding-negative', negative, 400, [CANARIES.body, CANARIES.key, CANARIES.signature, CANARIES.account]);
  controls.push({ control: 'binding-negative', status: negative.status, detected: true });

  const wrongSecretSigned = signRequest(github, githubBody, { provider: 'github', secret: CANARIES.key });
  const wrongSecret = await invoke('/__controls/wrong-secret', wrongSecretSigned.headers, githubBody);

  checkRejection('control/wrong-secret', wrongSecret, 400, [CANARIES.key, CANARIES.signature]);
  controls.push({ control: 'wrong-secret', status: wrongSecret.status, detected: true });

  const malformed = await invoke(
    '/__controls/malformed-signature',
    { 'x-hub-signature-256': CANARIES.signature, 'content-type': 'application/json' },
    githubBody,
  );

  checkRejection('control/malformed-signature', malformed, 400, [CANARIES.signature, CANARIES.key]);
  controls.push({ control: 'malformed-signature', status: malformed.status, detected: true });

  const falBody = validBodyFor(fal);
  const falSigned = signRequest(fal, falBody);
  const wrongAccount = await invoke('/__controls/wrong-account-canary', falSigned.headers, falBody);

  checkRejection('control/wrong-account', wrongAccount, 400, [CANARIES.account, CANARIES.signature]);
  controls.push({ control: 'wrong-account', status: wrongAccount.status, detected: true });

  let assertionDetected = false;

  try {
    checkReceipt(
      'control/assertion-engine',
      { status: 400, text: 'Bad Request', json: null, downstream: 0 },
      githubBody,
      'express',
      githubSigned.identity,
    );
  } catch {
    assertionDetected = true;
  }

  assert(assertionDetected, 'The receipt assertion accepted a fabricated 400 for a valid case.');
  controls.push({ control: 'assertion-detects-bad-valid', status: null, detected: true });

  let registryDetected = false;

  try {
    assertExactRegistry(EXPECTED_PROVIDERS.slice(0, EXPECTED_PROVIDERS.length - 1));
  } catch {
    registryDetected = true;
  }

  assert(registryDetected, 'The registry assertion accepted a missing provider.');
  controls.push({ control: 'missing-provider-detected', status: null, detected: true });

  let orderDetected = false;

  try {
    assertExactRegistry([...EXPECTED_PROVIDERS].reverse());
  } catch {
    orderDetected = true;
  }

  assert(orderDetected, 'The registry assertion accepted a reordered provider list.');
  controls.push({ control: 'registry-order-detected', status: null, detected: true });

  return controls;
}

/* ------------------------------------------------------------------ *
 * Hono, Next.js and Cloudflare child surfaces
 * ------------------------------------------------------------------ */

async function runHono(spec) {
  const requireConsumer = createRequire(join(spec.consumerRoot, 'noop.cjs'));
  const honoModule = await import(pathToFileURL(requireConsumer.resolve('hono')).href);
  const Hono = honoModule.Hono ?? honoModule.default?.Hono;

  assert(Hono !== undefined, 'Hono could not be loaded from the installed consumer.');
  const app = new Hono();
  const counters = new Map();

  for (const entry of spec.entries) {
    const module = await import(entry.moduleUrl);
    const middleware = module[entry.exportName];

    assert(middleware !== undefined, `Hono middleware for ${entry.key} is missing.`);
    counters.set(entry.route, { calls: 0 });
    app.post(entry.route, middleware, (context) => {
      counters.get(entry.route).calls += 1;
      const verified = context.get('webhook');

      return context.json({
        received: true,
        bytes: verified.rawBody.byteLength,
        identity: verified.identity,
        bodyBase64: Buffer.from(verified.rawBody).toString('base64'),
      });
    });
  }

  const invoke = async (route, headers, body) => {
    counters.get(route).calls = 0;

    const response = await app.fetch(
      new Request(`http://localhost${route}`, { method: 'POST', headers, body }),
    );

    const text = await response.text();
    let json = null;

    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    return { status: response.status, text, json, downstream: counters.get(route).calls };
  };

  return { cases: await runCases(spec, invoke), controls: [] };
}

async function runNext(spec) {
  const modules = new Map();

  for (const entry of spec.entries) {
    const module = await import(entry.moduleUrl);

    assert(module[entry.exportName] !== undefined, `Next.js ${entry.exportName} for ${entry.key} is missing.`);
    modules.set(entry.route, module);
  }

  const originalJson = Response.json;
  let jsonCalls = 0;

  Response.json = function phase10InstrumentedJson(...args) {
    jsonCalls += 1;

    return originalJson.apply(Response, args);
  };

  try {
    const invoke = async (route, headers, body) => {
      const module = modules.get(route);

      jsonCalls = 0;

      const response = await module[specEntryExport(spec, route)](new Request(`http://localhost${route}`, {
        method: 'POST',
        headers,
        body,
      }));

      const text = await response.text();
      let json = null;

      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }

      return { status: response.status, text, json, downstream: jsonCalls };
    };

    return { cases: await runCases(spec, invoke), controls: [] };
  } finally {
    Response.json = originalJson;
  }
}

function specEntryExport(spec, route) {
  const entry = spec.entries.find((candidate) => candidate.route === route);

  assert(entry !== undefined, `No runtime entry for ${route}.`);

  return entry.exportName;
}

async function probeWorkerd() {
  const script = `export default {
    fetch() {
      return Response.json({
        userAgent: navigator.userAgent,
        hasProcess: typeof process !== 'undefined',
        hasBuffer: typeof Buffer !== 'undefined',
        nodeCompat: typeof globalThis.process !== 'undefined',
      });
    },
  };`;

  const runtime = new (await import('miniflare')).Miniflare({
    modules: true,
    script,
    compatibilityDate: COMPATIBILITY_DATE,
    compatibilityFlags: [],
  });

  try {
    return await (await runtime.dispatchFetch('https://phase10.test/facts')).json();
  } finally {
    await runtime.dispose();
  }
}

async function runCloudflare(spec) {
  const { Miniflare } = await import('miniflare');
  const cases = [];

  for (const entry of spec.entries) {
    const bindings = {};

    for (const variable of entry.env) bindings[variable.name] = variable.value;

    assert(entry.bundlePath !== null && existsSync(entry.bundlePath), `Missing Cloudflare bundle for ${entry.key}.`);
    const directory = dirname(entry.bundlePath);

    const runtime = new Miniflare({
      modules: true,
      modulesRoot: directory,
      scriptPath: entry.bundlePath,
      compatibilityDate: COMPATIBILITY_DATE,
      compatibilityFlags: [],
      bindings,
    });

    try {
      const initial = await (await runtime.dispatchFetch('https://phase10.test/__phase10/stats')).json();

      assert(initial.jsonCalls === 0, `Cloudflare instrumented consumer counter for ${entry.key} was not reset.`);

      const invoke = async (route, headers, body) => {
        await runtime.dispatchFetch('https://phase10.test/__phase10/reset');
        const response = await runtime.dispatchFetch(`https://phase10.test${route}`, { method: 'POST', headers, body });
        const text = await response.text();
        const stats = await (await runtime.dispatchFetch('https://phase10.test/__phase10/stats')).json();
        let json = null;

        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }

        return { status: response.status, text, json, downstream: stats.jsonCalls };
      };

      cases.push(...(await runCases({ ...spec, entries: [entry] }, invoke)));
    } finally {
      await runtime.dispose();
    }
  }

  return { cases, controls: [], facts: await probeWorkerd() };
}

/* ------------------------------------------------------------------ *
 * Child entry point
 * ------------------------------------------------------------------ */

function hydrateSpec(spec) {
  assert(spec.schemaVersion === 1, 'Unsupported runtime spec version.');
  assert(Array.isArray(spec.entries) && spec.entries.length > 0, 'Runtime spec has no entries.');
  assert(existsSync(spec.consumerRoot), 'Runtime spec consumer root is missing.');
  assert(spec.bodyLimit === BODY_LIMIT, 'Runtime spec body limit mismatch.');

  for (const entry of spec.entries) {
    assert(existsSync(fileURLToPath(entry.moduleUrl)), `Missing module for ${entry.key}.`);

    if (entry.provider === 'fal') {
      entry.profile.privateKey = createPrivateKey({
        key: Buffer.from(entry.profile.privateKeyBase64, 'base64'),
        format: 'der',
        type: 'pkcs8',
      });
    }
  }
}

function applySpecEnvironment(spec) {
  const expected = new Map();

  for (const entry of spec.entries) {
    for (const variable of entry.env) {
      assert(variable.name.length > 0 && variable.value.length > 0, `Empty environment entry for ${entry.key}.`);

      if (expected.has(variable.name)) {
        assert(
          expected.get(variable.name) === variable.value,
          `Conflicting environment values for ${variable.name}.`,
        );
        continue;
      }

      expected.set(variable.name, variable.value);
    }
  }

  for (const [name, value] of expected) process.env[name] = value;
}

async function childMain(specPath) {
  const spec = JSON.parse(readFileSync(specPath, 'utf8'));

  hydrateSpec(spec);
  applySpecEnvironment(spec);

  let outcome;

  if (spec.framework === 'express') outcome = await runExpress(spec);
  else if (spec.framework === 'hono') outcome = await runHono(spec);
  else if (spec.framework === 'nextjs') outcome = await runNext(spec);
  else if (spec.framework === 'cloudflare') outcome = await runCloudflare(spec);
  else fail(`Unsupported framework ${String(spec.framework)} in the runtime spec.`);

  const result = {
    runtimeLabel: spec.runtimeLabel,
    framework: spec.framework,
    runtime: process.version,
    cases: outcome.cases,
    controls: outcome.controls,
    facts: outcome.facts ?? null,
  };

  writeFileSync(spec.outputPath, `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(
    `PHASE10 CHILD OK ${spec.runtimeLabel}/${spec.framework} cases=${result.cases.length} controls=${result.controls.length}\n`,
  );
}

/* ------------------------------------------------------------------ *
 * Bounded child process execution
 * ------------------------------------------------------------------ */

const CASE_STATUS = { valid: 200, tamper: 400, overflow: 413, 'wrong-layout': 400 };

const CASES_PER_FRAMEWORK = {
  valid: EXPECTED_PROVIDERS.length + CONFIGURED_VARIANTS.length,
  tamper: EXPECTED_PROVIDERS.length,
  overflow: EXPECTED_PROVIDERS.length,
  'wrong-layout': CONFIGURED_VARIANTS.length,
};

const TOTAL_CASES_PER_FRAMEWORK = EXPECTED_PROVIDERS.length * PRIMARY_CASES_PER_HANDLER
  + CONFIGURED_VARIANTS.length * CONFIGURED_CASES_PER_HANDLER;

const EXPRESS_CONTROL_COUNT = 8;

function sanitizedChildEnvironment() {
  const secretLike = /SECRET|WEBHOOK|SIGNING|PUBLIC_KEYS|FAL_/i;
  const env = {};
  const removed = [];

  for (const [name, value] of Object.entries(process.env)) {
    if (value === undefined) continue;

    if (secretLike.test(name)) {
      removed.push(name);
      continue;
    }

    env[name] = value;
  }

  return { env, removed: removed.sort() };
}

function terminateTree(pid) {
  if (pid === undefined) return;

  if (process.platform === 'win32') {
    try {
      execFileSync('taskkill', ['/pid', String(pid), '/t', '/f'], { stdio: 'ignore', timeout: 30_000 });
    } catch {
      // Failure does not establish termination; the child-close ledger must confirm it.
    }

    return;
  }

  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // Already gone.
  }
}

function runBoundedChild(options, runtime = { spawn, setTimeout, clearTimeout, terminateTree, now: Date.now }) {
  return new Promise((resolvePromise) => {
    const started = runtime.now();
    const record = { pid: null, closed: false, spawnFailed: false, timedOut: false };

    options.ledger.push(record);
    let child;

    try {
      child = runtime.spawn(options.executable, [options.scriptPath, ...options.args], {
        cwd: options.cwd,
        env: options.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        detached: process.platform !== 'win32',
      });
      record.pid = child.pid ?? null;
    } catch (error) {
      record.spawnFailed = true;
      resolvePromise({
        ok: false,
        status: null,
        signal: null,
        timedOut: false,
        terminationConfirmed: true,
        stdout: '',
        stderr: `spawn failed: ${String(error)}`,
        durationMs: runtime.now() - started,
      });

      return;
    }

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let forceTimer;
    let timer;

    const settle = (status, signal, extra) => {
      if (settled) return;

      settled = true;
      runtime.clearTimeout(timer);

      if (forceTimer !== undefined) runtime.clearTimeout(forceTimer);
      resolvePromise({
        ok: !timedOut && status === 0 && extra === undefined,
        status,
        signal,
        timedOut,
        terminationConfirmed: record.closed || (record.spawnFailed && record.pid === null),
        stdout,
        stderr: extra === undefined ? stderr : `${stderr}\n${extra}`,
        durationMs: runtime.now() - started,
      });
    };

    timer = runtime.setTimeout(() => {
      timedOut = true;
      record.timedOut = true;
      runtime.terminateTree(child.pid);
      forceTimer = runtime.setTimeout(() => {
        runtime.terminateTree(child.pid);
        settle(null, null, 'the child did not close after forced termination');
      }, 20_000);
    }, options.timeoutMs);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-40_000);
    });
    child.on('error', (error) => {
      if (record.pid === null) record.spawnFailed = true;
      stderr = (stderr + `\nchild error: ${String(error)}`).slice(-40_000);
    });
    child.on('close', (status, signal) => {
      record.closed = true;
      settle(status, signal, undefined);
    });
  });
}

function assertCaseInventory(cases, providers, label) {
  const required = new Set();

  for (const provider of providers) {
    for (const name of ['valid', 'tamper', 'overflow']) required.add(`primary|${provider}|${name}`);
  }

  for (const variant of CONFIGURED_VARIANTS) {
    for (const name of ['valid', 'wrong-layout']) required.add(`configured|${variant.key}|${name}`);
  }

  for (const record of cases) {
    const tuple = `${record.kind}|${record.entry}|${record.case}`;

    assert(required.delete(tuple), `${label} recorded an unexpected or duplicate handler/case tuple ${tuple}.`);
  }

  assert(required.size === 0, `${label} omitted required handler/case tuples: ${[...required].join(', ')}.`);
}

function validateChildResult(execution, expectation) {
  assert(execution.terminationConfirmed === true, `${expectation.label} child termination is unconfirmed; preserve its workspace.`);
  const detail = execution.stderr.trim().length > 0 ? `\nchild stderr:\n${execution.stderr.trim()}` : '';

  assert(!execution.timedOut, `${expectation.label} timed out after ${execution.durationMs} ms.${detail}`);
  assert(execution.status === 0, `${expectation.label} exited with status ${String(execution.status)}${detail}`);
  assert(
    execution.stdout.includes(`PHASE10 CHILD OK ${expectation.runtimeLabel}/${expectation.framework}`),
    `${expectation.label} did not report a completed child run.${detail}`,
  );
  assert(existsSync(expectation.outputPath), `${expectation.label} wrote no result file.${detail}`);

  const result = JSON.parse(readFileSync(expectation.outputPath, 'utf8'));

  assert(result.runtimeLabel === expectation.runtimeLabel, `${expectation.label} result has the wrong runtime label.`);
  assert(result.framework === expectation.framework, `${expectation.label} result has the wrong framework.`);
  assert(
    result.runtime === expectation.runtimeVersion,
    `${expectation.label} ran on ${String(result.runtime)} instead of the pinned ${expectation.runtimeVersion}.`,
  );
  assert(Array.isArray(result.cases), `${expectation.label} result has no case list.`);
  assertCaseInventory(result.cases, expectation.providers, expectation.label);
  assert(
    result.cases.length === TOTAL_CASES_PER_FRAMEWORK,
    `${expectation.label} recorded ${result.cases.length} executions instead of ${TOTAL_CASES_PER_FRAMEWORK}.`,
  );

  const primaryKeys = new Set(expectation.providers);
  const configuredKeys = new Set(CONFIGURED_VARIANTS.map((variant) => variant.key));
  const seen = new Set();
  const counts = { valid: 0, tamper: 0, overflow: 0, 'wrong-layout': 0 };

  for (const record of result.cases) {
    const caseName = record.case;
    const id = `${String(record.entry)}|${String(caseName)}`;

    assert(!seen.has(id), `${expectation.label} duplicated the execution ${id}.`);
    seen.add(id);
    assert(Object.hasOwn(CASE_STATUS, caseName), `${expectation.label} recorded unknown case ${String(caseName)}.`);
    assert(
      record.status === CASE_STATUS[caseName],
      `${expectation.label} ${id} returned ${String(record.status)} instead of ${CASE_STATUS[caseName]}.`,
    );

    if (record.kind === 'primary') {
      assert(
        primaryKeys.has(record.entry),
        `${expectation.label} ran a primary case for unknown provider ${String(record.entry)}.`,
      );
    } else {
      assert(record.kind === 'configured', `${expectation.label} recorded unknown handler kind ${String(record.kind)}.`);
      assert(
        configuredKeys.has(record.entry),
        `${expectation.label} ran a configured case for unknown variant ${String(record.entry)}.`,
      );
    }

    counts[caseName] += 1;
  }

  for (const caseName of Object.keys(CASES_PER_FRAMEWORK)) {
    assert(
      counts[caseName] === CASES_PER_FRAMEWORK[caseName],
      `${expectation.label} ran ${counts[caseName]} ${caseName} cases instead of ${CASES_PER_FRAMEWORK[caseName]}.`,
    );
  }

  assert(
    seen.size === result.cases.length,
    `${expectation.label} did not execute every handler/case pair exactly once.`,
  );

  if (expectation.framework === 'express') {
    assert(Array.isArray(result.controls), `${expectation.label} recorded no control list.`);
    assert(
      result.controls.length === EXPRESS_CONTROL_COUNT,
      `${expectation.label} recorded ${result.controls.length} controls instead of ${EXPRESS_CONTROL_COUNT}.`,
    );

    for (const control of result.controls) {
      assert(control.detected === true, `${expectation.label} control ${String(control.control)} was not detected.`);
    }
  } else {
    assert(result.controls.length === 0, `${expectation.label} recorded unexpected controls.`);
  }

  if (expectation.framework === 'cloudflare') {
    const facts = result.facts;

    assert(facts !== null && facts !== undefined && !Array.isArray(facts), `${expectation.label} recorded no workerd facts.`);
    assert(facts.hasProcess === false, `${expectation.label} ran with a Node process global inside workerd.`);
    assert(facts.hasBuffer === false, `${expectation.label} ran with a Node Buffer global inside workerd.`);
    assert(facts.nodeCompat === false, `${expectation.label} enabled Node compatibility inside workerd.`);
    assert(
      /workerd|cloudflare/i.test(String(facts.userAgent)),
      `${expectation.label} user agent ${String(facts.userAgent)} is not workerd.`,
    );
  }

  return {
    runtimeLabel: expectation.runtimeLabel,
    runtimeVersion: result.runtime,
    framework: expectation.framework,
    cases: result.cases,
    controls: result.controls,
    facts: result.facts ?? null,
    durationMs: execution.durationMs,
  };
}

/* ------------------------------------------------------------------ *
 * Repository and dependency integrity
 * ------------------------------------------------------------------ */

function hashFileIfPresent(name) {
  const file = join(REPO_ROOT, name);

  return existsSync(file) ? sha256hex(readFileSync(file)) : null;
}

function snapshotRepoState() {
  const trackedFiles = gitOutput(['ls-files', '-z']).split('\0').filter(Boolean);

  return {
    status: gitOutput(['status', '--porcelain']),
    head: gitOutput(['rev-parse', 'HEAD']),
    src: fingerprintTree(join(REPO_ROOT, 'src')),
    tests: fingerprintTree(join(REPO_ROOT, 'tests')),
    dist: fingerprintTree(join(REPO_ROOT, 'dist')),
    tracked: sha256hex(utf8(trackedFiles.map((name) => `${name}:${hashFileIfPresent(name)}`).join('\n'))),
    files: Object.fromEntries(
      ['package.json', 'package-lock.json', 'tsconfig.json', '.oxlintrc.json', 'eslint.config.mjs']
        .map((name) => [name, hashFileIfPresent(name)]),
    ),
  };
}

function verifyRepoIntegrity(before, after) {
  assert(before.head === after.head, 'HEAD changed while the runtime matrix was running.');
  assert(before.status === after.status, 'The repository working tree changed while the runtime matrix was running.');
  assert(before.src === after.src, 'The tracked source tree changed while the runtime matrix was running.');
  assert(before.tests === after.tests, 'The tracked test tree changed while the runtime matrix was running.');
  assert(before.dist === after.dist, 'The build output changed while the runtime matrix was running.');
  assert(before.tracked === after.tracked, 'A tracked file changed while the runtime matrix was running.');
  assert(deepEqual(before.files, after.files), 'A tracked root configuration file changed while the runtime matrix was running.');
}

function verifyDependencyIntegrity(workspace) {
  for (const record of workspace.dependencyStats) {
    assert(
      fingerprintTree(record.target) === record.fingerprint,
      `Read-only dependency ${record.label} was modified by the run.`,
    );
  }

  for (const junction of workspace.junctions) {
    assert(existsSync(junction.target), `Read-only dependency target disappeared: ${junction.target}.`);
  }

  return workspace.dependencyStats.map((record) => record.label);
}

function assertChildrenClosed(children) {
  for (const child of children) {
    assert(
      child.closed || (child.spawnFailed && child.pid === null),
      `Child ${String(child.pid)} has not confirmed close; preserve the workspace and its junctions.`,
    );
  }
}

function cleanupWorkspace(workspace) {
  assertChildrenClosed(workspace.children);
  const removed = [];

  for (const junction of [...workspace.junctions].reverse()) {
    try {
      const stat = lstatSync(junction.link);

      assert(stat.isSymbolicLink(), `${junction.link} is not a junction.`);
      unlinkSync(junction.link);
    } catch {
      // Removing the temporary root recursively would follow the junction, so a
      // junction that cannot be unlinked means the root must be retained.
      fail(`Could not remove the dependency junction ${junction.link}.`);
    }

    assert(!existsSync(junction.link), `Dependency junction ${junction.link} still exists.`);
    assert(existsSync(junction.target), `Dependency target ${junction.target} disappeared during cleanup.`);
    removed.push(junction.label);
  }

  assert(
    !existsSync(join(workspace.consumerRoot, 'node_modules', 'express')),
    'A dependency junction survived cleanup.',
  );

  rmSync(workspace.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  assert(!existsSync(workspace.root), `Temporary workspace ${workspace.root} was not removed.`);

  return removed;
}

/* ------------------------------------------------------------------ *
 * Crash and timeout controls for the bounded runner
 * ------------------------------------------------------------------ */

function writeControlScripts(workspace) {
  const directory = join(workspace.root, 'controls');

  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'crash.mjs'), 'process.exit(9);\n');
  writeFileSync(join(directory, 'hang.mjs'), 'setTimeout(() => { process.exit(0); }, 120_000);\n');

  return directory;
}

function assertTimeoutTermination(hang) {
  assert(hang.ok === false, 'The bounded runner treated a hanging child as a success.');
  assert(hang.timedOut === true, 'The bounded runner did not record the hang timeout.');
  assert(hang.terminationConfirmed === true, 'Hang control termination is unconfirmed; preserve its workspace.');
  assert(
    hang.signal !== null || (hang.status !== null && hang.status !== 0),
    'The hang control did not confirm abnormal termination after its timeout.',
  );
  assert(hang.durationMs < 60_000, `The hanging control child took ${hang.durationMs} ms to terminate.`);
}

async function proveBoundedChildFailure(workspace, executable, baseEnv) {
  const directory = writeControlScripts(workspace);
  const controls = [];

  const crash = await runBoundedChild({
    ledger: workspace.children,
    executable,
    scriptPath: join(directory, 'crash.mjs'),
    args: [],
    cwd: workspace.root,
    env: baseEnv,
    timeoutMs: 60_000,
  });

  assert(crash.ok === false, 'The bounded runner treated a crashing child as a success.');
  assert(crash.terminationConfirmed === true && !crash.timedOut, 'Crash control did not close before its timeout.');
  assert(crash.status === 9, `The crashing control child exited with ${String(crash.status)} instead of 9.`);
  controls.push({ control: 'child-crash-detected', exitStatus: crash.status, detected: true });

  const hang = await runBoundedChild({
    ledger: workspace.children,
    executable,
    scriptPath: join(directory, 'hang.mjs'),
    args: [],
    cwd: workspace.root,
    env: baseEnv,
    timeoutMs: HANG_CONTROL_TIMEOUT_MS,
  });

  assertTimeoutTermination(hang);
  assertChildrenClosed(workspace.children);
  controls.push({ control: 'child-timeout-detected', timedOut: true, terminationConfirmed: hang.terminationConfirmed, durationMs: hang.durationMs, detected: true });

  const runnerStillUsable = await runBoundedChild({
    ledger: workspace.children,
    executable,
    scriptPath: join(directory, 'crash.mjs'),
    args: [],
    cwd: workspace.root,
    env: baseEnv,
    timeoutMs: 60_000,
  });

  assert(
    runnerStillUsable.status === 9 && runnerStillUsable.terminationConfirmed && !runnerStillUsable.timedOut,
    'The bounded runner stopped reporting closed crash statuses after a forced kill.',
  );

  return controls;
}

/* ------------------------------------------------------------------ *
 * Parent orchestration
 * ------------------------------------------------------------------ */

function assertControlRejects(action, message) {
  let detected = false;

  try {
    action();
  } catch (error) {
    if (!(error instanceof HarnessError)) throw error;
    detected = true;
  }

  assert(detected, message);
}

async function runPureControls() {
  const cases = [];

  for (const provider of EXPECTED_PROVIDERS) {
    for (const name of ['valid', 'tamper', 'overflow']) cases.push({ kind: 'primary', entry: provider, case: name });
  }

  for (const variant of CONFIGURED_VARIANTS) {
    for (const name of ['valid', 'wrong-layout']) cases.push({ kind: 'configured', entry: variant.key, case: name });
  }

  assertCaseInventory(cases, EXPECTED_PROVIDERS, 'control/exact-inventory');
  const swapped = cases.map((record) => ({ ...record }));

  swapped.find((record) => record.entry === 'github' && record.case === 'tamper').case = 'wrong-layout';
  swapped.find((record) => record.entry === 'grafana-timestamped' && record.case === 'wrong-layout').case = 'tamper';
  assertControlRejects(
    () => assertCaseInventory(swapped, EXPECTED_PROVIDERS, 'control/swapped-inventory'),
    'The exact inventory assertion accepted swapped primary/configured cases.',
  );

  const ledger = [];
  const timers = new Map();
  const child = new EventEmitter();

  child.pid = 12345;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdout.setEncoding = () => {};

  child.stderr.setEncoding = () => {};

  let elapsed = 0;
  let nextTimer = 0;
  let killAttempts = 0;

  const runtime = {
    spawn: () => child,
    now: () => elapsed,
    setTimeout: (callback, delay) => {
      const timer = ++nextTimer;

      timers.set(timer, { callback, delay });

      return timer;
    },
    clearTimeout: (timer) => timers.delete(timer),
    terminateTree: () => { killAttempts += 1; },
  };

  const pending = runBoundedChild({
    executable: 'control-only', scriptPath: 'control-only', args: [], cwd: '.', env: {},
    timeoutMs: HANG_CONTROL_TIMEOUT_MS, ledger,
  }, runtime);

  while (timers.size > 0) {
    const [id, timer] = timers.entries().next().value;

    timers.delete(id);
    elapsed += timer.delay;
    timer.callback();
  }

  const uncertain = await pending;

  assert(killAttempts === 2 && uncertain.timedOut && !uncertain.terminationConfirmed, 'Unclosed-child control did not exercise both failed termination attempts.');
  assertControlRejects(() => assertTimeoutTermination(uncertain), 'The timeout assertion accepted an unclosed child.');
  assertControlRejects(() => assertChildrenClosed(ledger), 'Cleanup accepted a ledger containing an unclosed child.');
  child.emit('close', null, 'SIGKILL');
  assertChildrenClosed(ledger);
  const crash = { ok: false, timedOut: false, terminationConfirmed: true, status: 9, signal: null, durationMs: 1 };

  assertControlRejects(() => assertTimeoutTermination(crash), 'The timeout assertion accepted a crash without a timeout.');
  assertTimeoutTermination({ ...crash, timedOut: true, signal: 'SIGKILL', status: null });
  process.stdout.write('PHASE10 PURE CONTROLS PASS exact-inventory swapped-case unconfirmed-termination cleanup-ledger crash-is-not-timeout\n');
}

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

function assertRuntimeOption(value) {
  if (value !== 'both' && value !== 'node24' && value !== 'node22' && value !== 'current') {
    throw new UsageError(`--runtime must be one of current, both, node24 or node22 (received ${String(value)}).`);
  }
}

function parseArgs(argv) {
  const options = { runtime: 'current', keepTemp: false };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--keep-temp') {
      options.keepTemp = true;
      continue;
    }

    if (argument === '--runtime') {
      const value = argv[index + 1];

      assertRuntimeOption(value);
      options.runtime = value;
      index += 1;
      continue;
    }

    if (argument.startsWith('--runtime=')) {
      const value = argument.slice('--runtime='.length);

      assertRuntimeOption(value);
      options.runtime = value;
      continue;
    }

    throw new UsageError(`Unknown argument: ${argument}`);
  }

  return options;
}

function writeResultsNote(summary) {
  const directory = join(REPO_ROOT, 'notes', 'phase-10');

  mkdirSync(directory, { recursive: true });

  const target = join(directory, 'coordinator-generated-runtime-results.json');

  writeFileSync(target, `${JSON.stringify(summary, null, 2)}\n`);

  return relative(REPO_ROOT, target).replaceAll('\\', '/');
}

function summarise(results) {
  const executions = results.reduce((total, result) => total + result.cases.length, 0);

  const primaryExecutions = results.reduce(
    (total, result) => total + result.cases.filter((record) => record.kind === 'primary').length,
    0,
  );

  const configuredExecutions = results.reduce(
    (total, result) => total + result.cases.filter((record) => record.kind === 'configured').length,
    0,
  );

  return {
    executions,
    primaryExecutions,
    configuredExecutions,
    controls: results.reduce((total, result) => total + result.controls.length, 0),
    perRuntime: [...new Set(results.map((result) => result.runtimeLabel))].map((label) => {
      const runtimeResults = results.filter((result) => result.runtimeLabel === label);

      return {
        runtimeLabel: label,
        runtime: runtimeResults[0].runtimeVersion,
        executions: runtimeResults.reduce((total, result) => total + result.cases.length, 0),
        controls: runtimeResults.reduce((total, result) => total + result.controls.length, 0),
      };
    }),
  };
}

async function main(argv) {
  const options = parseArgs(argv);
  const startedAt = Date.now();
  const preflightState = preflight(options.runtime);

  if (process.env.NODE_OPTIONS !== undefined) {
    assert(
      !process.env.NODE_OPTIONS.includes('preserve-symlinks'),
      'NODE_OPTIONS must not enable --preserve-symlinks; junction resolution is part of the contract.',
    );
  }

  requireBuildArtifacts();

  const providers = await loadRegistryProviders();
  const anchorProof = await proveAnchors(providers);
  const repoBefore = snapshotRepoState();
  const childEnvironment = sanitizedChildEnvironment();

  const runtimeSelection = preflightState.runtimes;
  const pinnedRoot = realpathSync(join(REPO_ROOT, 'node_modules'));

  assert(existsSync(pinnedRoot), 'The pinned read-only dependency root is missing.');

  const workspace = createWorkspace();
  const results = [];
  let cleaned = false;

  try {
    packAndInstall(workspace);

    for (const name of ['express', 'hono', 'miniflare']) {
      linkPinnedDependency(workspace, pinnedRoot, name);
    }

    const handlers = generateHandlers(workspace, providers);
    const transpiled = await transpileHandlers(workspace, handlers);

    await bundleCloudflareHandlers(workspace, transpiled);

    const fal = createFalCredentials();
    const scriptPath = fileURLToPath(import.meta.url);

    for (const runtime of runtimeSelection) {
      for (const framework of FRAMEWORKS) {
        const spec = await writeRuntimeSpec(workspace, runtime.label, framework, transpiled, fal);

        const execution = await runBoundedChild({
          ledger: workspace.children,
          executable: runtime.executable,
          scriptPath,
          args: ['--child', spec.specPath],
          cwd: workspace.root,
          env: childEnvironment.env,
          timeoutMs: CHILD_TIMEOUT_MS,
        });

        const label = `${runtime.label}/${framework}`;

        results.push(
          validateChildResult(execution, {
            label,
            runtimeLabel: runtime.label,
            runtimeVersion: runtime.version,
            framework,
            providers,
            outputPath: spec.outputPath,
          }),
        );
        process.stdout.write(`PHASE10 ${label} ok executions=${TOTAL_CASES_PER_FRAMEWORK}\n`);
      }
    }

    const summary = summarise(results);

    assert(
      summary.executions === MINIMUM_EXECUTIONS_PER_RUNTIME * runtimeSelection.length,
      `The matrix executed ${summary.executions} cases; ${MINIMUM_EXECUTIONS_PER_RUNTIME * runtimeSelection.length} were required.`,
    );
    assert(
      providers.length * FRAMEWORKS.length + CONFIGURED_VARIANTS.length * FRAMEWORKS.length === 92,
      'The handler total is not the reviewed 92.',
    );
    assert(
      summary.primaryExecutions === EXPECTED_PROVIDERS.length * PRIMARY_CASES_PER_HANDLER * FRAMEWORKS.length * runtimeSelection.length,
      'Primary executions are not 63 per framework per runtime.',
    );
    assert(
      summary.configuredExecutions
        === CONFIGURED_VARIANTS.length * CONFIGURED_CASES_PER_HANDLER * FRAMEWORKS.length * runtimeSelection.length,
      'Configured executions are not 4 per framework per runtime.',
    );
    assert(summary.controls === EXPRESS_CONTROL_COUNT * runtimeSelection.length, 'The Express control total is wrong.');

    const childControls = await proveBoundedChildFailure(
      workspace,
      runtimeSelection[0].executable,
      childEnvironment.env,
    );

    const dependencyIntegrity = verifyDependencyIntegrity(workspace);

    verifyRepoIntegrity(repoBefore, snapshotRepoState());

    const removedJunctions = cleanupWorkspace(workspace);

    cleaned = true;
    assert(
      removedJunctions.length === 3 && removedJunctions.every((name) => ['express', 'hono', 'miniflare'].includes(name)),
      'Cleanup did not remove every dependency junction.',
    );

    const answer = {
      schemaVersion: 1,
      phase: 'phase-10',
      owner: OWNER,
      branch: preflightState.branch,
      baseSha: BASE_SHA,
      head: preflightState.head,
      authoringClaimRequired: false,
      generatedAt: new Date().toISOString(),
      result: 'PASS',
      durationMs: Date.now() - startedAt,
      runtimes: summary.perRuntime,
      providerOrder: providers,
      frameworks: FRAMEWORKS,
      bodyLimit: BODY_LIMIT,
      overflowBytes: OVERFLOW_BYTES,
      casePolicy: {
        primary: ['valid', 'tamper', 'overflow'],
        configured: ['valid', 'wrong-layout'],
        caseStatus: CASE_STATUS,
        perFramework: CASES_PER_FRAMEWORK,
        totals: {
          executions: summary.executions,
          primaryExecutions: summary.primaryExecutions,
          configuredExecutions: summary.configuredExecutions,
          controls: summary.controls,
        },
      },
      configuredVariants: CONFIGURED_VARIANTS.map((variant) => ({
        key: variant.key,
        provider: variant.provider,
        cliArgs: variant.cliArgs,
      })),
      anchorProof,
      childControls,
      handlers: results.map((result) => ({
        runtimeLabel: result.runtimeLabel,
        framework: result.framework,
        cases: result.cases.length,
        controls: result.controls.length,
        durationMs: result.durationMs,
        facts: result.facts,
        executions: result.cases,
        controlsRecorded: result.controls,
      })),
      integrity: {
        dependencyJunctionsRemoved: removedJunctions,
        readOnlyDependencyPackageTreesVerified: dependencyIntegrity,
        childCloseConfirmed: workspace.children.map((child) => ({ ...child })),
        ambientSecretEnvironmentFiltered: childEnvironment.removed,
        repositoryUnchanged: true,
        temporaryWorkspaceRemoved: true,
      },
      limitations: [
        'Dependency content fingerprints cover the three linked package trees (express, hono, miniflare), not external transitive dependencies; nested links are recorded without traversing their targets.',
        'Generated Next.js and Cloudflare templates surface only {received, bytes}; their exact-byte proof is MAC acceptance over the transmitted bytes plus the returned byte length, not an identity deep-equal.',
        'Generated templates inject no clock, so each request is signed at wall-clock time immediately before it is sent; fixture timestamps are never replayed and no tolerance is widened.',
        'This harness proves runtime adapter behavior, not semantic TypeScript compilation of the generated files; the existing build and type gates own that.',
        'Cloudflare handlers are bundled by esbuild for a neutral platform and run in real workerd with empty Node compatibility flags; that is not a Cloudflare deployment test.',
      ],
    };

    const note = writeResultsNote(answer);

    process.stdout.write('PHASE10 RESULT PASS\n');
    process.stdout.write(`PHASE10 providers=${providers.length} frameworks=${FRAMEWORKS.length} executions=${summary.executions}\n`);

    for (const runtime of summary.perRuntime) {
      process.stdout.write(
        `PHASE10 runtime ${runtime.runtimeLabel} ${runtime.runtime} executions=${runtime.executions} controls=${runtime.controls}\n`,
      );
    }

    process.stdout.write(`PHASE10 note=${note}\n`);
  } finally {
    if (!cleaned) process.stderr.write(`PHASE10 WORKSPACE RETAINED ${workspace.root}\n`);
  }
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

const cliArgs = process.argv.slice(2);

if (cliArgs.length === 1 && cliArgs[0] === '--controls') {
  runPureControls().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
} else if (cliArgs[0] === '--child') {
  const specPath = cliArgs[1];

  if (specPath === undefined) {
    process.stderr.write('PHASE10 CHILD ERROR missing spec path\n');
    process.exitCode = 2;
  } else {
    childMain(specPath).catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
  }
} else {
  main(cliArgs).catch((error) => {
    if (error instanceof BlockedError) {
      process.stderr.write(`PHASE10 BLOCKED ${error.message}\n`);
      process.exitCode = 3;
    } else if (error instanceof UsageError) {
      process.stderr.write(`PHASE10 USAGE ${error.message}\n`);
      process.exitCode = 2;
    } else {
      process.stderr.write(`PHASE10 FAIL ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  });
}
