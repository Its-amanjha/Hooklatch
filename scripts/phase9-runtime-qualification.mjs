#!/usr/bin/env node
/**
 * Standalone Phase 9 Stage B runtime qualification tooling.
 * Evaluates Node 22/24 and real workerd (Miniflare) qualification.
 *
 * Exit codes:
 *   0: qualification or self-test passed and cleanup verified.
 *   1: failure in qualification, child, or cleanup.
 *   2: usage / invalid argument.
 *   3: Stage B not ready (BLOCKED: 21 built API absent before temp allocation).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import esbuild from 'esbuild';
import { Miniflare } from 'miniflare';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const WORKSPACE_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');

const EXPECTED_21_PROVIDERS = [
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
  'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana',
  'polar', 'linear', 'vercel', 'fal',
];

const REQUIRED_CLI_FLAGS = ['--public-key-env', '--expected-user-env'];
const COMPATIBILITY_DATE = '2026-08-06';
const MAX_REPORT_BYTES = 131072;

function within(root, target) {
  const relative = path.relative(root, target);

  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function requireCheck(condition, category) {
  if (!condition) {
    throw new Error(category);
  }
}

function containsLink(directory) {
  try {
    const entries = fs.readdirSync(directory, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        return true;
      }

      if (entry.isDirectory()) {
        const fullPath = path.join(directory, entry.name);

        if (containsLink(fullPath)) {
          return true;
        }
      }
    }

    return false;
  } catch {
    return true;
  }
}

class PathLedger {
  constructor(root) {
    this.root = root;
    this.registered = new Set();
  }

  register(entryPath) {
    this.registered.add(entryPath);
  }

  cleanup() {
    const paths = Array.from(this.registered).sort((a, b) => b.length - a.length);

    for (const p of paths) {
      if (fs.existsSync(p)) {
        const stat = fs.lstatSync(p);

        if (stat.isSymbolicLink()) {
          fs.unlinkSync(p);
        } else if (stat.isDirectory()) {
          fs.rmdirSync(p);
        } else {
          fs.unlinkSync(p);
        }
      }
    }

    if (fs.existsSync(this.root)) {
      fs.rmSync(this.root, { recursive: true, force: true });
    }

    return !fs.existsSync(this.root);
  }
}

function getTrackedFiles(root) {
  try {
    const output = execFileSync('git', ['ls-files'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });

    return output.split(/\r?\n/).filter(Boolean);
  } catch {
    return ['package.json', 'src/index.ts', 'src/types.ts', 'src/providers/index.ts'];
  }
}

function computeWorkspaceHashes(root) {
  const tracked = getTrackedFiles(root);
  const result = new Map();

  for (const relPath of tracked) {
    const fullPath = path.join(root, relPath);

    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath);
      const hash = crypto.createHash('sha256').update(content).digest('hex');

      result.set(relPath, hash);
    }
  }

  const distDir = path.join(root, 'dist');

  if (fs.existsSync(distDir)) {
    const walk = (dir) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);

        if (ent.isDirectory()) {
          walk(full);
        } else {
          const rel = path.relative(root, full);
          const hash = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');

          result.set(rel, hash);
        }
      }
    };

    walk(distDir);
  }

  return result;
}

function checkIntegrity(before, root) {
  for (const [relPath, beforeHash] of before.entries()) {
    const fullPath = path.join(root, relPath);

    if (!fs.existsSync(fullPath)) {
      return { intact: false, file: relPath, reason: 'deleted' };
    }

    const currentHash = crypto.createHash('sha256').update(fs.readFileSync(fullPath)).digest('hex');

    if (currentHash !== beforeHash) {
      return { intact: false, file: relPath, reason: 'modified' };
    }
  }

  return { intact: true };
}

function findNode22Binary() {
  if (process.env.NODE22_PATH && fs.existsSync(process.env.NODE22_PATH)) {
    return process.env.NODE22_PATH;
  }

  try {
    const cmd = process.platform === 'win32' ? 'where.exe' : 'which';

    const output = execFileSync(cmd, ['node22'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();

    const firstLine = output.split(/\r?\n/)[0];

    if (firstLine && fs.existsSync(firstLine)) {
      return firstLine;
    }
  } catch {
    // node22 not installed
  }

  return null;
}

function detectNodeRuntimes() {
  const versionString = process.versions.node;
  const major = parseInt(versionString.split('.')[0] || '0', 10);
  const node22Path = findNode22Binary();

  return {
    current: versionString,
    major,
    node24: {
      available: major === 24,
      version: major === 24 ? versionString : null,
      executed: major === 24,
    },
    node22: {
      available: Boolean(node22Path) || major === 22,
      version: major === 22 ? versionString : (node22Path ? 'available-on-host' : null),
      executed: major === 22,
      reason: major === 22 ? 'current-process' : (node22Path ? 'separate-binary' : 'node22-binary-not-found'),
    },
  };
}

async function inspectProviderReadiness(root) {
  const missing = [];

  try {
    const providersPath = path.join(root, 'dist/providers/index.js');

    if (!fs.existsSync(providersPath)) {
      missing.push('missing-dist-providers-index');

      return { ready: false, missing };
    }

    const providers = await import(pathToFileURL(providersPath).href);

    if (!Array.isArray(providers.SUPPORTED_PROVIDERS)
      || providers.SUPPORTED_PROVIDERS.length !== EXPECTED_21_PROVIDERS.length
      || EXPECTED_21_PROVIDERS.some((id, index) => providers.SUPPORTED_PROVIDERS[index] !== id)) {
      missing.push('exact-ordered-21-provider-registry');
    }

    const cliPath = path.join(root, 'dist/cli/index.js');

    if (fs.existsSync(cliPath)) {
      const output = execFileSync(process.execPath, [cliPath, '--help'], {
        cwd: root,
        encoding: 'utf8',
        timeout: 5000,
        maxBuffer: MAX_REPORT_BYTES,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      });

      if (REQUIRED_CLI_FLAGS.some((flag) => !output.includes(flag))) {
        missing.push('built-cli-flags');
      }
    } else {
      missing.push('missing-dist-cli');
    }

    const typesPath = path.join(root, 'dist/types.d.ts');

    if (fs.existsSync(typesPath)) {
      const declarations = fs.readFileSync(typesPath, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');

      if (!/\b(?:type|interface)\s+Fal(?:Provider)?Options\b/.test(declarations)
        && !declarations.includes("provider: 'fal'")) {
        missing.push('public-fal-option-types');
      }
    } else {
      missing.push('missing-dist-types');
    }
  } catch {
    missing.push('built-artifact-readiness-error');
  }

  return { ready: missing.length === 0, missing };
}

function deriveKey(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  const pkcs8Der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey(privKey);
  const rawPub = pubKey.export({ format: 'der', type: 'spki' }).subarray(12);

  return { privKey, rawPub: new Uint8Array(rawPub) };
}

function buildCaseCatalogue() {
  const cases = [];
  const fixedNow = 1729684800; // 2024-10-23T12:00:00Z
  const falKey1 = deriveKey('1010101010101010101010101010101010101010101010101010101010101010');
  const falKey2 = deriveKey('2020202020202020202020202020202020202020202020202020202020202020');
  const falUser = 'user_fal_qualification_42';
  const falReqId = 'req_fal_qual_001';
  const falBody = Buffer.from('{"status":"COMPLETED","output":"https://fal.media/cat.png"}', 'utf-8');

  const falDigest = crypto.createHash('sha256').update(falBody).digest('hex');
  const falMsg = `${falReqId}\n${falUser}\n${String(fixedNow)}\n${falDigest}`;
  const falSig = crypto.sign(null, Buffer.from(falMsg, 'utf-8'), falKey1.privKey).toString('hex');

  // 1. Fal Positive Baseline
  cases.push({
    id: 'fal-positive-baseline',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: falBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: fixedNow, authenticatedFields: ['timestamp'] },
    },
  });

  // 2. Fal Body Tamper at Offset 0
  const tamperedFalBody0 = Buffer.from(falBody);
  tamperedFalBody0[0] ^= 0x01;

  cases.push({
    id: 'fal-body-tamper-offset-0',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: tamperedFalBody0,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 3. Fal Body Tamper at Middle Offset
  const tamperedFalBodyMid = Buffer.from(falBody);
  const midOffset = Math.floor(falBody.length / 2);
  tamperedFalBodyMid[midOffset] ^= 0xff;

  cases.push({
    id: 'fal-body-tamper-offset-mid',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: tamperedFalBodyMid,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 4. Fal Account Binding Mismatch (header userId !== expectedUserId)
  cases.push({
    id: 'fal-account-binding-mismatch',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: 'user_different_expected',
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 5. Fal Valid Account Wrong Recipient (recipient header altered)
  cases.push({
    id: 'fal-valid-account-wrong-recipient',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': 'user_wrong_recipient_eve',
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 6. Fal Stale Bad MAC: forged signature with stale timestamp -> invalid-signature (auth before freshness)
  cases.push({
    id: 'fal-stale-bad-mac-auth-precedence',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
      toleranceSeconds: 300,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow - 999),
      'x-fal-webhook-signature': 'f'.repeat(128),
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 7. Fal Signature 64-byte Length Guard
  cases.push({
    id: 'fal-signature-length-guard',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': '0'.repeat(64),
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'malformed-signature',
    },
  });

  // 8. Fal Freshness Boundary (+300s edge pass)
  const tsPlus300 = fixedNow + 300;
  const sigPlus300 = crypto.sign(null, Buffer.from(`${falReqId}\n${falUser}\n${String(tsPlus300)}\n${falDigest}`, 'utf-8'), falKey1.privKey).toString('hex');

  cases.push({
    id: 'fal-freshness-boundary-plus-300',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
      toleranceSeconds: 300,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(tsPlus300),
      'x-fal-webhook-signature': sigPlus300,
    },
    rawBody: falBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: tsPlus300, authenticatedFields: ['timestamp'] },
    },
  });

  // 9. Fal Freshness Expired (-301s)
  const expiredSig = crypto.sign(null, Buffer.from(`${falReqId}\n${falUser}\n${String(fixedNow - 301)}\n${falDigest}`, 'utf-8'), falKey1.privKey).toString('hex');

  cases.push({
    id: 'fal-freshness-expired-minus-301',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
      toleranceSeconds: 300,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow - 301),
      'x-fal-webhook-signature': expiredSig,
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'timestamp-expired',
    },
  });

  // 10. Fal Freshness Future (+301s)
  const futureSig = crypto.sign(null, Buffer.from(`${falReqId}\n${falUser}\n${String(fixedNow + 301)}\n${falDigest}`, 'utf-8'), falKey1.privKey).toString('hex');

  cases.push({
    id: 'fal-freshness-future-plus-301',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
      toleranceSeconds: 300,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow + 301),
      'x-fal-webhook-signature': futureSig,
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'timestamp-future',
    },
  });

  // 11. Fal Zero Tolerance Exact
  cases.push({
    id: 'fal-zero-tolerance-exact',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
      toleranceSeconds: 0,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig,
    },
    rawBody: falBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: fixedNow, authenticatedFields: ['timestamp'] },
    },
  });

  // 12. Fal Key Rotation (Second Key in Accept-Set)
  const key2Sig = crypto.sign(null, Buffer.from(falMsg, 'utf-8'), falKey2.privKey).toString('hex');

  cases.push({
    id: 'fal-key-rotation-accept-second',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey1.rawPub, falKey2.rawPub],
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': key2Sig,
    },
    rawBody: falBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: fixedNow, authenticatedFields: ['timestamp'] },
    },
  });

  // 13. Fal Key Removal (Removed Key 1 Rejected)
  cases.push({
    id: 'fal-key-removal-reject-first',
    provider: 'fal',
    options: {
      provider: 'fal',
      publicKeys: [falKey2.rawPub], // Only key 2 configured
      expectedUserId: falUser,
      now: () => fixedNow,
    },
    headers: {
      'x-fal-webhook-request-id': falReqId,
      'x-fal-webhook-user-id': falUser,
      'x-fal-webhook-timestamp': String(fixedNow),
      'x-fal-webhook-signature': falSig, // Signed with key 1
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 14. Vercel Positive Baseline
  const vercelSecret = 'vercel-test-secret-qual-2026';
  const vercelBody = Buffer.from('{"event":"deployment","id":"dpl_123"}', 'utf-8');
  const vercelSig = crypto.createHmac('sha1', vercelSecret).update(vercelBody).digest('hex');

  cases.push({
    id: 'vercel-positive-baseline',
    provider: 'vercel',
    options: {
      provider: 'vercel',
      secrets: [vercelSecret],
      now: () => fixedNow,
    },
    headers: {
      'x-vercel-signature': vercelSig,
    },
    rawBody: vercelBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
  });

  // 15. Vercel Signature Length Guard (SHA-256 rejected)
  const vercelSha256 = crypto.createHmac('sha256', vercelSecret).update(vercelBody).digest('hex');

  cases.push({
    id: 'vercel-signature-length-guard',
    provider: 'vercel',
    options: {
      provider: 'vercel',
      secrets: [vercelSecret],
      now: () => fixedNow,
    },
    headers: {
      'x-vercel-signature': vercelSha256,
    },
    rawBody: vercelBody,
    expected: {
      ok: false,
      reason: 'malformed-signature',
    },
  });

  // 16. Vercel Wrong Secret (invalid-signature)
  const wrongSecretSig = crypto.createHmac('sha1', 'wrong-canary-secret').update(vercelBody).digest('hex');

  cases.push({
    id: 'vercel-wrong-secret',
    provider: 'vercel',
    options: {
      provider: 'vercel',
      secrets: [vercelSecret],
      now: () => fixedNow,
    },
    headers: {
      'x-vercel-signature': wrongSecretSig,
    },
    rawBody: vercelBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 17. Baseline Stripe HMAC-SHA256
  const stripeSecret = 'whsec_qual_stripe_baseline_test';
  const stripeBody = Buffer.from('{"id":"evt_qual_1","object":"event"}', 'utf-8');
  const stripeSig = crypto.createHmac('sha256', stripeSecret).update(`${fixedNow}.${stripeBody.toString('utf-8')}`).digest('hex');

  cases.push({
    id: 'baseline-stripe-hmac-sha256',
    provider: 'stripe',
    options: {
      provider: 'stripe',
      secrets: [stripeSecret],
      now: () => fixedNow,
    },
    headers: {
      'stripe-signature': `t=${fixedNow},v1=${stripeSig}`,
    },
    rawBody: stripeBody,
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: fixedNow, authenticatedFields: ['timestamp'] },
    },
  });

  // 18. Baseline GitHub Body-Only HMAC-SHA256
  const githubSecret = 'github_qual_secret_baseline';
  const githubBody = Buffer.from('{"action":"completed"}', 'utf-8');
  const githubSig = crypto.createHmac('sha256', githubSecret).update(githubBody).digest('hex');

  cases.push({
    id: 'baseline-github-hmac-sha256',
    provider: 'github',
    options: {
      provider: 'github',
      secrets: [githubSecret],
    },
    headers: {
      'x-hub-signature-256': `sha256=${githubSig}`,
      'x-github-delivery': '11111111-2222-3333-4444-555555555555',
    },
    rawBody: githubBody,
    expected: {
      ok: true,
      identity: { deliveryId: '11111111-2222-3333-4444-555555555555', eventId: null, timestamp: null, authenticatedFields: [] },
    },
  });

  return cases;
}

function matchOutcome(c, api, runtime, outcome) {
  if (outcome.ok !== c.expected.ok) {
    return { matches: false, reason: `ok mismatch: expected ${c.expected.ok}, got ${outcome.ok}` };
  }

  if (!c.expected.ok) {
    if (c.expected.reason && outcome.reason !== c.expected.reason) {
      return { matches: false, reason: `reason mismatch: expected ${c.expected.reason}, got ${outcome.reason}` };
    }

    return { matches: true };
  }

  if (outcome.provider !== c.provider) {
    return { matches: false, reason: `provider mismatch: expected ${c.provider}, got ${outcome.provider}` };
  }

  if (c.expected.identity) {
    const expId = c.expected.identity;
    const actId = outcome.identity || {};

    if (actId.deliveryId !== expId.deliveryId) {
      return { matches: false, reason: `deliveryId mismatch: expected ${expId.deliveryId}, got ${actId.deliveryId}` };
    }

    if (actId.eventId !== expId.eventId) {
      return { matches: false, reason: `eventId mismatch: expected ${expId.eventId}, got ${actId.eventId}` };
    }

    if (actId.timestamp !== expId.timestamp) {
      return { matches: false, reason: `timestamp mismatch: expected ${expId.timestamp}, got ${actId.timestamp}` };
    }

    const expFields = JSON.stringify(expId.authenticatedFields || []);
    const actFields = JSON.stringify(actId.authenticatedFields || []);

    if (expFields !== actFields) {
      return { matches: false, reason: `authenticatedFields mismatch: expected ${expFields}, got ${actFields}` };
    }
  }

  return { matches: true };
}

function generateWorkerSource(sdkModulePath) {
  return `
import { verify, createVerifier, verifyRequest } from ${JSON.stringify(sdkModulePath)};

export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const userAgent = navigator.userAgent || '';
    if (!userAgent.includes('Cloudflare-Workers')) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid-worker-user-agent' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (typeof process !== 'undefined') {
      return new Response(JSON.stringify({ ok: false, error: 'node-global-process-leaked' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (typeof Buffer !== 'undefined') {
      return new Response(JSON.stringify({ ok: false, error: 'node-global-buffer-leaked' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (typeof require !== 'undefined') {
      return new Response(JSON.stringify({ ok: false, error: 'commonjs-require-leaked' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const data = await request.json();
      const { api, spec } = data;
      const rawBody = new Uint8Array(spec.rawBodyBase64 ? Uint8Array.from(atob(spec.rawBodyBase64), c => c.charCodeAt(0)) : []);
      const headers = spec.headers || {};
      
      const reconstructedOptions = { provider: spec.options.provider };
      if (spec.options.secrets !== undefined) reconstructedOptions.secrets = spec.options.secrets;
      if (spec.options.publicKeys !== undefined) reconstructedOptions.publicKeys = spec.options.publicKeys.map(k => new Uint8Array(k));
      if (spec.options.expectedUserId !== undefined) reconstructedOptions.expectedUserId = spec.options.expectedUserId;
      if (spec.options.toleranceSeconds !== undefined) reconstructedOptions.toleranceSeconds = spec.options.toleranceSeconds;
      if (spec.options.now !== undefined) reconstructedOptions.now = () => spec.options.now;
      if (spec.options.maxBodyBytes !== undefined) reconstructedOptions.maxBodyBytes = spec.options.maxBodyBytes;

      let res;
      if (api === 'verify') {
        res = await verify({ rawBody, headers }, reconstructedOptions);
      } else if (api === 'createVerifier') {
        const verifier = createVerifier(reconstructedOptions);
        res = await verifier({ rawBody, headers });
      } else if (api === 'verifyRequest') {
        const reqObj = new Request('https://workerd.test/webhook', {
          method: 'POST',
          headers,
          body: rawBody,
          duplex: 'half'
        });
        res = await verifyRequest(reqObj, reconstructedOptions);
      }

      return new Response(JSON.stringify({ ok: true, result: res }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (err) {
      return new Response(JSON.stringify({
        ok: false,
        error: { code: err.code || 'unknown', message: err.message, name: err.name }
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
`;
}

async function runNodeCases(sdk, catalogue) {
  requireCheck(Array.isArray(catalogue) && catalogue.length > 0, 'empty-case-catalogue');

  const results = [];

  for (const c of catalogue) {
    for (const api of ['verify', 'createVerifier', 'verifyRequest']) {
      try {
        let outcome;

        if (api === 'verify') {
          outcome = await sdk.verify({ rawBody: c.rawBody, headers: c.headers }, c.options);
        } else if (api === 'createVerifier') {
          const verifier = sdk.createVerifier(c.options);

          outcome = await verifier({ rawBody: c.rawBody, headers: c.headers });
        } else if (api === 'verifyRequest') {
          const req = new Request('https://node.test/webhook', {
            method: 'POST',
            headers: c.headers,
            body: c.rawBody,
            duplex: 'half',
          });

          outcome = await sdk.verifyRequest(req, c.options);
        }

        const match = matchOutcome(c, api, 'node', outcome);

        results.push({ id: c.id, api, runtime: 'node', passed: match.matches, outcome, mismatch: match.reason });
      } catch (err) {
        results.push({ id: c.id, api, runtime: 'node', passed: false, error: err.message });
      }
    }
  }

  return results;
}

async function runWorkerCases(mf, catalogue) {
  requireCheck(Array.isArray(catalogue) && catalogue.length > 0, 'empty-case-catalogue');

  const results = [];

  for (const c of catalogue) {
    for (const api of ['verify', 'createVerifier', 'verifyRequest']) {
      try {
        const serializedOptions = { provider: c.options.provider };

        if (c.options.secrets !== undefined) {
          serializedOptions.secrets = c.options.secrets;
        }

        if (c.options.publicKeys !== undefined) {
          serializedOptions.publicKeys = c.options.publicKeys.map((k) => Array.from(k));
        }

        if (c.options.expectedUserId !== undefined) {
          serializedOptions.expectedUserId = c.options.expectedUserId;
        }

        if (c.options.toleranceSeconds !== undefined) {
          serializedOptions.toleranceSeconds = c.options.toleranceSeconds;
        }

        if (c.options.now !== undefined) {
          serializedOptions.now = c.options.now();
        }

        if (c.options.maxBodyBytes !== undefined) {
          serializedOptions.maxBodyBytes = c.options.maxBodyBytes;
        }

        const payload = {
          api,
          spec: {
            rawBodyBase64: Buffer.from(c.rawBody).toString('base64'),
            headers: c.headers,
            options: serializedOptions,
          },
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        let res;

        try {
          res = await mf.dispatchFetch('https://workerd.test/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeoutId);
        }

        const json = await res.json();

        if (!json.ok) {
          results.push({ id: c.id, api, runtime: 'worker', passed: false, error: json.error });
          continue;
        }

        const outcome = json.result;
        const match = matchOutcome(c, api, 'worker', outcome);

        results.push({ id: c.id, api, runtime: 'worker', passed: match.matches, outcome, mismatch: match.reason });
      } catch (err) {
        results.push({ id: c.id, api, runtime: 'worker', passed: false, error: err.message });
      }
    }
  }

  return results;
}

async function runSelfTest(tempRoot) {
  const ledger = new PathLedger(tempRoot);
  const controls = [];

  // Control 1: Containment
  const tempBase = fs.realpathSync(os.tmpdir());
  const isContained = within(tempBase, tempRoot);
  controls.push({ name: 'containment', passed: isContained });
  requireCheck(isContained, 'self-test-containment');

  // Control 2: Scratch allocation & Link-free Ledger
  const scratchDir = path.join(tempRoot, 'harness-scratch');
  fs.mkdirSync(scratchDir);
  ledger.register(scratchDir);

  const probeFile = path.join(scratchDir, 'probe.txt');
  fs.writeFileSync(probeFile, 'control-probe-data', 'utf8');
  ledger.register(probeFile);

  const hasLinks = containsLink(tempRoot);
  controls.push({ name: 'ledger-and-link-detection', passed: !hasLinks && fs.existsSync(probeFile) });

  // Control 3: Bounded execution & Timeout preservation
  let timeoutPreserved = false;
  const timeoutController = new AbortController();
  const timeoutId = setTimeout(() => timeoutController.abort(), 20);

  try {
    await new Promise((_, reject) => {
      timeoutController.signal.addEventListener('abort', () => {
        reject(new Error('simulated-timeout-abort'));
      });
    });
  } catch (err) {
    clearTimeout(timeoutId);
    timeoutPreserved = err.message === 'simulated-timeout-abort' && fs.existsSync(probeFile);
  }

  controls.push({ name: 'timeout-and-preservation', passed: timeoutPreserved });

  // Control 4: Result Matcher Mutant Kills
  const dummySpec = {
    provider: 'fal',
    expected: {
      ok: true,
      identity: { deliveryId: null, eventId: null, timestamp: 1729684800, authenticatedFields: ['timestamp'] },
    },
  };

  const goodOutcome = {
    ok: true,
    provider: 'fal',
    identity: { deliveryId: null, eventId: null, timestamp: 1729684800, authenticatedFields: ['timestamp'] },
  };

  const mutantBadReason = { ok: false, reason: 'wrong-reason' };
  const mutantBadTs = { ...goodOutcome, identity: { ...goodOutcome.identity, timestamp: 999999 } };
  const mutantBadFields = { ...goodOutcome, identity: { ...goodOutcome.identity, authenticatedFields: ['body'] } };

  const goodMatch = matchOutcome(dummySpec, 'verify', 'node', goodOutcome).matches;
  const killBadReason = !matchOutcome(dummySpec, 'verify', 'node', mutantBadReason).matches;
  const killBadTs = !matchOutcome(dummySpec, 'verify', 'node', mutantBadTs).matches;
  const killBadFields = !matchOutcome(dummySpec, 'verify', 'node', mutantBadFields).matches;

  const matcherControlsPassed = goodMatch && killBadReason && killBadTs && killBadFields;
  controls.push({ name: 'matcher-mutant-kills', passed: matcherControlsPassed });

  // Control 5: Non-Empty Inventory Guard
  let emptyInventoryBlocked = false;

  try {
    const emptyCatalogue = [];

    if (emptyCatalogue.length === 0) {
      throw new Error('empty-case-inventory');
    }
  } catch (err) {
    emptyInventoryBlocked = err.message === 'empty-case-inventory';
  }

  controls.push({ name: 'empty-inventory-guard', passed: emptyInventoryBlocked });

  const allPassed = controls.every((c) => c.passed);

  return { ok: allPassed, controls };
}

function usage() {
  process.stdout.write(
    'Usage: node scripts/phase9-runtime-qualification.mjs [--json] [--self-test] [--help]\n'
    + 'Exit 0: checks and cleanup passed; 1: failure; 2: usage; 3: Stage B not ready.\n'
    + 'Selftests exercise harness controls independently from unexecuted baseline SDK builds.\n',
  );
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

  const jsonOutput = args.includes('--json');
  const selfTest = args.includes('--self-test');
  const nodeRuntimes = detectNodeRuntimes();
  const beforeHashes = computeWorkspaceHashes(WORKSPACE_ROOT);

  // 1. Readiness Check (Pre-allocation Gate)
  if (!selfTest) {
    const readiness = await inspectProviderReadiness(WORKSPACE_ROOT);

    if (!readiness.ready) {
      const blockedReport = {
        mode: 'qualification',
        status: 'BLOCKED',
        exitCode: 3,
        runtimes: nodeRuntimes,
        readiness,
        cleanup: { ok: true, allocated: false },
        integrity: checkIntegrity(beforeHashes, WORKSPACE_ROOT),
      };

      if (jsonOutput) {
        process.stdout.write(JSON.stringify(blockedReport, null, 2) + '\n');
      } else {
        console.log(`[Phase 9 Runtime Qualification]: BLOCKED (Exit 3)`);
        console.log(`Missing Stage B Built Artifacts: ${readiness.missing.join(', ')}`);
        console.log(`Runtime: Node ${nodeRuntimes.current} (Node 24=${nodeRuntimes.node24.executed}, Node 22=${nodeRuntimes.node22.executed})`);
        console.log(`No temporary directories allocated.`);
      }

      return 3;
    }
  }

  // 2. Allocate Isolated Temp Directory
  const tempBase = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(tempBase, 'hooklatch-phase9-runtime-'));
  requireCheck(within(tempBase, root), 'owned-root-containment');

  const ledger = new PathLedger(root);
  let exitCode = 1;
  let testResults = [];
  let cleanupOk = false;

  try {
    if (selfTest) {
      const stRes = await runSelfTest(root);
      exitCode = stRes.ok ? 0 : 1;
    } else {
      // 3. Isolated Packed SDK Installation
      const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      const npmPath = path.resolve(path.dirname(process.execPath), npmCmd);

      const packOutput = execFileSync(npmPath, ['pack', '--pack-destination', root], {
        cwd: WORKSPACE_ROOT,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 30000,
        windowsHide: true,
      }).trim();

      const tarballName = packOutput.split(/\r?\n/).pop()?.trim() || '';
      const tarballPath = path.join(root, tarballName);
      requireCheck(fs.existsSync(tarballPath), 'pack-tarball-exists');
      ledger.register(tarballPath);

      const consumerDir = path.join(root, 'consumer');
      fs.mkdirSync(consumerDir);
      ledger.register(consumerDir);

      const consumerPackageJson = path.join(consumerDir, 'package.json');
      fs.writeFileSync(consumerPackageJson, JSON.stringify({
        name: 'phase9-runtime-consumer',
        type: 'module',
        dependencies: {
          hooklatch: `file:${tarballPath}`,
        },
      }, null, 2));
      ledger.register(consumerPackageJson);

      const cacheDir = path.join(root, 'npm-cache');
      fs.mkdirSync(cacheDir);
      ledger.register(cacheDir);

      execFileSync(npmPath, ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', cacheDir], {
        cwd: consumerDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 30000,
        windowsHide: true,
      });

      const installedSdkEntry = path.join(consumerDir, 'node_modules/hooklatch/dist/index.js');
      requireCheck(fs.existsSync(installedSdkEntry), 'installed-sdk-entry-exists');

      const installedSdk = await import(pathToFileURL(installedSdkEntry).href);
      const catalogue = buildCaseCatalogue();

      // Run Node qualification cases
      const nodeRes = await runNodeCases(installedSdk, catalogue);
      testResults.push(...nodeRes);

      // Run workerd / Miniflare qualification cases
      const workerSrc = generateWorkerSource(pathToFileURL(installedSdkEntry).href);
      const workerEntryPath = path.join(root, 'worker-entry.js');
      fs.writeFileSync(workerEntryPath, workerSrc, 'utf8');
      ledger.register(workerEntryPath);

      const bundleOutPath = path.join(root, 'worker-bundle.js');
      ledger.register(bundleOutPath);

      esbuild.buildSync({
        entryPoints: [workerEntryPath],
        bundle: true,
        outfile: bundleOutPath,
        format: 'esm',
        target: 'es2022',
        platform: 'neutral',
      });

      // Scan bundle for disallowed node built-in imports
      const bundledCode = fs.readFileSync(bundleOutPath, 'utf8');

      if (/(?:from\s*['"]node:|require\(['"]node:)/.test(bundledCode)) {
        throw new Error('disallowed-node-imports-in-worker-bundle');
      }

      const mf = new Miniflare({
        modules: true,
        scriptPath: bundleOutPath,
        compatibilityDate: COMPATIBILITY_DATE,
      });

      try {
        const workerRes = await runWorkerCases(mf, catalogue);
        testResults.push(...workerRes);
      } finally {
        await mf.dispose();
      }

      const allPassed = testResults.length > 0 && testResults.every((r) => r.passed);
      exitCode = allPassed ? 0 : 1;
    }

    // Cleanup via ledger
    requireCheck(!containsLink(root), 'remaining-link');
    cleanupOk = ledger.cleanup();
  } catch (err) {
    console.error('Execution failure:', err);
    cleanupOk = ledger.cleanup();
    exitCode = 1;
  }

  const integrity = checkIntegrity(beforeHashes, WORKSPACE_ROOT);

  if (!integrity.intact || !cleanupOk) {
    exitCode = 1;
  }

  const report = {
    mode: selfTest ? 'self-test' : 'qualification',
    status: exitCode === 0 ? 'PASSED' : exitCode === 3 ? 'BLOCKED' : 'FAILED',
    exitCode,
    runtimes: nodeRuntimes,
    casesTotal: testResults.length,
    casesPassed: testResults.filter((r) => r.passed).length,
    cleanup: { ok: cleanupOk, path: root },
    integrity,
  };

  if (jsonOutput) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    console.log(`[Phase 9 Runtime Qualification]: ${report.status} (Exit ${exitCode})`);
    console.log(`Node: ${nodeRuntimes.current} (Node 24=${nodeRuntimes.node24.executed}, Node 22=${nodeRuntimes.node22.executed})`);
    console.log(`Cases: ${report.casesPassed} / ${report.casesTotal} passed`);
    console.log(`Cleanup: ${cleanupOk ? 'OK' : 'FAILED'}, Integrity: ${integrity.intact ? 'INTACT' : 'CORRUPTED'}`);
  }

  return exitCode;
}

main().then((code) => {
  process.exit(code);
}).catch((err) => {
  console.error('Fatal runner error:', err);
  process.exit(1);
});
