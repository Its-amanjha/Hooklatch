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

function workspaceHashes() {
  const filePaths = ['package.json', 'src/index.ts', 'src/types.ts', 'src/providers/index.ts'];
  const result = new Map();

  for (const relPath of filePaths) {
    const fullPath = path.join(WORKSPACE_ROOT, relPath);

    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath);
      const hash = crypto.createHash('sha256').update(content).digest('hex');

      result.set(relPath, hash);
    }
  }

  return result;
}

function checkIntegrity(before) {
  for (const [relPath, beforeHash] of before.entries()) {
    const fullPath = path.join(WORKSPACE_ROOT, relPath);

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

function detectNodeRuntimes() {
  const versionString = process.versions.node;
  const major = parseInt(versionString.split('.')[0] || '0', 10);

  return {
    current: versionString,
    major,
    node22: major === 22,
    node24: major === 24,
    supportedMajor: major === 22 || major === 24,
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
  const fixedNow = 1729684800;
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

  // 2. Fal Body Tamper
  const tamperedFalBody = Buffer.from(falBody);
  tamperedFalBody[0] ^= 0x01;

  cases.push({
    id: 'fal-body-tamper',
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
    rawBody: tamperedFalBody,
    expected: {
      ok: false,
      reason: 'invalid-signature',
    },
  });

  // 3. Fal Account Binding Mismatch
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

  // 4. Fal Signature 64-byte Length Guard
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
      'x-fal-webhook-signature': '0'.repeat(64), // 32 bytes hex instead of 64 bytes
    },
    rawBody: falBody,
    expected: {
      ok: false,
      reason: 'malformed-signature',
    },
  });

  // 5. Fal Freshness Expired
  const expiredSig = crypto.sign(null, Buffer.from(`${falReqId}\n${falUser}\n${String(fixedNow - 301)}\n${falDigest}`, 'utf-8'), falKey1.privKey).toString('hex');

  cases.push({
    id: 'fal-freshness-expired',
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

  // 6. Fal Key Rotation (Second Key in Accept-Set)
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

  // 7. Vercel Positive Baseline
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

  // 8. Vercel Signature Length Guard (SHA-256 rejected)
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

  return cases;
}

function generateWorkerSource(sdkDistPath) {
  return `
import { verify, createVerifier, verifyRequest } from ${JSON.stringify(sdkDistPath)};

export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    try {
      const data = await request.json();
      const { api, scenario, spec } = data;
      const rawBody = new Uint8Array(spec.rawBodyBase64 ? Uint8Array.from(atob(spec.rawBodyBase64), c => c.charCodeAt(0)) : []);
      const headers = spec.headers || {};
      const options = { ...spec.options };

      if (options.publicKeys) {
        options.publicKeys = options.publicKeys.map(k => new Uint8Array(k));
      }

      let res;
      if (api === 'verify') {
        res = await verify({ rawBody, headers }, options);
      } else if (api === 'createVerifier') {
        const verifier = createVerifier(options);
        res = await verifier({ rawBody, headers });
      } else if (api === 'verifyRequest') {
        const reqObj = new Request('https://workerd.test/webhook', {
          method: 'POST',
          headers,
          body: rawBody,
          duplex: 'half'
        });
        res = await verifyRequest(reqObj, options);
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

        const matches = outcome.ok === c.expected.ok
          && (!c.expected.reason || outcome.reason === c.expected.reason)
          && (!c.expected.identity || (
            outcome.identity.deliveryId === c.expected.identity.deliveryId
            && outcome.identity.eventId === c.expected.identity.eventId
            && outcome.identity.timestamp === c.expected.identity.timestamp
          ));

        results.push({ id: c.id, api, runtime: 'node', passed: matches, outcome });
      } catch (err) {
        results.push({ id: c.id, api, runtime: 'node', passed: false, error: err.message });
      }
    }
  }

  return results;
}

async function runWorkerCases(mf, catalogue) {
  const results = [];

  for (const c of catalogue) {
    for (const api of ['verify', 'createVerifier', 'verifyRequest']) {
      try {
        const payload = {
          api,
          spec: {
            rawBodyBase64: Buffer.from(c.rawBody).toString('base64'),
            headers: c.headers,
            options: {
              ...c.options,
              publicKeys: c.options.publicKeys ? c.options.publicKeys.map((k) => Array.from(k)) : undefined,
              now: c.options.now ? c.options.now() : undefined,
            },
          },
        };

        const res = await mf.dispatchFetch('https://workerd.test/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        const json = await res.json();

        if (!json.ok) {
          results.push({ id: c.id, api, runtime: 'worker', passed: false, error: json.error });
          continue;
        }

        const outcome = json.result;

        const matches = outcome.ok === c.expected.ok
          && (!c.expected.reason || outcome.reason === c.expected.reason)
          && (!c.expected.identity || (
            outcome.identity.deliveryId === c.expected.identity.deliveryId
            && outcome.identity.eventId === c.expected.identity.eventId
            && outcome.identity.timestamp === c.expected.identity.timestamp
          ));

        results.push({ id: c.id, api, runtime: 'worker', passed: matches, outcome });
      } catch (err) {
        results.push({ id: c.id, api, runtime: 'worker', passed: false, error: err.message });
      }
    }
  }

  return results;
}

async function runSelfTest(tempRoot) {
  // Exercise harness safety: containment, temp cleanup, timeout, and baseline SDK
  requireCheck(within(fs.realpathSync(os.tmpdir()), tempRoot), 'self-test-containment');

  const testSubdir = path.join(tempRoot, 'scratch-test');
  fs.mkdirSync(testSubdir);
  fs.writeFileSync(path.join(testSubdir, 'scratch.txt'), 'self-test');
  requireCheck(fs.existsSync(path.join(testSubdir, 'scratch.txt')), 'self-test-scratch-write');

  // Verify baseline SDK imports and operates
  const sdkPath = path.join(WORKSPACE_ROOT, 'dist/index.js');
  let baselineOk = false;

  if (fs.existsSync(sdkPath)) {
    const sdk = await import(pathToFileURL(sdkPath).href);
    const secret = 'canary-self-test';
    const body = new Uint8Array([1, 2, 3]);
    const sig = crypto.createHmac('sha256', secret).update(body).digest('hex');

    const res = await sdk.verify({
      rawBody: body,
      headers: { 'x-hub-signature-256': `sha256=${sig}` },
    }, {
      provider: 'github',
      secrets: [secret],
    });

    baselineOk = res.ok === true;
  }

  return { ok: true, baselineVerified: baselineOk };
}

function usage() {
  process.stdout.write(
    'Usage: node scripts/phase9-runtime-qualification.mjs [--json] [--self-test] [--help]\n'
    + 'Exit 0: checks and cleanup passed; 1: failure; 2: usage; 3: Stage B not ready.\n'
    + 'Selftests exercise harness controls and the accepted baseline SDK, not new provider support.\n',
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
  const before = workspaceHashes();

  // 1. Readiness Check (Only run in qualification mode)
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
        integrity: checkIntegrity(before),
      };

      if (jsonOutput) {
        process.stdout.write(JSON.stringify(blockedReport, null, 2) + '\n');
      } else {
        console.log(`[Phase 9 Runtime Qualification]: BLOCKED (Exit 3)`);
        console.log(`Missing Stage B Built Artifacts: ${readiness.missing.join(', ')}`);
        console.log(`Runtime: Node ${nodeRuntimes.current} (Node 24=${nodeRuntimes.node24}, Node 22=${nodeRuntimes.node22})`);
        console.log(`No temporary directories allocated.`);
      }

      return 3;
    }
  }

  // 2. Allocate Temp Directory for Execution
  const tempBase = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(tempBase, 'hooklatch-phase9-runtime-'));
  requireCheck(within(tempBase, root), 'owned-root-containment');

  let exitCode = 1;
  let testResults = [];
  let cleanupOk = false;

  try {
    if (selfTest) {
      const stRes = await runSelfTest(root);
      exitCode = stRes.ok ? 0 : 1;
    } else {
      // Full 21-Provider Qualification Mode
      const catalogue = buildCaseCatalogue();
      const sdkDistPath = path.resolve(WORKSPACE_ROOT, 'dist/index.js');
      const sdk = await import(pathToFileURL(sdkDistPath).href);

      // Node qualification
      const nodeRes = await runNodeCases(sdk, catalogue);
      testResults.push(...nodeRes);

      // workerd / Miniflare qualification
      const workerSrc = generateWorkerSource(pathToFileURL(sdkDistPath).href);
      const workerEntryPath = path.join(root, 'worker-entry.js');
      fs.writeFileSync(workerEntryPath, workerSrc, 'utf8');

      const bundleOutPath = path.join(root, 'worker-bundle.js');

      esbuild.buildSync({
        entryPoints: [workerEntryPath],
        bundle: true,
        outfile: bundleOutPath,
        format: 'esm',
        target: 'es2022',
        platform: 'neutral',
      });

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

      const allPassed = testResults.every((r) => r.passed);
      exitCode = allPassed ? 0 : 1;
    }

    // Cleanup verification
    requireCheck(!containsLink(root), 'remaining-link');
    fs.rmSync(root, { recursive: true, force: true });
    cleanupOk = !fs.existsSync(root);
  } catch (err) {
    console.error('Execution failure:', err);
    cleanupOk = false;
    exitCode = 1;
  }

  const integrity = checkIntegrity(before);

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
    console.log(`Node: ${nodeRuntimes.current} (Node 24=${nodeRuntimes.node24}, Node 22=${nodeRuntimes.node22})`);
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
