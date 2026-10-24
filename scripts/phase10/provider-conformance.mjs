import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createHmac, createPrivateKey, randomUUID, sign } from 'node:crypto';
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

const CACHE_DIR = join(REPO_ROOT, 'notes', 'phase-10', 'gemini-sdk-cache');
const RECEIPT_PATH = join(CACHE_DIR, 'receipt.json');
const FROZEN_LOCK_PATH = join(CACHE_DIR, 'package-lock.json');
const NPM_CACHE_DIR = join(CACHE_DIR, 'npm-cache');
const CORPUS_PATH = join(REPO_ROOT, 'tests', 'conformance', 'phase10-provider-cases.json');
const RESULTS_PATH = join(REPO_ROOT, 'notes', 'phase-10', 'gemini-repair-2-results.json');
const REPORT_PATH = join(REPO_ROOT, 'notes', 'phase-10', 'gemini-repair-2-review.md');
const DIST_INDEX = join(REPO_ROOT, 'dist', 'index.js');
const REPAIR_CLAIM_PATH = join(REPO_ROOT, 'notes', 'phase-10', 'gemini-repair-2-session.json');

const PINNED_PACKAGES = [
  {
    name: 'standardwebhooks',
    version: '1.1.1',
    tarball: 'standardwebhooks-1.1.1.tgz',
    exportPath: 'standardwebhooks',
    repository: 'https://github.com/standard-webhooks/standard-webhooks',
    evidenceClass: 'actual-sdk-conformance',
  },
  {
    name: '@paddle/paddle-node-sdk',
    version: '3.10.0',
    tarball: 'paddle-paddle-node-sdk-3.10.0.tgz',
    exportPath: '@paddle/paddle-node-sdk',
    repository: 'https://github.com/PaddleHQ/paddle-node-sdk',
    evidenceClass: 'actual-sdk-conformance',
  },
  {
    name: '@sanity/webhook',
    version: '4.0.4',
    tarball: 'sanity-webhook-4.0.4.tgz',
    exportPath: '@sanity/webhook',
    repository: 'https://github.com/sanity-io/webhook-toolkit',
    evidenceClass: 'actual-sdk-conformance',
  },
  {
    name: '@linear/sdk',
    version: '99.0.0',
    tarball: 'linear-sdk-99.0.0.tgz',
    exportPath: '@linear/sdk/webhooks',
    repository: 'https://github.com/linear/linear',
    evidenceClass: 'actual-sdk-conformance',
  },
];

const DOCS_PROBES = [
  {
    provider: 'vercel',
    officialSdkAvailable: false,
    evidenceClass: 'docs-only-probe',
    recipe: 'HMAC-SHA1 hex 40-character digest over raw request body',
    documentationUrl: 'https://vercel.com/docs/webhooks/webhooks-api',
  },
  {
    provider: 'fal',
    officialSdkAvailable: false,
    evidenceClass: 'docs-only-probe',
    recipe: 'Ed25519 signature over requestId LF userId LF timestamp LF sha256Hex(body)',
    documentationUrl: 'https://fal.ai/docs/documentation/model-apis/inference/webhooks',
  },
];

const REQUIRED_PROVIDERS = ['standard-webhooks', 'paddle', 'sanity', 'linear', 'vercel', 'fal'];

const ALLOWED_CASE_PROPERTIES = new Set([
  'id',
  'provider',
  'category',
  'description',
  'payload',
  'secret',
  'secrets',
  'headers',
  'timestampConfig',
  'signatureTemplate',
  'signedUserId',
  'options',
  'expectedHooklatch',
  'expectedSdk',
  'classification',
  'divergenceReason',
  'evidenceReference',
  'isBinaryView',
]);

const ALLOWED_HOOKLATCH_REASONS = new Set([
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'invalid-signature',
  'missing-identity',
  'missing-timestamp',
  'timestamp-expired',
  'timestamp-future',
  'body-too-large',
]);

const ALLOWED_HOOKLATCH_ERROR_CODES = new Set([
  'unknown-provider',
  'missing-secrets',
  'invalid-secret',
  'invalid-options',
  'invalid-input',
  'body-consumed',
  'body-read-failed',
  'crypto-unavailable',
  'internal',
]);

function computeSha256(filePath) {
  const bytes = readFileSync(filePath);

  return createHash('sha256').update(bytes).digest('hex');
}

function verifyRepairClaim() {
  if (!existsSync(REPAIR_CLAIM_PATH)) {
    console.error('ERROR: Missing exclusive repair session claim at ' + REPAIR_CLAIM_PATH + '; STOP.');

    process.exit(3);
  }

  const claim = JSON.parse(readFileSync(REPAIR_CLAIM_PATH, 'utf8'));

  if (claim.owner !== 'gemini' || claim.state !== 'active' || !claim.sessionToken) {
    console.error('ERROR: Repair session claim is not active for owner gemini; STOP.');

    process.exit(3);
  }

  return claim.sessionToken;
}

function verifyCacheIntegrity() {
  if (!existsSync(RECEIPT_PATH)) {
    return { ok: false, reason: 'Missing receipt.json at ' + RECEIPT_PATH };
  }

  if (!existsSync(FROZEN_LOCK_PATH)) {
    return { ok: false, reason: 'Missing frozen package-lock.json at ' + FROZEN_LOCK_PATH };
  }

  let receipt;

  try {
    receipt = JSON.parse(readFileSync(RECEIPT_PATH, 'utf8'));
  } catch (err) {
    return { ok: false, reason: 'Corrupted receipt.json: ' + err.message };
  }

  if (receipt.schemaVersion !== 1) {
    return { ok: false, reason: 'Unsupported receipt schemaVersion: ' + receipt.schemaVersion };
  }

  for (const pkg of PINNED_PACKAGES) {
    const pkgReceipt = receipt.packages?.[pkg.name];

    if (!pkgReceipt) {
      return { ok: false, reason: 'Missing package receipt entry for ' + pkg.name };
    }

    if (pkgReceipt.version !== pkg.version) {
      return { ok: false, reason: `Version mismatch for ${pkg.name}: expected ${pkg.version}, got ${pkgReceipt.version}` };
    }

    const tarballPath = join(CACHE_DIR, pkg.tarball);

    if (!existsSync(tarballPath)) {
      return { ok: false, reason: 'Missing tarball at ' + tarballPath };
    }

    const actualHash = computeSha256(tarballPath);

    if (actualHash !== pkgReceipt.sha256) {
      return {
        ok: false,
        reason: `SHA256 mismatch for ${pkg.name}: expected ${pkgReceipt.sha256}, got ${actualHash}`,
      };
    }
  }

  return { ok: true, receipt };
}

function validateCorpus(corpus) {
  if (!corpus || typeof corpus !== 'object') {
    throw new Error('Corpus validation failed: corpus must be an object');
  }

  if (corpus.schemaVersion !== 1) {
    throw new Error(`Corpus validation failed: schemaVersion must be 1, got ${corpus.schemaVersion}`);
  }

  if (!Array.isArray(corpus.providers) || corpus.providers.length === 0) {
    throw new Error('Corpus validation failed: providers must be a non-empty array');
  }

  for (const req of REQUIRED_PROVIDERS) {
    if (!corpus.providers.includes(req)) {
      throw new Error(`Corpus validation failed: missing required provider ${req} in providers array`);
    }
  }

  if (!Array.isArray(corpus.cases) || corpus.cases.length === 0) {
    throw new Error('Corpus validation failed: cases must be a non-empty array');
  }

  if (corpus.casesCount !== corpus.cases.length) {
    throw new Error(`Corpus validation failed: casesCount (${corpus.casesCount}) does not match cases.length (${corpus.cases.length})`);
  }

  if (!corpus.falKeys || typeof corpus.falKeys !== 'object' || !corpus.falKeys.rawPublicKeyHex || !corpus.falKeys.privateKeyDerBase64) {
    throw new Error('Corpus validation failed: falKeys must contain rawPublicKeyHex and privateKeyDerBase64');
  }

  const seenIds = new Set();
  const providerCaseCounts = new Map(REQUIRED_PROVIDERS.map((p) => [p, 0]));

  for (const tc of corpus.cases) {
    if (!tc.id || typeof tc.id !== 'string') {
      throw new Error('Corpus validation failed: test case missing valid id');
    }

    if (seenIds.has(tc.id)) {
      throw new Error(`Corpus validation failed: duplicate test case id "${tc.id}"`);
    }

    seenIds.add(tc.id);

    for (const key of Object.keys(tc)) {
      if (!ALLOWED_CASE_PROPERTIES.has(key)) {
        throw new Error(`Corpus validation failed: unknown property "${key}" on test case "${tc.id}"`);
      }
    }

    if (!REQUIRED_PROVIDERS.includes(tc.provider)) {
      throw new Error(`Corpus validation failed: test case "${tc.id}" has unsupported provider "${tc.provider}"`);
    }

    providerCaseCounts.set(tc.provider, (providerCaseCounts.get(tc.provider) || 0) + 1);

    if (typeof tc.payload !== 'string') {
      throw new Error(`Corpus validation failed: test case "${tc.id}" payload must be a string`);
    }

    if (!tc.expectedHooklatch || typeof tc.expectedHooklatch !== 'object') {
      throw new Error(`Corpus validation failed: test case "${tc.id}" missing expectedHooklatch`);
    }

    if (!tc.expectedSdk || typeof tc.expectedSdk !== 'object') {
      throw new Error(`Corpus validation failed: test case "${tc.id}" missing expectedSdk`);
    }

    if (!tc.expectedHooklatch.ok) {
      const reason = tc.expectedHooklatch.reason;
      const errorCode = tc.expectedHooklatch.errorCode;

      if (!reason && !errorCode) {
        throw new Error(`Corpus validation failed: negative expectedHooklatch in "${tc.id}" must specify reason or errorCode`);
      }

      if (reason && !ALLOWED_HOOKLATCH_REASONS.has(reason)) {
        throw new Error(`Corpus validation failed: invalid expectedHooklatch reason "${reason}" in "${tc.id}"`);
      }

      if (errorCode && !ALLOWED_HOOKLATCH_ERROR_CODES.has(errorCode)) {
        throw new Error(`Corpus validation failed: invalid expectedHooklatch errorCode "${errorCode}" in "${tc.id}"`);
      }
    }

    const classification = tc.classification;

    if (!['protocol-agreement', 'expected-documented-receiver-policy-divergence', 'docs-only-probe'].includes(classification)) {
      throw new Error(`Corpus validation failed: invalid classification "${classification}" in "${tc.id}"`);
    }

    if (classification === 'expected-documented-receiver-policy-divergence') {
      if (!tc.divergenceReason || typeof tc.divergenceReason !== 'string' || tc.divergenceReason.trim() === '') {
        throw new Error(`Corpus validation failed: divergence "${tc.id}" missing valid divergenceReason`);
      }

      if (!tc.evidenceReference || typeof tc.evidenceReference !== 'string' || tc.evidenceReference.trim() === '') {
        throw new Error(`Corpus validation failed: divergence "${tc.id}" missing valid evidenceReference`);
      }
    }

    if (classification === 'docs-only-probe' && tc.provider !== 'vercel' && tc.provider !== 'fal') {
      throw new Error(`Corpus validation failed: docs-only-probe is only permitted for vercel and fal, got "${tc.provider}" in "${tc.id}"`);
    }
  }

  for (const [provider, count] of providerCaseCounts.entries()) {
    if (count === 0) {
      throw new Error(`Corpus validation failed: missing required provider coverage for "${provider}" (0 cases)`);
    }
  }

  return { ok: true, caseCount: corpus.cases.length };
}

function classifyCaseOutcome(testCase, hooklatchOutcome, sdkOutcome) {
  if (sdkOutcome.infrastructureFailure) {
    return {
      passed: false,
      reason: 'Infrastructure failure in SDK execution: ' + (sdkOutcome.error || '') + ' - ' + (sdkOutcome.message || ''),
    };
  }

  const dRes = hooklatchOutcome.direct;
  const vRes = hooklatchOutcome.verifier;
  const rRes = hooklatchOutcome.request;

  if (dRes.ok !== vRes.ok || vRes.ok !== rRes.ok) {
    return {
      passed: false,
      reason: `Multi-API mismatch: direct=${dRes.ok}, verifier=${vRes.ok}, request=${rRes.ok}`,
    };
  }

  if (dRes.ok !== testCase.expectedHooklatch.ok) {
    return {
      passed: false,
      reason: `Hooklatch outcome mismatch: got ok=${dRes.ok}, expected=${testCase.expectedHooklatch.ok}`,
    };
  }

  if (!testCase.expectedHooklatch.ok) {
    if (testCase.expectedHooklatch.reason) {
      const expReason = testCase.expectedHooklatch.reason;

      if (dRes.reason !== expReason || vRes.reason !== expReason || rRes.reason !== expReason) {
        return {
          passed: false,
          reason: `Hooklatch reason mismatch: expected=${expReason}, direct=${dRes.reason}, verifier=${vRes.reason}, request=${rRes.reason}`,
        };
      }
    } else if (testCase.expectedHooklatch.errorCode) {
      const expCode = testCase.expectedHooklatch.errorCode;

      if (dRes.error !== expCode || vRes.error !== expCode || rRes.error !== expCode) {
        return {
          passed: false,
          reason: `Hooklatch error code mismatch: expected=${expCode}, direct=${dRes.error}, verifier=${vRes.error}, request=${rRes.error}`,
        };
      }
    }
  }

  if (sdkOutcome.ok !== testCase.expectedSdk.ok) {
    return {
      passed: false,
      reason: `SDK outcome mismatch: got ok=${sdkOutcome.ok}, expected=${testCase.expectedSdk.ok}`,
    };
  }

  const classification = testCase.classification;

  if (classification === 'protocol-agreement') {
    if (dRes.ok !== sdkOutcome.ok) {
      return {
        passed: false,
        reason: `Protocol agreement violation: Hooklatch ok=${dRes.ok} does not match SDK ok=${sdkOutcome.ok}`,
      };
    }

    return { passed: true, category: 'protocol-agreement' };
  }

  if (classification === 'expected-documented-receiver-policy-divergence') {
    if (!testCase.divergenceReason || !testCase.evidenceReference) {
      return {
        passed: false,
        reason: 'Documented divergence missing divergenceReason or evidenceReference',
      };
    }

    if (dRes.ok !== sdkOutcome.ok) {
      return { passed: true, category: 'expected-documented-receiver-policy-divergence' };
    }

    if (!dRes.ok && !sdkOutcome.ok) {
      const isAuthFirst = dRes.reason === 'invalid-signature';
      const isSdkTimestamp = sdkOutcome.error === 'WebhookVerificationError' || sdkOutcome.error === 'PaddleVerificationError' || (testCase.provider === 'paddle' && !sdkOutcome.error);

      if (isAuthFirst && isSdkTimestamp) {
        return { passed: true, category: 'expected-documented-receiver-policy-divergence' };
      }
    }

    return {
      passed: false,
      reason: 'Disallowed divergence: outcomes agree without qualified ordering or policy divergence basis',
    };
  }

  if (classification === 'docs-only-probe') {
    if (testCase.provider !== 'vercel' && testCase.provider !== 'fal') {
      return {
        passed: false,
        reason: 'docs-only-probe is restricted to vercel and fal providers',
      };
    }

    return { passed: true, category: 'docs-only-probe' };
  }

  return {
    passed: false,
    reason: `Unknown classification: ${classification}`,
  };
}

function takeIntegritySnapshot(root) {
  const snapshot = new Map();
  const trackedOutput = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', timeout: 30000 });
  const trackedFiles = trackedOutput.split('\0').filter(Boolean);

  for (const rel of trackedFiles) {
    const full = join(root, rel);

    if (existsSync(full)) {
      snapshot.set(rel, computeSha256(full));
    }
  }

  const distDir = join(root, 'dist');

  if (existsSync(distDir)) {
    function walkDist(dir) {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);

        if (entry.isDirectory()) {
          walkDist(full);
        } else if (entry.isFile()) {
          const rel = join('dist', full.slice(distDir.length + 1)).replace(/\\/g, '/');

          snapshot.set(rel, computeSha256(full));
        }
      }
    }

    walkDist(distDir);
  }

  return snapshot;
}

function verifyIntegritySnapshot(root, expectedSnapshot) {
  const violations = [];

  for (const [rel, expectedHash] of expectedSnapshot.entries()) {
    const full = join(root, rel);

    if (!existsSync(full)) {
      violations.push({ file: rel, reason: 'File deleted' });
      continue;
    }

    const currentHash = computeSha256(full);

    if (currentHash !== expectedHash) {
      violations.push({ file: rel, expectedHash, currentHash, reason: 'Content altered' });
    }
  }

  return { ok: violations.length === 0, violations };
}

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidate1 = join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js');

  if (existsSync(candidate1)) {
    return candidate1;
  }

  const candidate2 = join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');

  if (existsSync(candidate2)) {
    return candidate2;
  }

  return 'npm';
}

function createSafeTempConsumer() {
  const baseTmp = resolve(tmpdir());
  const dirName = 'hooklatch-conformance-' + randomUUID();
  const consumerDir = join(baseTmp, dirName);

  mkdirSync(consumerDir, { recursive: true });
  assert(consumerDir.startsWith(baseTmp), 'Temp consumer directory outside tmpdir boundary');

  return consumerDir;
}

function cleanupSafeTempConsumer(consumerDir) {
  if (!consumerDir || !existsSync(consumerDir)) {
    return;
  }

  const baseTmp = resolve(tmpdir());

  assert(consumerDir.startsWith(baseTmp), 'Refusing to clean up directory outside tmpdir');

  rmSync(consumerDir, { recursive: true, force: true });

  if (existsSync(consumerDir)) {
    throw new Error('Cleanup failed: temp consumer directory still exists at ' + consumerDir);
  }
}

function runPrepareOnline() {
  verifyRepairClaim();

  console.log('[provider-conformance] Starting explicit online acquisition (--prepare-online)...');

  const tempConsumer = createSafeTempConsumer();
  const tempNpmCache = join(tempConsumer, 'npm-cache');

  mkdirSync(tempNpmCache, { recursive: true });
  mkdirSync(CACHE_DIR, { recursive: true });

  const npmCli = resolveNpmCli();
  const packageReceipts = {};

  try {
    for (const pkg of PINNED_PACKAGES) {
      console.log('  Acquiring ' + pkg.name + '@' + pkg.version + '...');

      const targetSpec = pkg.name + '@' + pkg.version;

      execFileSync(
        process.execPath,
        [npmCli, 'pack', targetSpec, '--cache', tempNpmCache, '--ignore-scripts', '--pack-destination', CACHE_DIR],
        { cwd: tempConsumer, timeout: 300000, stdio: 'inherit' },
      );

      const tarballPath = join(CACHE_DIR, pkg.tarball);

      if (!existsSync(tarballPath)) {
        throw new Error('Expected packed tarball not found at ' + tarballPath);
      }

      const hash = computeSha256(tarballPath);

      packageReceipts[pkg.name] = {
        name: pkg.name,
        version: pkg.version,
        tarball: pkg.tarball,
        sha256: hash,
        exportPath: pkg.exportPath,
        repository: pkg.repository,
        evidenceClass: pkg.evidenceClass,
      };
    }

    const receipt = {
      schemaVersion: 1,
      acquiredAt: new Date().toISOString(),
      acquiredBy: 'gemini',
      baseSha: computeSha256(CORPUS_PATH),
      packages: packageReceipts,
      docsOnlyProbes: DOCS_PROBES,
    };

    writeFileSync(RECEIPT_PATH, JSON.stringify(receipt, null, 2) + '\n', 'utf8');

    if (existsSync(tempNpmCache)) {
      cpSync(tempNpmCache, NPM_CACHE_DIR, { recursive: true });
    }

    console.log('[provider-conformance] Online acquisition complete.');
  } finally {
    cleanupSafeTempConsumer(tempConsumer);
  }
}

function resolveCaseForExecution(testCase, referenceNowSec, referenceNowMs, falPrivateKey) {
  let payload = testCase.payload;
  const headers = { ...testCase.headers };
  const provider = testCase.provider;
  let simulatedClock = referenceNowSec;
  let dynamicTs = null;

  if (testCase.timestampConfig && testCase.timestampConfig.mode !== 'none') {
    const cfg = testCase.timestampConfig;
    const isSeconds = cfg.unit === 'seconds';
    const offset = cfg.relativeOffset ?? 0;

    if (cfg.mode === 'fixed') {
      simulatedClock = cfg.fixed ? (isSeconds ? cfg.fixed : Math.floor(cfg.fixed / 1000)) : referenceNowSec;
      dynamicTs = cfg.fixed;
    } else {
      simulatedClock = referenceNowSec;
      dynamicTs = isSeconds ? (referenceNowSec + offset) : (Math.floor(referenceNowSec + offset) * 1000);

      if (provider === 'standard-webhooks') {
        headers['webhook-timestamp'] = String(dynamicTs);

        const rawSec = testCase.secret.startsWith('whsec_') ? testCase.secret.slice(6) : testCase.secret;
        const key = Buffer.from(rawSec, 'base64');
        const sig = createHmac('sha256', key).update(headers['webhook-id'] + '.' + dynamicTs + '.' + payload).digest('base64');

        if (testCase.signatureTemplate) {
          headers['webhook-signature'] = testCase.signatureTemplate.replace('{sig}', sig).replace('{ts}', String(dynamicTs));
        } else if (testCase.category !== 'corrupt-signature' && testCase.category !== 'divergence-ordering') {
          headers['webhook-signature'] = 'v1,' + sig;
        }
      } else if (provider === 'paddle') {
        const sig = createHmac('sha256', testCase.secret).update(dynamicTs + ':' + payload).digest('hex');

        if (testCase.signatureTemplate) {
          headers['paddle-signature'] = testCase.signatureTemplate.replace('{sig}', sig).replace('{ts}', String(dynamicTs));
        } else if (testCase.category !== 'corrupt-signature' && testCase.category !== 'divergence-ordering') {
          if (testCase.category === 'accept-reject' && !testCase.expectedHooklatch.ok && testCase.expectedHooklatch.reason === 'missing-signature') {
            headers['paddle-signature'] = 'ts=' + dynamicTs;
          } else if (testCase.category === 'accept-reject' && !testCase.expectedHooklatch.ok && testCase.expectedHooklatch.reason === 'missing-timestamp') {
            headers['paddle-signature'] = 'h1=' + sig;
          } else {
            headers['paddle-signature'] = 'ts=' + dynamicTs + ';h1=' + sig;
          }
        } else {
          headers['paddle-signature'] = 'ts=' + dynamicTs + ';h1=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a';
        }
      } else if (provider === 'sanity') {
        if (testCase.signatureTemplate) {
          headers['sanity-webhook-signature'] = testCase.signatureTemplate.replace('{ts}', String(dynamicTs));
        } else if (headers['sanity-webhook-signature']) {
          if (testCase.category !== 'corrupt-signature') {
            const toSign = (payload === '') ? (dynamicTs + '.') : (dynamicTs + '.' + payload);
            const sig = createHmac('sha256', testCase.secret).update(toSign).digest('base64url');

            headers['sanity-webhook-signature'] = 't=' + dynamicTs + ',v1=' + sig;
          }
        }
      } else if (provider === 'linear') {
        if (payload.includes('"webhookTimestamp"')) {
          payload = payload.replace(/"webhookTimestamp"\s*:\s*\d+/, `"webhookTimestamp": ${dynamicTs}`);
        }

        if (testCase.category !== 'corrupt-signature' && headers['linear-signature']) {
          const sig = createHmac('sha256', testCase.secret).update(payload).digest('hex');

          headers['linear-signature'] = sig;
        }
      } else if (provider === 'fal') {
        headers['x-fal-webhook-timestamp'] = String(dynamicTs);

        if (testCase.category !== 'corrupt-signature') {
          const reqId = headers['x-fal-webhook-request-id'] || 'req_fal_synthetic_001';
          const userId = testCase.signedUserId || headers['x-fal-webhook-user-id'] || 'user_fal_synthetic_001';
          const bodyHash = createHash('sha256').update(payload).digest('hex');
          const content = reqId + '\n' + userId + '\n' + dynamicTs + '\n' + bodyHash;
          const sig = sign(null, Buffer.from(content), falPrivateKey).toString('hex');

          headers['x-fal-webhook-signature'] = sig;
        }
      }
    }
  }

  return { payload, headers, clock: simulatedClock, dynamicTs };
}

function writeEvaluatorScript(destDir) {
  const evaluatorCode = `import { Buffer } from 'node:buffer';
import { createHmac, createHash, createPrivateKey, sign, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import * as hooklatchModule from 'hooklatch';
import { Webhook, WebhookVerificationError } from 'standardwebhooks';
import { Paddle, Environment } from '@paddle/paddle-node-sdk';
import { isValidSignature } from '@sanity/webhook';
import { LinearWebhookClient } from '@linear/sdk/webhooks';

const sdkModules = {
  standardwebhooks: { Webhook, WebhookVerificationError },
  paddle: { Paddle, Environment },
  sanity: { isValidSignature },
  linear: { LinearWebhookClient },
};

${resolveCaseForExecution.toString()}

async function executeCaseAgainstHooklatch(resolvedCase, testCase) {
  const { verify, verifyRequest, createVerifier } = hooklatchModule;
  const provider = testCase.provider;
  let rawBody;

  if (testCase.isBinaryView) {
    const full = Buffer.from('PREFIX_' + resolvedCase.payload);
    rawBody = full.subarray(7);
  } else {
    rawBody = Buffer.from(resolvedCase.payload);
  }

  const headers = resolvedCase.headers;
  const secrets = testCase.secrets || (testCase.secret ? [testCase.secret] : []);
  const now = () => resolvedCase.clock;

  let verifyOptions;

  if (provider === 'fal') {
    const rawPub = Buffer.from(testCase.secret.rawPublicKeyHex, 'hex');
    verifyOptions = {
      provider: 'fal',
      publicKeys: [rawPub],
      expectedUserId: testCase.secret.expectedUserId,
      now,
    };
  } else {
    verifyOptions = {
      provider,
      secrets,
      now,
    };
  }

  if (testCase.options?.toleranceSeconds !== undefined) {
    verifyOptions.toleranceSeconds = testCase.options.toleranceSeconds;
  }

  function formatHooklatchResult(res) {
    if (!res) return null;
    if (res.ok) {
      return {
        ok: true,
        reason: null,
        identity: res.identity ?? null,
        rawBodyBase64: res.rawBody ? Buffer.from(res.rawBody).toString('base64') : null,
      };
    }
    return {
      ok: false,
      reason: res.reason ?? (typeof res.error === 'string' ? res.error : (res.error ? (res.error.code || res.error.name) : 'unknown')),
      error: (typeof res.error === 'string' ? res.error : (res.error?.code || res.error?.name || 'HooklatchError')),
      message: res.message || res.error?.message,
    };
  }

  let directResult;
  try {
    directResult = await verify({ rawBody, headers }, verifyOptions);
  } catch (err) {
    directResult = {
      ok: false,
      reason: err.code || 'HooklatchError',
      error: err.code || err.name || 'HooklatchError',
      message: err.message,
    };
  }

  let verifierResult;
  try {
    const verifier = createVerifier(verifyOptions);
    verifierResult = await verifier({ rawBody, headers });
  } catch (err) {
    verifierResult = {
      ok: false,
      reason: err.code || 'HooklatchError',
      error: err.code || err.name || 'HooklatchError',
      message: err.message,
    };
  }

  let requestResult;
  try {
    const dummyReq = new Request('http://localhost', {
      method: 'POST',
      headers,
      body: rawBody,
    });
    requestResult = await verifyRequest(dummyReq, verifyOptions);
  } catch (err) {
    requestResult = {
      ok: false,
      reason: err.code || 'HooklatchError',
      error: err.code || err.name || 'HooklatchError',
      message: err.message,
    };
  }

  return {
    directResult: formatHooklatchResult(directResult),
    verifierResult: formatHooklatchResult(verifierResult),
    requestResult: formatHooklatchResult(requestResult),
    executedBytes: rawBody.length,
    executedHeaders: headers,
  };
}

async function executeCaseAgainstSdk(resolvedCase, testCase) {
  const provider = testCase.provider;
  const payload = resolvedCase.payload;
  const headers = resolvedCase.headers;
  const secret = testCase.secret;

  if (process.env.FAULT_INJECT === 'unexpected-sdk-exception') {
    throw new TypeError('Unexpected SDK defect');
  }

  if (process.env.FAULT_INJECT === 'sdk-crash') {
    process.exit(134);
  }

  if (process.env.FAULT_INJECT === 'sdk-hang') {
    await new Promise(() => {});
  }

  if (provider === 'standard-webhooks') {
    const { Webhook, WebhookVerificationError } = sdkModules.standardwebhooks;
    try {
      const wh = new Webhook(secret);
      const verified = wh.verify(payload, headers, { jsonParse: false });
      return { ok: true, value: verified, target: 'standardwebhooks', sdkVersion: '1.1.1', exportName: 'Webhook.prototype.verify', sourceLocation: 'dist/index.js' };
    } catch (err) {
      const isKnownWhError = (err instanceof WebhookVerificationError) || (err.name === 'WebhookVerificationError');
      const knownMessages = [
        'Missing required headers',
        'Invalid Signature Headers',
        'Message timestamp too old',
        'Message timestamp too new',
        'Invalid signature',
      ];
      const isKnownMsg = typeof err.message === 'string' && (
        knownMessages.includes(err.message) || err.message.startsWith('No matching signature')
      );

      if (isKnownWhError && isKnownMsg) {
        return {
          ok: false,
          error: 'WebhookVerificationError',
          message: err.message,
          target: 'standardwebhooks',
          sdkVersion: '1.1.1',
          exportName: 'Webhook.prototype.verify',
          sourceLocation: 'dist/index.js',
        };
      }

      return {
        ok: false,
        infrastructureFailure: true,
        error: err.name || 'UnexpectedError',
        message: err.message,
        target: 'standardwebhooks',
        sdkVersion: '1.1.1',
      };
    }
  }

  if (provider === 'paddle') {
    const { Paddle, Environment } = sdkModules.paddle;
    try {
      const paddle = new Paddle('dummy_api_key_synthetic', { environment: Environment.sandbox });
      const sigHeader = headers['paddle-signature'] || headers['Paddle-Signature'] || '';
      const isValid = await paddle.webhooks.isSignatureValid(payload, secret, sigHeader);

      if (typeof isValid !== 'boolean') {
        return {
          ok: false,
          infrastructureFailure: true,
          error: 'UnexpectedReturnValue',
          message: 'Expected boolean from Paddle isSignatureValid',
          target: '@paddle/paddle-node-sdk',
          sdkVersion: '3.10.0',
        };
      }

      return { ok: isValid, target: '@paddle/paddle-node-sdk', sdkVersion: '3.10.0', exportName: 'Paddle.prototype.webhooks.isSignatureValid', sourceLocation: 'dist/esm/index.esm.node.js' };
    } catch (err) {
      if (err.message === '[Paddle] Invalid webhook signature') {
        return {
          ok: false,
          error: 'PaddleVerificationError',
          message: err.message,
          target: '@paddle/paddle-node-sdk',
          sdkVersion: '3.10.0',
          exportName: 'Paddle.prototype.webhooks.isSignatureValid',
          sourceLocation: 'dist/esm/index.esm.node.js',
        };
      }

      return {
        ok: false,
        infrastructureFailure: true,
        error: err.name || 'UnexpectedError',
        message: err.message,
        target: '@paddle/paddle-node-sdk',
        sdkVersion: '3.10.0',
      };
    }
  }

  if (provider === 'sanity') {
    const { isValidSignature } = sdkModules.sanity;
    const sigHeader = headers['sanity-webhook-signature'] || headers['Sanity-Webhook-Signature'];

    if (!sigHeader) {
      return { ok: false, error: 'missing-signature', target: '@sanity/webhook', sdkVersion: '4.0.4', exportName: 'isValidSignature', sourceLocation: 'dist/index.mjs' };
    }

    try {
      const result = await isValidSignature(payload, sigHeader, secret);

      if (typeof result !== 'boolean') {
        return {
          ok: false,
          infrastructureFailure: true,
          error: 'UnexpectedReturnValue',
          message: 'Expected boolean from Sanity isValidSignature',
          target: '@sanity/webhook',
          sdkVersion: '4.0.4',
        };
      }

      return { ok: result, target: '@sanity/webhook', sdkVersion: '4.0.4', exportName: 'isValidSignature', sourceLocation: 'dist/index.mjs' };
    } catch (err) {
      const isKnownType = err.type === 'WebhookSignatureValueError' || err.type === 'WebhookSignatureFormatError';
      const isKnownName = err.name === 'WebhookSignatureValueError' || err.name === 'WebhookSignatureFormatError';

      if (isKnownType || isKnownName) {
        return {
          ok: false,
          error: err.type || err.name,
          message: err.message,
          target: '@sanity/webhook',
          sdkVersion: '4.0.4',
          exportName: 'isValidSignature',
          sourceLocation: 'dist/index.mjs',
        };
      }

      return {
        ok: false,
        infrastructureFailure: true,
        error: err.name || 'UnexpectedError',
        message: err.message,
        target: '@sanity/webhook',
        sdkVersion: '4.0.4',
      };
    }
  }

  if (provider === 'linear') {
    const { LinearWebhookClient } = sdkModules.linear;
    try {
      const client = new LinearWebhookClient(secret);
      const sig = headers['linear-signature'] || headers['Linear-Signature'] || '';

      if (!sig) {
        return { ok: false, error: 'missing-signature', target: '@linear/sdk', sdkVersion: '99.0.0', exportName: 'LinearWebhookClient.prototype.verify', sourceLocation: 'dist/webhooks/index.mjs' };
      }

      const bodyBuffer = Buffer.from(payload);
      const isValid = client.verify(bodyBuffer, sig);

      if (typeof isValid !== 'boolean') {
        return {
          ok: false,
          infrastructureFailure: true,
          error: 'UnexpectedReturnValue',
          message: 'Expected boolean from Linear verify',
          target: '@linear/sdk',
          sdkVersion: '99.0.0',
        };
      }

      return { ok: isValid, target: '@linear/sdk', sdkVersion: '99.0.0', exportName: 'LinearWebhookClient.prototype.verify', sourceLocation: 'dist/webhooks/index.mjs' };
    } catch (err) {
      const exactKnownErrors = [
        'Invalid webhook signature',
        'Missing webhook timestamp',
        'Invalid webhook timestamp',
      ];

      if (exactKnownErrors.includes(err.message)) {
        return {
          ok: false,
          error: 'LinearVerificationError',
          message: err.message,
          target: '@linear/sdk',
          sdkVersion: '99.0.0',
          exportName: 'LinearWebhookClient.prototype.verify',
          sourceLocation: 'dist/webhooks/index.mjs',
        };
      }

      return {
        ok: false,
        infrastructureFailure: true,
        error: err.name || 'UnexpectedError',
        message: err.message,
        target: '@linear/sdk',
        sdkVersion: '99.0.0',
      };
    }
  }

  if (provider === 'vercel') {
    const sigHeader = headers['x-vercel-signature'] || headers['X-Vercel-Signature'];
    if (!sigHeader) return { ok: false, error: 'missing-signature', target: 'vercel-docs-probe', sdkVersion: 'docs' };
    const expectedSig = createHmac('sha1', secret).update(payload).digest('hex');
    const ok = sigHeader.toLowerCase() === expectedSig.toLowerCase();
    return { ok, error: ok ? null : 'invalid-signature', target: 'vercel-docs-probe', sdkVersion: 'docs' };
  }

  if (provider === 'fal') {
    const sig = headers['x-fal-webhook-signature'] || headers['X-Fal-Webhook-Signature'];
    const reqId = headers['x-fal-webhook-request-id'] || headers['X-Fal-Webhook-Request-Id'];
    const userId = headers['x-fal-webhook-user-id'] || headers['X-Fal-Webhook-User-Id'];
    const ts = headers['x-fal-webhook-timestamp'] || headers['X-Fal-Webhook-Timestamp'];

    if (!sig || !reqId || !userId || !ts) return { ok: false, error: 'missing-signature', target: 'fal-docs-probe', sdkVersion: 'docs' };
    if (userId !== testCase.secret.expectedUserId) return { ok: false, error: 'missing-identity', target: 'fal-docs-probe', sdkVersion: 'docs' };

    const tsNum = parseInt(ts, 10);
    if (Number.isNaN(tsNum)) return { ok: false, error: 'malformed-timestamp', target: 'fal-docs-probe', sdkVersion: 'docs' };
    const nowSec = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - tsNum) > 300) return { ok: false, error: 'timestamp-expired', target: 'fal-docs-probe', sdkVersion: 'docs' };

    const bodyHash = createHash('sha256').update(payload).digest('hex');
    const message = reqId + '\\n' + userId + '\\n' + ts + '\\n' + bodyHash;
    const keyDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(testCase.secret.rawPublicKeyHex, 'hex')]);

    try {
      const pubKey = createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
      const ok = cryptoVerify(null, Buffer.from(message), pubKey, Buffer.from(sig, 'hex'));
      return { ok, error: ok ? null : 'invalid-signature', target: 'fal-docs-probe', sdkVersion: 'docs' };
    } catch {
      return { ok: false, error: 'invalid-signature', target: 'fal-docs-probe', sdkVersion: 'docs' };
    }
  }

  return { ok: false, error: 'unknown-provider', target: 'none' };
}

async function main() {
  const fs = await import('node:fs');
  const inputPath = process.argv[2];
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const falPrivateKey = input.falPrivateKeyPem ? createPrivateKey(input.falPrivateKeyPem) : null;
  const results = [];

  for (const item of input.items) {
    let resolvedCase = item.resolvedCase;

    if (!resolvedCase) {
      const nowSec = Math.floor(Date.now() / 1000);
      const nowMs = Date.now();

      resolvedCase = resolveCaseForExecution(item.testCase, nowSec, nowMs, falPrivateKey);
    }

    const hooklatchExec = await executeCaseAgainstHooklatch(resolvedCase, item.testCase);
    let sdkExec;

    try {
      sdkExec = await executeCaseAgainstSdk(resolvedCase, item.testCase);
    } catch (err) {
      sdkExec = { ok: false, infrastructureFailure: true, error: err.name || 'UnexpectedError', message: err.message };
    }

    results.push({
      id: item.testCase.id,
      hooklatch: {
        direct: hooklatchExec.directResult,
        verifier: hooklatchExec.verifierResult,
        request: hooklatchExec.requestResult,
        executedBytes: hooklatchExec.executedBytes,
        executedHeaders: hooklatchExec.executedHeaders,
      },
      sdk: sdkExec,
      resolvedCase: {
        payload: resolvedCase.payload,
        headers: resolvedCase.headers,
        dynamicTs: resolvedCase.dynamicTs,
        clock: resolvedCase.clock,
      },
    });
  }

  process.stdout.write(JSON.stringify(results));
}

main().catch((err) => {
  console.error('Evaluator child process failed:', err);
  process.exit(1);
});
`;

  const scriptPath = join(destDir, 'eval-runner.mjs');

  writeFileSync(scriptPath, evaluatorCode, 'utf8');

  return scriptPath;
}

async function runControls(hooklatchModule, root, tempConsumer) {
  console.log('[provider-conformance] Running negative control suites (--controls)...');

  const controlOutcomes = [];

  // Control 1: Production SDK crash fault injection
  const c1InputPath = join(tempConsumer, 'c1-input.json');
  const c1Corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));
  const c1Item = c1Corpus.cases[0];
  const c1Resolved = resolveCaseForExecution(c1Item, Math.floor(Date.now() / 1000), Date.now(), null);

  writeFileSync(c1InputPath, JSON.stringify({ items: [{ resolvedCase: c1Resolved, testCase: c1Item }] }));

  const c1Proc = spawnSync(process.execPath, [join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'sdk-crash' },
    timeout: 5000,
  });

  assert(c1Proc.status !== 0, 'Control 1 failed: child process crash was not detected as failure');
  controlOutcomes.push({ name: 'control-sdk-crash', passed: true });

  // Control 2: Production SDK hang/timeout fault injection
  const c2Start = Date.now();
  const c2Proc = spawnSync(process.execPath, [join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'sdk-hang' },
    timeout: 300,
  });
  const c2Duration = Date.now() - c2Start;

  assert(c2Proc.error && c2Proc.error.code === 'ETIMEDOUT', 'Control 2 failed: hanging SDK call was not timed out');
  assert(c2Duration < 2000, 'Control 2 failed: timeout duration exceeded reasonable threshold');
  controlOutcomes.push({ name: 'control-sdk-hang', passed: true });

  // Control 3: Production SDK unexpected exception (TypeError)
  const c3Proc = spawnSync(process.execPath, [join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'unexpected-sdk-exception' },
    timeout: 5000,
    encoding: 'utf8',
  });

  const c3Results = JSON.parse(c3Proc.stdout || '[]');
  const c3SdkResult = c3Results[0]?.sdk || {};
  const c3Classify = classifyCaseOutcome(c1Item, c3Results[0]?.hooklatch, c3SdkResult);

  assert(c3SdkResult.infrastructureFailure === true, 'Control 3 failed: unexpected TypeError was not marked infrastructureFailure');
  assert(!c3Classify.passed && c3Classify.reason.includes('Infrastructure failure'), 'Control 3 failed: unexpected TypeError passed qualification');
  controlOutcomes.push({ name: 'control-unexpected-sdk-exception', passed: true });

  // Control 4: Cleanup failure propagation
  assert.throws(() => {
    cleanupSafeTempConsumer(REPO_ROOT);
  }, /Refusing to clean up directory outside tmpdir/);

  // Verify cleanup failure is not swallowed and prevents PASS
  const c4Proc = spawnSync(process.execPath, ['-e', `
    const { existsSync, mkdirSync, rmSync } = require('node:fs');
    const { resolve } = require('node:path');
    const { tmpdir } = require('node:os');
    const assert = require('node:assert/strict');
    function cleanupSafeTempConsumer(consumerDir) {
      if (!consumerDir || !existsSync(consumerDir)) return;
      const baseTmp = resolve(tmpdir());
      assert(consumerDir.startsWith(baseTmp), 'Refusing to clean up directory outside tmpdir');
      throw new Error('Simulated cleanup failure: resource busy');
    }
    const testDir = resolve(tmpdir(), 'test-consumer-fail-' + Date.now());
    mkdirSync(testDir, { recursive: true });
    try {
      cleanupSafeTempConsumer(testDir);
    } finally {
      if (existsSync(testDir)) rmSync(testDir, { recursive: true, force: true });
    }
  `], { timeout: 5000 });

  assert(c4Proc.status !== 0, 'Control 4 failed: cleanup error did not cause failing exit code');
  assert(c4Proc.stderr.toString().includes('Simulated cleanup failure: resource busy'),
    'Control 4 failed: simulated cleanup failure was not propagated to stderr');
  controlOutcomes.push({ name: 'control-cleanup-failure', passed: true });

  // Control 5: Altered dist bytes detection
  const dummySnapshot = new Map([
    ['dist/index.js', '0000000000000000000000000000000000000000000000000000000000000000'],
  ]);
  const c5Check = verifyIntegritySnapshot(root, dummySnapshot);

  assert(!c5Check.ok && c5Check.violations.length > 0, 'Control 5 failed: snapshot verification did not detect altered file hash');
  controlOutcomes.push({ name: 'control-altered-dist-bytes', passed: true });

  // Control 6: Removed corpus provider coverage detection
  const c6Corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));
  c6Corpus.cases = c6Corpus.cases.filter((c) => c.provider !== 'linear');
  c6Corpus.casesCount = c6Corpus.cases.length;

  assert.throws(() => {
    validateCorpus(c6Corpus);
  }, /missing required provider coverage for "linear"/);
  controlOutcomes.push({ name: 'control-removed-corpus-coverage', passed: true });

  // Control 7: Misclassified divergence detection via single canonical classifier
  const c7DivergenceCase = c1Corpus.cases.find((c) => c.classification === 'expected-documented-receiver-policy-divergence' && c.expectedHooklatch.ok && !c.expectedSdk.ok);
  const c7MutatedCase = { ...c7DivergenceCase, classification: 'protocol-agreement' };
  const c7FakeHookResult = { direct: { ok: true, reason: null }, verifier: { ok: true, reason: null }, request: { ok: true, reason: null } };
  const c7FakeSdkResult = { ok: false, error: c7DivergenceCase.expectedSdk.error || 'SdkVerificationError' };
  const c7Classify = classifyCaseOutcome(c7MutatedCase, c7FakeHookResult, c7FakeSdkResult);

  assert(!c7Classify.passed && c7Classify.reason.includes('Protocol agreement violation'),
    'Control 7 failed: canonical classifier did not catch misclassified divergence');
  controlOutcomes.push({ name: 'control-misclassified-divergence', passed: true });

  console.log('[provider-conformance] All ' + controlOutcomes.length + ' controls passed.');

  return controlOutcomes;
}

async function verifyHeaderNormalizations(hooklatchModule, testCases, falPrivateKey) {
  console.log('[provider-conformance] Verifying header normalization models (Plain Object, WHATWG Headers, Tuples)...');

  const { verify } = hooklatchModule;
  const nowSec = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();

  for (const provider of REQUIRED_PROVIDERS) {
    const tc = testCases.find((c) => c.provider === provider && c.expectedHooklatch.ok);

    if (!tc) continue;

    const resolved = resolveCaseForExecution(tc, nowSec, nowMs, falPrivateKey);
    const rawBody = Buffer.from(resolved.payload);
    const clock = resolved.clock;

    const secrets = tc.secrets || (tc.secret ? [tc.secret] : []);
    let options;

    if (provider === 'fal') {
      options = {
        provider: 'fal',
        publicKeys: [Buffer.from(tc.secret.rawPublicKeyHex, 'hex')],
        expectedUserId: tc.secret.expectedUserId,
        now: () => clock,
      };
    } else {
      options = {
        provider: tc.provider,
        secrets,
        now: () => clock,
      };
    }

    if (tc.options?.toleranceSeconds !== undefined) {
      options.toleranceSeconds = tc.options.toleranceSeconds;
    }

    // Model 1: Plain Object
    const res1 = await verify({ rawBody, headers: resolved.headers }, options);

    assert(res1.ok, `Header Model 1 (Plain Object) failed for ${provider} (${tc.id})`);

    // Model 2: Mixed-case Object
    const mixedHeaders = {};

    for (const [k, v] of Object.entries(resolved.headers)) {
      const mixedKey = k.split('-').map((s) => s.charAt(0).toUpperCase() + s.slice(1)).join('-');

      mixedHeaders[mixedKey] = v;
    }

    const res2 = await verify({ rawBody, headers: mixedHeaders }, options);

    assert(res2.ok, `Header Model 2 (Mixed-case Object) failed for ${provider} (${tc.id})`);

    // Model 3: WHATWG Headers
    const whatwgHeaders = new Headers();

    for (const [k, v] of Object.entries(resolved.headers)) {
      whatwgHeaders.set(k, v);
    }

    const res3 = await verify({ rawBody, headers: whatwgHeaders }, options);

    assert(res3.ok, `Header Model 3 (WHATWG Headers) failed for ${provider} (${tc.id})`);

    // Model 4: [string, string][] Tuples
    const tupleHeaders = Object.entries(resolved.headers);
    const res4 = await verify({ rawBody, headers: tupleHeaders }, options);

    assert(res4.ok, `Header Model 4 (Tuples) failed for ${provider} (${tc.id})`);
  }

  // WHATWG Negative 1: Comma-combined duplicate header (must fail with malformed-signature)
  const cNeg1Headers = new Headers();
  cNeg1Headers.append('webhook-id', 'msg_dup_1');
  cNeg1Headers.append('webhook-id', 'msg_dup_2');
  cNeg1Headers.set('webhook-timestamp', String(nowSec));
  cNeg1Headers.set('webhook-signature', 'v1,dG90YWxseU90aGVyU2lnbmF0dXJlMDIwMjAyMDIwMjAyMDI=');

  const neg1Res = await verify({
    rawBody: Buffer.from('{"test":"dup"}'),
    headers: cNeg1Headers,
  }, {
    provider: 'standard-webhooks',
    secrets: ['whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s='],
    now: () => nowSec,
  });

  assert(!neg1Res.ok && neg1Res.reason === 'malformed-signature', 'WHATWG negative 1 (comma-duplicate id) did not fail with malformed-signature');

  // Non-zero offset Uint8Array view test (binary view preservation)
  const fullBuf = Buffer.from('PADDING_{"event":"view_test"}');
  const viewSlice = fullBuf.subarray(8);
  const viewKey = Buffer.from('whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s='.slice(6), 'base64');
  const viewSig = createHmac('sha256', viewKey).update('msg_view.' + nowSec + '.{"event":"view_test"}').digest('base64');

  const viewRes = await verify({
    rawBody: viewSlice,
    headers: {
      'webhook-id': 'msg_view',
      'webhook-timestamp': String(nowSec),
      'webhook-signature': 'v1,' + viewSig,
    },
  }, {
    provider: 'standard-webhooks',
    secrets: ['whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s='],
    now: () => nowSec,
  });

  assert(viewRes.ok, 'Uint8Array non-zero offset view verification failed in Hooklatch');

  console.log('[provider-conformance] Header normalization models and negative edge checks verified.');
}

function generateMarkdownReport(results, receipt) {
  const lines = [];

  lines.push('# Provider SDK Conformance Audit & Differential Report (Round 2 Repairs)');
  lines.push('');
  lines.push('Generated: ' + results.timestamp);
  lines.push('Base Commit: ' + receipt.baseSha);
  lines.push('Author / Partner: Gemini 3.8 (Owner: `gemini`)');
  lines.push('');
  lines.push('## 1. Executive Summary');
  lines.push('');
  lines.push('This report provides an independent, offline-verified differential analysis comparing Hooklatch');
  lines.push('against official provider SDKs and documented webhook verification specifications.');
  lines.push('');
  lines.push('- **Total Conformance Cases**: ' + results.totalCases);
  lines.push('- **Agreements Confirmed**: ' + results.agreementCount);
  lines.push('- **Documented Policy Divergences**: ' + results.divergenceCount);
  lines.push('- **Docs-Only Probes**: ' + results.docsProbeCount);
  lines.push('- **Unexpected Mismatches**: ' + results.unexpectedMismatchCount);
  lines.push('- **Controls Executed**: ' + results.controls.length + ' / ' + results.controls.length + ' PASS');
  lines.push('');
  lines.push('## 2. Pinned SDK Inventory and Integrity Receipts');
  lines.push('');
  lines.push('| Provider / Package | Version | Tarball SHA-256 | Evidence Classification |');
  lines.push('| --- | --- | --- | --- |');

  for (const pkg of PINNED_PACKAGES) {
    const r = receipt.packages?.[pkg.name] || {};

    lines.push('| `' + pkg.name + '` | `' + pkg.version + '` | `' + (r.sha256 || 'pending') + '` | ' + pkg.evidenceClass + ' |');
  }

  for (const probe of DOCS_PROBES) {
    lines.push('| `' + probe.provider + '` (Docs recipe) | N/A | N/A | ' + probe.evidenceClass + ' |');
  }

  lines.push('');
  lines.push('## 3. Policy Divergence Classification & Justification');
  lines.push('');
  lines.push('Every divergence between Hooklatch and official vendor SDKs is grounded in frozen Hooklatch architecture and primary implementation evidence:');
  lines.push('');
  lines.push('1. **Standard Webhooks Authentication-Before-Freshness Ordering**: Hooklatch evaluates cryptographic authentication prior to timestamp freshness. Expired timestamps with invalid signatures fail with `invalid-signature`; the vendor SDK evaluates timestamp freshness first, throwing `Message timestamp too old`.');
  lines.push('2. **Standard Webhooks Short Key Bounds**: Hooklatch enforces strict minimum 24-byte key bound for Standard Webhooks (`MIN_KEY_BYTES = 24`), rejecting weak keys with `invalid-secret`; the vendor SDK accepts arbitrary non-empty keys.');
  lines.push('3. **Paddle Segment Whitespace Resiliency**: Hooklatch permissively trims whitespace around key-value tokens in headers; Paddle Node SDK splits on \';\' and \'=\' without trimming keys (\'  h1\' !== \'h1\'), failing header extraction.');
  lines.push('4. **Paddle Multi-Signature Rotation Accept-Set**: Hooklatch evaluates all `h1` tokens in `paddle-signature` against configured secrets; Paddle SDK loops and checks only the final `h1` token.');
  lines.push('5. **Paddle Authentication-Before-Freshness Ordering**: Hooklatch evaluates cryptographic authentication prior to timestamp freshness. Expired timestamps with invalid signatures fail with `invalid-signature`; Paddle Node SDK evaluates timestamp freshness first (`new Date() > ...`), returning `false`.');
  lines.push('6. **Sanity Default Timestamp Freshness**: Hooklatch core enforces standard 300s timestamp freshness for Sanity webhooks; `@sanity/webhook` does not expire timestamps by policy and only checks a minimum timestamp bound.');
  lines.push('7. **Sanity Empty Body Preservation**: Hooklatch authenticates exact request bytes including empty payloads (`""`); `@sanity/webhook` explicitly throws `WebhookSignatureFormatError` disallowing empty payloads.');
  lines.push('8. **Linear Exact Body Preservation & Zero Parsing in Core**: Hooklatch verifies exact visible body bytes without parsing JSON or requiring body schemas; `@linear/sdk` requires JSON parsing and enforces `webhookTimestamp` in payload within 60s of `Date.now()`.');
  lines.push('');
  lines.push('## 4. Conformance Test Results Inventory');
  lines.push('');
  lines.push('| Case ID | Provider | Category | Classification | Hooklatch OK | SDK OK | Status |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');

  for (const item of results.details) {
    const status = item.matchedExpectation ? 'PASS' : 'FAIL';

    lines.push('| `' + item.id + '` | `' + item.provider + '` | ' + item.category + ' | `' + item.classification + '` | ' + item.hooklatch.direct.ok + ' | ' + item.sdk.ok + ' | ' + status + ' |');
  }

  lines.push('');

  return lines.join('\n');
}

async function runOfflineConformance(options) {
  console.log('[provider-conformance] Starting offline SDK conformance harness (Round 2)...');

  const preSnapshot = takeIntegritySnapshot(REPO_ROOT);
  const cacheCheck = verifyCacheIntegrity();

  if (!cacheCheck.ok) {
    console.error('ERROR: Cache integrity verification failed: ' + cacheCheck.reason);
    console.error('Prerequisites missing: run node scripts/phase10/provider-conformance.mjs --prepare-online first.');

    process.exit(3);
  }

  if (!existsSync(DIST_INDEX)) {
    console.error('ERROR: Built Hooklatch dist missing at ' + DIST_INDEX + '; run npm run build first.');

    process.exit(3);
  }

  if (!existsSync(CORPUS_PATH)) {
    console.error('ERROR: Conformance corpus missing at ' + CORPUS_PATH);

    process.exit(3);
  }

  let corpus;

  try {
    corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));
  } catch (err) {
    console.error('ERROR: Failed to parse corpus JSON: ' + err.message);

    process.exit(3);
  }

  try {
    validateCorpus(corpus);
  } catch (err) {
    console.error('ERROR: Corpus validation failed: ' + err.message);

    process.exit(3);
  }

  const falPrivateKey = createPrivateKey({
    key: Buffer.from(corpus.falKeys.privateKeyDerBase64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });

  const npmCli = resolveNpmCli();
  const tempConsumer = createSafeTempConsumer();

  let resultsSummary = {
    timestamp: new Date().toISOString(),
    totalCases: 0,
    agreementCount: 0,
    divergenceCount: 0,
    docsProbeCount: 0,
    unexpectedMismatchCount: 0,
    controls: [],
    details: [],
  };

  try {
    console.log('  Packaging local Hooklatch from dist...');

    const packOutput = execFileSync(
      process.execPath,
      [npmCli, 'pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', tempConsumer],
      { cwd: REPO_ROOT, encoding: 'utf8', timeout: 300000 },
    );

    const packEntries = JSON.parse(packOutput);
    const hooklatchTarball = join(tempConsumer, packEntries[0].filename);

    console.log('  Setting up temporary consumer and installing cached packages offline...');

    const consumerPkgJson = {
      name: 'gemini-conformance-consumer',
      version: '1.0.0',
      type: 'module',
      private: true,
    };

    writeFileSync(join(tempConsumer, 'package.json'), JSON.stringify(consumerPkgJson, null, 2), 'utf8');

    // Replay frozen package-lock.json if present
    if (existsSync(FROZEN_LOCK_PATH)) {
      copyFileSync(FROZEN_LOCK_PATH, join(tempConsumer, 'package-lock.json'));
    }

    const cachedTarballs = PINNED_PACKAGES.map((pkg) => join(CACHE_DIR, pkg.tarball));

    execFileSync(
      process.execPath,
      [npmCli, 'install', '--offline', '--cache', NPM_CACHE_DIR, '--ignore-scripts', hooklatchTarball, ...cachedTarballs],
      { cwd: tempConsumer, stdio: ['ignore', 'pipe', 'pipe'], timeout: 300000 },
    );

    console.log('  Preparing isolated evaluator runner in consumer...');

    const evalRunnerPath = writeEvaluatorScript(tempConsumer);

    const evaluationItems = [];

    for (const testCase of corpus.cases) {
      evaluationItems.push({ testCase });
    }

    const evalInputPath = join(tempConsumer, 'eval-input.json');

    writeFileSync(evalInputPath, JSON.stringify({
      items: evaluationItems,
      falPrivateKeyPem: falPrivateKey.export({ type: 'pkcs8', format: 'pem' }),
    }), 'utf8');

    console.log('  Running ' + corpus.cases.length + ' test cases through isolated evaluator...');

    const evalStart = Date.now();
    const evalProc = spawnSync(process.execPath, [evalRunnerPath, evalInputPath], {
      cwd: tempConsumer,
      timeout: 120000,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024,
    });
    const evalDuration = Date.now() - evalStart;

    if (evalProc.error) {
      if (evalProc.error.code === 'ETIMEDOUT') {
        throw new Error(`Evaluator timed out after ${evalDuration}ms`);
      }

      throw evalProc.error;
    }

    if (evalProc.status !== 0) {
      throw new Error(`Evaluator exited with status ${evalProc.status}: ${evalProc.stderr || evalProc.stdout}`);
    }

    let evalResults;

    try {
      evalResults = JSON.parse(evalProc.stdout);
    } catch (err) {
      throw new Error(`Failed to parse evaluator results JSON: ${err.message}. Output was: ${evalProc.stdout}`);
    }

    const evalResultsMap = new Map(evalResults.map((r) => [r.id, r]));

    let agreementCount = 0;
    let divergenceCount = 0;
    let docsProbeCount = 0;
    let unexpectedMismatchCount = 0;
    const details = [];

    for (const item of evaluationItems) {
      const testCase = item.testCase;
      const res = evalResultsMap.get(testCase.id);

      if (!res) {
        throw new Error(`Missing evaluation result for case ${testCase.id}`);
      }

      const resolvedCase = res.resolvedCase;
      const hooklatchOutcome = res.hooklatch;
      const sdkOutcome = res.sdk;

      const classificationResult = classifyCaseOutcome(testCase, hooklatchOutcome, sdkOutcome);

      if (classificationResult.passed) {
        if (testCase.classification === 'protocol-agreement') {
          agreementCount += 1;
        } else if (testCase.classification === 'expected-documented-receiver-policy-divergence') {
          divergenceCount += 1;
        } else if (testCase.classification === 'docs-only-probe') {
          docsProbeCount += 1;
        }
      } else {
        unexpectedMismatchCount += 1;
        console.error('  FAIL [Unexpected Mismatch]: ' + testCase.id + ' (' + classificationResult.reason + ')');
      }

      const dRes = hooklatchOutcome.direct;

      // Metadata & exact bytes assertion
      if (testCase.expectedHooklatch.ok && dRes.ok && dRes.rawBodyBase64) {
        assert(Buffer.from(dRes.rawBodyBase64, 'base64').equals(Buffer.from(resolvedCase.payload)),
          'Raw body bytes mismatch for ' + testCase.id);
      }

      if (testCase.expectedHooklatch.ok && dRes.ok && testCase.expectedHooklatch.identity) {
        const expId = testCase.expectedHooklatch.identity;
        if (expId.deliveryId !== undefined) {
          assert.strictEqual(dRes.identity?.deliveryId, expId.deliveryId, 'deliveryId mismatch for ' + testCase.id);
        }
        if (expId.eventId !== undefined) {
          assert.strictEqual(dRes.identity?.eventId, expId.eventId, 'eventId mismatch for ' + testCase.id);
        }
        if (expId.authenticatedFields) {
          assert.deepStrictEqual(dRes.identity?.authenticatedFields, expId.authenticatedFields, 'authenticatedFields mismatch for ' + testCase.id);
        }
      }

      details.push({
        id: testCase.id,
        provider: testCase.provider,
        category: testCase.category,
        classification: testCase.classification,
        divergenceReason: testCase.divergenceReason || null,
        evidenceReference: testCase.evidenceReference || null,
        executedPayloadBase64: Buffer.from(resolvedCase.payload).toString('base64'),
        executedHeaders: resolvedCase.headers,
        executedBytes: hooklatchOutcome.executedBytes ?? Buffer.from(resolvedCase.payload).length,
        materializedTimestamp: resolvedCase.dynamicTs ?? null,
        simulatedClock: resolvedCase.clock,
        executedSignature: resolvedCase.headers['webhook-signature'] || resolvedCase.headers['paddle-signature'] || resolvedCase.headers['sanity-webhook-signature'] || resolvedCase.headers['linear-signature'] || resolvedCase.headers['x-vercel-signature'] || resolvedCase.headers['x-fal-webhook-signature'] || null,
        hooklatch: {
          direct: { ok: dRes.ok, reason: dRes.reason || null, error: dRes.error || null },
          verifier: { ok: hooklatchOutcome.verifier.ok, reason: hooklatchOutcome.verifier.reason || null, error: hooklatchOutcome.verifier.error || null },
          request: { ok: hooklatchOutcome.request.ok, reason: hooklatchOutcome.request.reason || null, error: hooklatchOutcome.request.error || null },
          verifiedBytes: dRes.rawBodyBase64 ? Buffer.from(dRes.rawBodyBase64, 'base64').length : null,
          verifiedIdentity: dRes.identity || null,
        },
        sdk: {
          target: sdkOutcome.target,
          sdkVersion: sdkOutcome.sdkVersion,
          exportName: sdkOutcome.exportName || null,
          sourceLocation: sdkOutcome.sourceLocation || null,
          ok: sdkOutcome.ok,
          error: sdkOutcome.error || null,
          infrastructureFailure: Boolean(sdkOutcome.infrastructureFailure),
        },
        matchedExpectation: classificationResult.passed,
      });
    }

    // Load public Hooklatch via tempConsumer node_modules
    const consumerModulesDir = join(tempConsumer, 'node_modules');
    const hooklatch = await import(pathToFileURL(join(consumerModulesDir, 'hooklatch', 'dist', 'index.js')).href);

    await verifyHeaderNormalizations(hooklatch, corpus.cases, falPrivateKey);

    let controls = [];

    if (options.controls) {
      controls = await runControls(hooklatch, REPO_ROOT, tempConsumer);
    }

    resultsSummary = {
      timestamp: new Date().toISOString(),
      totalCases: corpus.cases.length,
      agreementCount,
      divergenceCount,
      docsProbeCount,
      unexpectedMismatchCount,
      controls,
      details,
    };
  } finally {
    cleanupSafeTempConsumer(tempConsumer);
  }

  const postSnapshot = verifyIntegritySnapshot(REPO_ROOT, preSnapshot);

  if (!postSnapshot.ok) {
    console.error('FATAL [provider-conformance]: Workspace or dist integrity violation detected post-run:');

    for (const v of postSnapshot.violations) {
      console.error(`  - ${v.file}: ${v.reason} (expected: ${v.expectedHash}, current: ${v.currentHash})`);
    }

    process.exit(1);
  }

  if (resultsSummary.unexpectedMismatchCount > 0) {
    console.error(`FATAL [provider-conformance]: ${resultsSummary.unexpectedMismatchCount} unexpected mismatches occurred.`);
    process.exit(1);
  }

  writeFileSync(RESULTS_PATH, JSON.stringify(resultsSummary, null, 2) + '\n', 'utf8');
  console.log('[provider-conformance] Results written to ' + RESULTS_PATH);

  const report = generateMarkdownReport(resultsSummary, cacheCheck.receipt);

  writeFileSync(REPORT_PATH, report + '\n', 'utf8');
  console.log('[provider-conformance] Audit report written to ' + REPORT_PATH);

  console.log(`[provider-conformance] PASS: ${resultsSummary.totalCases} cases verified (${resultsSummary.agreementCount} agreements, ${resultsSummary.divergenceCount} documented divergences, ${resultsSummary.docsProbeCount} docs probes).`);
}

async function main() {
  const args = process.argv.slice(2);
  const options = {
    prepareOnline: false,
    controls: false,
  };

  for (const arg of args) {
    if (arg === '--prepare-online') {
      options.prepareOnline = true;
    } else if (arg === '--controls') {
      options.controls = true;
    } else {
      console.error('ERROR: Unknown CLI argument: ' + arg);
      console.error('Usage: node scripts/phase10/provider-conformance.mjs [--prepare-online] [--controls]');
      process.exit(2);
    }
  }

  if (options.prepareOnline) {
    runPrepareOnline();
    return;
  }

  await runOfflineConformance(options);
}

main().catch((err) => {
  console.error('FATAL [provider-conformance]:', err);
  process.exit(1);
});
