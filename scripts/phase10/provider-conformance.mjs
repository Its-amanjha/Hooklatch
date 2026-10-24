import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createHmac, createPrivateKey, randomUUID, sign } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHealthLedger, runChild, confirmTermination } from './cjs-prototype.mjs';

export async function finishQualification({ cleanup, integrity, publish }) {
  await cleanup();

  const checked = integrity();

  assert(checked.ok, 'Post-run integrity check failed');

  return publish();
}

export function validateCacheReceipt(receipt, lock) {
  assert(receipt.schemaVersion === 2 && isNonEmptyString(receipt.lockfileSha256), 'Missing pinned lockfile receipt');
  assert(lock.lockfileVersion === 3 && isPlainObject(lock.packages), 'Invalid frozen lockfile');

  for (const pkg of PINNED_PACKAGES) {
    const pinned = receipt.packages?.[pkg.name];
    const installed = lock.packages[`node_modules/${pkg.name}`];

    assert(pinned?.version === pkg.version && pinned.exportPath === pkg.exportPath, 'Pinned package receipt mismatch');
    assert(pinned.sourceRevision === pinned.integrity && isNonEmptyString(pinned.integrity), 'Missing published-source revision');
    assert(installed?.version === pkg.version && installed.integrity === pinned.integrity, 'Frozen dependency graph mismatch');
  }
}

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

const CACHE_DIR = join(REPO_ROOT, 'notes', 'phase-10', 'gemini-sdk-cache');
const RECEIPT_PATH = join(CACHE_DIR, 'receipt.json');
const FROZEN_LOCK_PATH = join(CACHE_DIR, 'package-lock.json');
const NPM_CACHE_DIR = join(CACHE_DIR, 'npm-cache');
const CORPUS_PATH = join(REPO_ROOT, 'tests', 'conformance', 'phase10-provider-cases.json');
const RESULTS_PATH = join(REPO_ROOT, 'notes', 'phase-10', 'coordinator-conformance-results.json');
const REPORT_PATH = join(REPO_ROOT, 'notes', 'phase-10', 'coordinator-conformance-review.md');
const DIST_INDEX = join(REPO_ROOT, 'dist', 'index.js');

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
    sdkCompared: false,
    evidenceClass: 'docs-only-probe',
    recipe: 'HMAC-SHA1 hex 40-character digest over raw request body',
    documentationUrl: 'https://vercel.com/docs/webhooks/webhooks-api',
  },
  {
    provider: 'fal',
    sdkCompared: false,
    evidenceClass: 'docs-only-probe',
    recipe: 'Ed25519 signature over requestId LF userId LF timestamp LF sha256Hex(body)',
    documentationUrl: 'https://fal.ai/docs/documentation/model-apis/inference/webhooks',
  },
];

const REQUIRED_PROVIDERS = ['standard-webhooks', 'paddle', 'sanity', 'linear', 'vercel', 'fal'];

const REQUIRED_CATEGORIES = [
  'accept-reject',
  'secret-rotation',
  'freshness-window',
  'corrupt-signature',
  'divergence-ordering',
  'policy-divergence',
  'byte-preservation',
  'docs-probe',
];

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
  'clockMode',
  'binaryPayloadBase64',
  'unsupportedVendorInterface',
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

const FROZEN_DIVERGENCES = new Map([
  [
    'std-divergence-auth-before-freshness',
    {
      provider: 'standard-webhooks',
      expectedError: 'WebhookVerificationError',
      expectedMessage: 'Message timestamp too old',
      divergenceReason: 'Hooklatch evaluates cryptographic authentication prior to timestamp freshness, failing with invalid-signature. Standard Webhooks SDK evaluates timestamp freshness first, throwing WebhookVerificationError (Message timestamp too old).',
      evidenceReference: 'Hooklatch verification pipeline in src/internal/verification.ts vs standardwebhooks Webhook.verify in dist/index.js:15',
    },
  ],
  [
    'std-divergence-weak-key',
    {
      provider: 'standard-webhooks',
      expectedHooklatchCode: 'invalid-secret',
      expectedSdkOk: true,
      divergenceReason: 'Hooklatch enforces strict MIN_KEY_BYTES = 24 bound on Standard Webhooks secrets to protect against weak symmetric keys, failing at option validation with invalid-secret. The vendor SDK permits arbitrary key lengths.',
      evidenceReference: 'Hooklatch MIN_KEY_BYTES bound in src/providers/standard-webhooks.ts vs standardwebhooks Webhook constructor in dist/index.js',
    },
  ],
  [
    'paddle-divergence-whitespace-segment',
    {
      provider: 'paddle',
      expectedHooklatchOk: true,
      expectedError: 'PaddleVerificationError',
      divergenceReason: 'Hooklatch trims segment whitespace around semicolons per standard header robustness, successfully recognizing "h1"; @paddle/paddle-node-sdk splits on ";" without trimming, yielding key " h1" which fails parameter matching and throws Invalid webhook signature.',
      evidenceReference: 'Hooklatch segment.trim() in src/providers/paddle.ts vs @paddle/paddle-node-sdk WebhooksValidator.extractHeader',
    },
  ],
  [
    'paddle-divergence-rotation-first-valid',
    {
      provider: 'paddle',
      expectedHooklatchOk: true,
      expectedSdkOk: false,
      divergenceReason: 'Hooklatch evaluates repeated h1 fields as a secret rotation accept-set; Paddle Node SDK loops and overwrites "h1", checking only the final h1 value.',
      evidenceReference: 'Hooklatch rotation accept-set in src/providers/paddle.ts vs @paddle/paddle-node-sdk WebhooksValidator.extractHeader',
    },
  ],
  [
    'paddle-divergence-auth-before-freshness',
    {
      provider: 'paddle',
      expectedHooklatchReason: 'invalid-signature',
      expectedSdkOk: false,
      divergenceReason: 'Hooklatch evaluates cryptographic authentication prior to timestamp freshness, failing with invalid-signature. Paddle Node SDK evaluates timestamp freshness first (new Date() > ...), returning false.',
      evidenceReference: 'Hooklatch core verification pipeline in src/internal/verification.ts vs @paddle/paddle-node-sdk WebhooksValidator.isValidSignature',
    },
  ],
  [
    'sanity-reject-default-tolerance-stale',
    {
      provider: 'sanity',
      expectedHooklatchReason: 'timestamp-expired',
      expectedSdkOk: true,
      divergenceReason: 'Hooklatch core enforces standard timestamp freshness (300s default); @sanity/webhook assertValidSignature does not expire timestamps and only checks MINIMUM_TIMESTAMP bound.',
      evidenceReference: 'Hooklatch verification pipeline in src/internal/verification.ts vs @sanity/webhook in dist/index.mjs',
    },
  ],
  [
    'sanity-divergence-empty-body',
    {
      provider: 'sanity',
      expectedHooklatchOk: true,
      expectedError: 'WebhookSignatureFormatError',
      divergenceReason: 'Hooklatch authenticates exact request bytes including empty string payloads; @sanity/webhook assertValidSignature explicitly throws WebhookSignatureFormatError disallowing empty body verification.',
      evidenceReference: 'Hooklatch raw body preservation in src/providers/sanity.ts vs @sanity/webhook assertValidSignature in dist/index.mjs:22',
    },
  ],
  [
    'linear-divergence-stale-body-timestamp',
    {
      provider: 'linear',
      expectedHooklatchOk: true,
      expectedError: 'LinearVerificationError',
      expectedMessage: 'Invalid webhook timestamp',
      divergenceReason: 'Hooklatch core verifies exact visible request bytes without parsing JSON or extracting payload schema timestamps; @linear/sdk parses JSON and requires webhookTimestamp to be within 60 seconds of Date.now().',
      evidenceReference: 'Hooklatch body-only verification in src/providers/linear.ts vs @linear/sdk LinearWebhookClient.verify in dist/webhooks/webhooks-BtY8wrj8.mjs:62',
    },
  ],
]);

function isPlainObject(value) {
  return value !== null && Object.prototype.toString.call(value) === '[object Object]';
}

function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

function isNonEmptyString(value) {
  return isString(value) && value.trim().length > 0;
}

function isNumber(value) {
  return Object.prototype.toString.call(value) === '[object Number]' && !Number.isNaN(value);
}

function computeSha256(filePath) {
  const bytes = readFileSync(filePath);

  return createHash('sha256').update(bytes).digest('hex');
}

export function verifyCacheIntegrity() {
  if (!existsSync(NPM_CACHE_DIR)) {
    return { ok: false, reason: 'Missing offline dependency cache at ' + NPM_CACHE_DIR };
  }

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

  if (receipt.schemaVersion !== 2) {
    return { ok: false, reason: 'Unsupported receipt schemaVersion: ' + receipt.schemaVersion };
  }

  const lockBytes = readFileSync(FROZEN_LOCK_PATH);
  const lock = JSON.parse(lockBytes);

  validateCacheReceipt(receipt, lock);
  assert(computeSha256(FROZEN_LOCK_PATH) === receipt.lockfileSha256, 'Frozen lockfile checksum mismatch');

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

    const integrity = 'sha512-' + createHash('sha512').update(readFileSync(tarballPath)).digest('base64');

    assert(integrity === pkgReceipt.integrity, 'Published package integrity mismatch');

    if (actualHash !== pkgReceipt.sha256) {
      return {
        ok: false,
        reason: `SHA256 mismatch for ${pkg.name}: expected ${pkgReceipt.sha256}, got ${actualHash}`,
      };
    }
  }

  return { ok: true, receipt };
}

const REVIEWED_CASES = new Map([["std-valid-standard","131ffe05f84f4333200fdbaf1a065ad800a26b0a3a51efa4f795eb7b5fbf26ff"],["std-valid-no-prefix-secret","c4174726f5fe4044f7dd7659b3ca204028306d6fd157bbcb7799c4fd3fd843f7"],["std-valid-rotation-first-valid","7d2b157f6cf87518e00f5c40375ec8a14ca63e6772ab7a7d3508cfd0261434ac"],["std-valid-rotation-second-valid","e59d017aa048fa6f8901d27bb1b9891dd2c794a65efdff1b2bc356106be0dfe2"],["std-valid-unknown-scheme","83a176410156a5c6f2052b5d245ff1bdb1e41eb926843be0282d57d1e1104d71"],["std-valid-custom-tolerance","21a43f1e88ab446a29c3c6f39d021c5838b81ce727709ccba9b5b2be54a61f49"],["std-valid-near-boundary-299s","eb8c600283d356db083578d36e28e3d8b8cbadd0eec9e4eca80945f6c4046aca"],["std-valid-zero-tolerance","a100a11ab6f0f9fea3d92e95fa1aad4f099c9471186efd790ce57740bcda469f"],["std-reject-default-tolerance-stale","e83705b869cfef1d72757bc1771b77e1a759e816f8ef04ca066a5be69dd24d45"],["std-reject-future-timestamp","43adba07240a205be204fd91ca6752291a41a0a331f2aa853c364c2e3f2f4659"],["std-reject-corrupted-sig","0e5cfce57efccd4376a673f4375cf37a588b301f7e795c20f2ec737197c898ee"],["std-reject-missing-id","e92de3c22332bbba94e5f62fff0de645cd570643a4bd6f0e5b09121dbe1fa040"],["std-divergence-auth-before-freshness","7fd52208800607e9bfb28383e0fc235ffaa55d2735888624c71e6406b8cbe113"],["std-divergence-weak-key","9b43cde3c0089627cadd95ea6a03e06ecd52c9480e398785ce4c729bb7417b32"],["paddle-valid-standard","3cff69f67cd0e5a300a103903a81e33a6fbeb8a9d0748ec3ae09568ccca97b90"],["paddle-valid-near-boundary-4s","0e28ba991abf7a737720c389bd4e8fa85eaa02a9bc20c12cd2bcf0c4e89f6852"],["paddle-valid-custom-tolerance","ab0494b6f15d37a809f877a4dde828397813d43e3243bb543bda1f70b61436d4"],["paddle-valid-zero-tolerance","728c603c11197c47b61c1cd1fbc008b6434e3f9c46725217978f467419d7fe1c"],["paddle-exact-body-whitespace","e3ecd7a6c6e1c1110822c27980a17675a10e11b33fc21e48bd37846ae799a7ea"],["paddle-valid-multi-secret","3874eb9edc6e67a9da2991e86e4a9c8145b52898f36f779159e0cee9997be7db"],["paddle-reject-default-tolerance-stale","394b7a6176b051c1efa28d5d8ce288cedf78a31a88ec3f92890e9bbae825d834"],["paddle-reject-corrupted-sig","d73a6185e7e3b6d898a330a93f92ccc7fef37d377ccbba347c2f739f64d50f85"],["paddle-reject-missing-sig","3dbc2b355f5cb95580e04d70766d0cf103fa72a6c0000768cc9aa1dc929c0ad3"],["paddle-reject-missing-timestamp","38418b56b80842ecf91ec670600cc11cb5540d6ece2c268575ffe127993e702a"],["paddle-divergence-whitespace-segment","fd43cdf13980308a87b84d3907d13d5b7b634df4865272547b9b6e78353328a2"],["paddle-divergence-rotation-first-valid","61b88aa1f7f1433281fc5840c20150927658efbfcaa48a6253ffb96488a41ec7"],["paddle-divergence-auth-before-freshness","a549d673ffc72ac017bf3c897e4cd23e555f5301abe77803ce846fcd05c7b9a7"],["sanity-valid-standard","3c72626a3ca8f3650a6eac464418d6b9df3fee3796211c5f7d2ab603ccf7fb93"],["sanity-valid-near-boundary-299s","91c04892f91658af9784e2573b23260c44761c255841d6f48970c907138461bc"],["sanity-valid-custom-tolerance","5e5dd88708b72764ae4fc6033e01640a26dda39a6f4a7f4609c317bd736b5577"],["sanity-valid-zero-tolerance","f86a309d60d9cb3d75a6542f75bbdf676d56807594a82ff03c60a81eac591b02"],["sanity-reject-default-tolerance-stale","53e252c626154472bc244c940398222b1944b84c52669438194f9cf87cac4b68"],["sanity-reject-corrupted-sig","6ae029e0c81c4def0f20f14ff85206013e0367e02463827be3dd522b82793bb4"],["sanity-reject-missing-sig","9e327210aa91b57264fa9d1f45cb1a916ab6aa327de1b1c14eb0cd383b611e53"],["sanity-reject-missing-timestamp","0ffc1871cb874b106afc505d5be1b65d64a7cbe462ca5209e1c8e6a0be69ad5b"],["sanity-divergence-empty-body","2de0661ecf01380fe95ef6ad615c72b21af69b5cbec05115679a1f30d5b790a8"],["linear-valid-standard","7d8d3638130aea3388033d8c2612bc9a1b7e061124d3bfdfc38b6e5ac4a4dfad"],["linear-valid-near-boundary-59s","9ddbeac320cec9b89ff60e45355dff40d627147aefd67e5faf9a8c668303ad5c"],["linear-valid-custom-tolerance","ade93bd362be9afda8375a9c31c4b74b3b2978670f1e004850be5412e75221d1"],["linear-valid-zero-tolerance","f503c6cbb1b5832d5410971e9084da3ce0f6617302d41b5c5ff46c97c1cf32c7"],["linear-exact-body-formatting","24bbbc0ad5958a57311fd5bc1358ad202727870a3eb702f145116c2f7d4b4b68"],["linear-valid-binary-view","4f5e235e7cb93859d96b4c1979ceb44aa7b1dc71cdb1c1e7f434f2addd254678"],["linear-reject-corrupted-sig","51fc40273e970bcfa71f58bd63c4e710653d83a75a6614d8aa4d5d271b42f426"],["linear-reject-missing-sig","3e7f6075fcdb049d5336165897b12aa9be66ecd35b0d54a997b3f31af1847773"],["linear-divergence-stale-body-timestamp","8d2ca5837b56971d4cb18b04bcc4d6e5d4022c7dedfc7df900d1b3b245631263"],["vercel-valid-standard","fdfc239255e76aa13e805ef341d766d3ec2b36bcde117a19098b1ae416e6d7ae"],["vercel-valid-exact-body","cdbda0794c7d52b02fa47a94f7ec3a601a418be5d64317298ceb96e5e7e8bef0"],["vercel-reject-corrupted-sig","aafab01a0a133219746181e80e2aff1976192c4ccac795ca162371e82266efb3"],["vercel-reject-missing-sig","1e30951b5a6046d1ab6e09f2d657e2a76c3eb124e94966c707039729a7af3295"],["fal-valid-standard","78ac2189d066a02752a121b4dabc732e48a2c1193280d7cb831fdd73a7f8d580"],["fal-reject-corrupted-sig","deb7c823b41b419c25529784610366f7b433f4bac9b835df1031f9e3dc9ffa3f"],["fal-reject-wrong-user-id","e8d88c100596d298b6ac4cf7c4321951458e914e1f717fa7b1b6c8489edb9010"],["fal-reject-stale-timestamp","58e1ffc1ce93f1a0a0144a66fdcb4f640161b08b27b8fcb1680bf7af68a9b9cd"],["std-valid-exact-inclusive-edge-300s","82cf1d70b51b382d96fc332c804b3c26f57ce29dfc2bd4b65b92a69cb631d37d"],["paddle-valid-exact-inclusive-edge-5s","598f00c59e25229ce8dab36fbb48edbbafd63d7b56bcc189a841bce924690e11"],["linear-valid-exact-inclusive-edge-60s","e9ed6719631a56bf7709a3ffcaf410a92816f95727eddfdc976b7c9dac1b855b"],["std-valid-zero-tolerance-edge","e0060e743aec901000a7539ac42cc7c785bb6a79eea01731c2c8699c9f133eeb"]]);

export function validateCorpus(corpus) {
  if (!isPlainObject(corpus)) {
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

  if (!Array.isArray(corpus.cases) || corpus.cases.length < 50) {
    throw new Error(`Corpus validation failed: cases must contain at least 50 cases, got ${corpus.cases?.length}`);
  }

  if (corpus.casesCount !== corpus.cases.length) {
    throw new Error(`Corpus validation failed: casesCount (${corpus.casesCount}) does not match cases.length (${corpus.cases.length})`);
  }

  if (!corpus.falKeys || !isPlainObject(corpus.falKeys) || !corpus.falKeys.rawPublicKeyHex || !corpus.falKeys.privateKeyDerBase64) {
    throw new Error('Corpus validation failed: falKeys must contain rawPublicKeyHex and privateKeyDerBase64');
  }

  const seenIds = new Set();
  const providerCaseCounts = new Map(REQUIRED_PROVIDERS.map((p) => [p, 0]));
  const seenCategories = new Set();

  for (const tc of corpus.cases) {
    if (!isNonEmptyString(tc.id)) {
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

    if (!isNonEmptyString(tc.category)) {
      throw new Error(`Corpus validation failed: test case "${tc.id}" missing category`);
    }

    seenCategories.add(tc.category);

    if (!isString(tc.payload)) {
      throw new Error(`Corpus validation failed: test case "${tc.id}" payload must be a string`);
    }

    if (!isPlainObject(tc.headers)) {
      throw new Error(`Corpus validation failed: test case "${tc.id}" headers must be an object`);
    }

    if (!isPlainObject(tc.expectedHooklatch)) {
      throw new Error(`Corpus validation failed: test case "${tc.id}" missing expectedHooklatch`);
    }

    if (!isPlainObject(tc.expectedSdk)) {
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
      if (!isNonEmptyString(tc.divergenceReason)) {
        throw new Error(`Corpus validation failed: divergence "${tc.id}" missing valid divergenceReason`);
      }

      if (!isNonEmptyString(tc.evidenceReference)) {
        throw new Error(`Corpus validation failed: divergence "${tc.id}" missing valid evidenceReference`);
      }

      if (!FROZEN_DIVERGENCES.has(tc.id)) {
        throw new Error(`Corpus validation failed: divergence "${tc.id}" is not in the frozen supported divergence inventory`);
      }
    }

    if (classification === 'docs-only-probe' && tc.provider !== 'vercel' && tc.provider !== 'fal') {
      throw new Error(`Corpus validation failed: docs-only-probe is only permitted for vercel and fal, got "${tc.provider}" in "${tc.id}"`);
    }
  }

  for (const reqCat of REQUIRED_CATEGORIES) {
    if (!seenCategories.has(reqCat)) {
      throw new Error(`Corpus validation failed: missing required category "${reqCat}" in corpus cases`);
    }
  }

  for (const [provider, count] of providerCaseCounts.entries()) {
    if (count === 0) {
      throw new Error(`Corpus validation failed: missing required provider coverage for "${provider}" (0 cases)`);
    }
  }

  assert(corpus.cases.length === REVIEWED_CASES.size, 'Corpus validation failed: reviewed inventory changed');

  for (const row of corpus.cases) {
    const digest = createHash('sha256').update(JSON.stringify(row)).digest('hex');

    assert(REVIEWED_CASES.get(row.id) === digest, 'Corpus validation failed: reviewed case changed: ' + row.id);
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
    const pinned = FROZEN_DIVERGENCES.get(testCase.id);

    if (!pinned) {
      return {
        passed: false,
        reason: `Disallowed unpinned divergence ID "${testCase.id}"`,
      };
    }

    if (testCase.provider !== pinned.provider) {
      return {
        passed: false,
        reason: `Divergence provider mismatch: expected ${pinned.provider}, got ${testCase.provider}`,
      };
    }

    if (testCase.divergenceReason !== pinned.divergenceReason) {
      return {
        passed: false,
        reason: 'Divergence reason mismatch against frozen definition',
      };
    }

    if (testCase.evidenceReference !== pinned.evidenceReference) {
      return {
        passed: false,
        reason: 'Divergence evidenceReference mismatch against frozen definition',
      };
    }

    if (pinned.expectedMessage && sdkOutcome.message !== pinned.expectedMessage) {
      return {
        passed: false,
        reason: `SDK rejection message mismatch: expected "${pinned.expectedMessage}", got "${sdkOutcome.message}"`,
      };
    }

    if (pinned.expectedError && sdkOutcome.error !== pinned.expectedError) {
      return {
        passed: false,
        reason: `SDK rejection error mismatch: expected "${pinned.expectedError}", got "${sdkOutcome.error}"`,
      };
    }

    if (pinned.expectedHooklatchReason && dRes.reason !== pinned.expectedHooklatchReason) {
      return {
        passed: false,
        reason: `Hooklatch rejection reason mismatch: expected "${pinned.expectedHooklatchReason}", got "${dRes.reason}"`,
      };
    }

    if (pinned.expectedHooklatchCode && dRes.error !== pinned.expectedHooklatchCode) {
      return {
        passed: false,
        reason: `Hooklatch error code mismatch: expected "${pinned.expectedHooklatchCode}", got "${dRes.error}"`,
      };
    }

    if (pinned.expectedSdkOk !== undefined && sdkOutcome.ok !== pinned.expectedSdkOk) {
      return {
        passed: false,
        reason: `SDK ok mismatch: expected ${pinned.expectedSdkOk}, got ${sdkOutcome.ok}`,
      };
    }

    return { passed: true, category: 'expected-documented-receiver-policy-divergence' };
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

  if (existsSync(join(root, 'dist'))) {
    function walkDist(dir) {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);

        if (entry.isDirectory()) {
          walkDist(full);
        } else if (entry.isFile()) {
          const rel = full.slice(root.length + 1).replace(/\\/g, '/');

          snapshot.set(rel, computeSha256(full));
        }
      }
    }

    walkDist(join(root, 'dist'));
  }

  return snapshot;
}

function verifyIntegritySnapshot(root, expectedSnapshot) {
  const violations = [];

  for (const [rel, expectedHash] of expectedSnapshot.entries()) {
    const full = join(root, rel);

    if (!existsSync(full)) {
      violations.push({ file: rel, reason: 'missing', expectedHash, currentHash: null });
    } else {
      const currentHash = computeSha256(full);

      if (currentHash !== expectedHash) {
        violations.push({ file: rel, reason: 'modified', expectedHash, currentHash });
      }
    }
  }

  return { ok: violations.length === 0, violations };
}

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);

  const candidates = [
    join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(nodeDir, '..', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];

  for (const c of candidates) {
    if (existsSync(c)) return c;
  }

  try {
    const npmPath = execFileSync('where', ['npm.cmd'], { encoding: 'utf8', timeout: 10000 }).trim().split('\r\n')[0];

    if (npmPath) {
      const entry = join(dirname(npmPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');

      if (existsSync(entry)) return entry;
    }
  } catch {
    // fall through
  }

  throw blocked('npm CLI JavaScript entry is unavailable');
}

async function runCommand(args, { cwd, timeout = 120000, env = process.env } = {}, ledger) {
  const evidence = await runChild(process.execPath, args, { cwd, timeoutMs: timeout, env, ledger });

  return {
    ...evidence,
    status: evidence.exitCode,
    error: evidence.timedOut ? { code: 'ETIMEDOUT' } : evidence.spawnError ? { code: 'SPAWN_ERROR' } : null,
  };
}

async function checkedCommand(args, options, ledger) {
  const result = await runCommand(args, options, ledger);

  if (result.stderr.includes('ENOTCACHED')) throw blocked('Offline dependency cache is incomplete');

  assert(result.ok, 'Child command failed: ' + JSON.stringify(result));

  return result.stdout;
}

function blocked(message) {
  const error = new Error(message);

  error.code = 'PREREQUISITE_BLOCKED';

  return error;
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

  if (process.env.FAULT_INJECT_CLEANUP === '1') {
    throw new Error('Simulated production cleanup failure in disposal path');
  }

  rmSync(consumerDir, { recursive: true, force: true });

  if (existsSync(consumerDir)) {
    throw new Error('Cleanup failed: temp consumer directory still exists at ' + consumerDir);
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
  const evaluatorCode = `import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac, createHash, createPrivateKey, sign, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import * as hooklatchModule from 'hooklatch';
import { Webhook, WebhookVerificationError } from 'standardwebhooks';
import { Paddle, Environment } from '@paddle/paddle-node-sdk';
import { isValidSignature, assertValidSignature } from '@sanity/webhook';
import { LinearWebhookClient } from '@linear/sdk/webhooks';

const REQUIRED_PROVIDERS = ["standard-webhooks", "paddle", "sanity", "linear", "vercel", "fal"];
const sdkModules = {
  standardwebhooks: { Webhook, WebhookVerificationError },
  paddle: { Paddle, Environment },
  sanity: { isValidSignature, assertValidSignature },
  linear: { LinearWebhookClient },
};

${resolveCaseForExecution.toString()}
${verifyHeaderNormalizations.toString()}

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
    if (process.env.HANG_READY_FILE) {
      const fsMod = await import('node:fs');
      fsMod.writeFileSync(process.env.HANG_READY_FILE, 'ready', 'utf8');
    }

    const timer = setInterval(() => {}, 1000);
    await new Promise(() => {});
    clearInterval(timer);
  }

  let restoreDateNow = null;
  if (testCase.clockMode === 'deterministic') {
    const fixedNow = resolvedCase.clock * 1000;
    const origNow = Date.now;
    const OrigDate = Date;
    class MockDate extends OrigDate {
      constructor(...args) {
        if (args.length === 0) {
          super(fixedNow);
        } else {
          super(...args);
        }
      }
      static now() {
        return fixedNow;
      }
    }
    Date = MockDate;
    globalThis.Date = MockDate;
    restoreDateNow = () => {
      Date = OrigDate;
      globalThis.Date = OrigDate;
    };
  }

  try {
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
      const { assertValidSignature } = sdkModules.sanity;
      const sigHeader = headers['sanity-webhook-signature'] || headers['Sanity-Webhook-Signature'];

      if (!sigHeader) {
        return { ok: false, error: 'missing-signature', target: '@sanity/webhook', sdkVersion: '4.0.4', exportName: 'assertValidSignature', sourceLocation: 'dist/index.mjs' };
      }

      try {
        await assertValidSignature(payload, sigHeader, secret);

        return { ok: true, target: '@sanity/webhook', sdkVersion: '4.0.4', exportName: 'assertValidSignature', sourceLocation: 'dist/index.mjs' };
      } catch (err) {
        const errType = err.type || err.constructor?.name || err.name;

        if (errType === 'WebhookSignatureValueError' || errType === 'WebhookSignatureFormatError') {
          return {
            ok: false,
            error: errType,
            message: err.message,
            target: '@sanity/webhook',
            sdkVersion: '4.0.4',
            exportName: 'assertValidSignature',
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
      if (userId !== secret.expectedUserId) return { ok: false, error: 'missing-identity', target: 'fal-docs-probe', sdkVersion: 'docs' };

      const tsNum = parseInt(ts, 10);
      if (Number.isNaN(tsNum)) return { ok: false, error: 'malformed-timestamp', target: 'fal-docs-probe', sdkVersion: 'docs' };

      const nowSec = resolvedCase.clock;
      if (Math.abs(nowSec - tsNum) > 300) return { ok: false, error: 'timestamp-expired', target: 'fal-docs-probe', sdkVersion: 'docs' };

      const bodyHash = createHash('sha256').update(payload).digest('hex');
      const message = [reqId, userId, ts, bodyHash].join(String.fromCharCode(10));
      const keyDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(secret.rawPublicKeyHex, 'hex')]);

      try {
        const pubKey = createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
        const ok = cryptoVerify(null, Buffer.from(message), pubKey, Buffer.from(sig, 'hex'));
        return { ok, error: ok ? null : 'invalid-signature', target: 'fal-docs-probe', sdkVersion: 'docs' };
      } catch {
        return { ok: false, error: 'invalid-signature', target: 'fal-docs-probe', sdkVersion: 'docs' };
      }
    }

    return { ok: false, error: 'unsupported-provider' };
  } finally {
    if (restoreDateNow) {
      restoreDateNow();
    }
  }
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

  if (input.headerChecks) {
    const previousLog = console.log;

    console.log = () => {};
    await verifyHeaderNormalizations(hooklatchModule, input.items.map((item) => item.testCase), falPrivateKey);
    console.log = previousLog;
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

  // Point 1: Embedded evaluator code syntax verification
  const checkProc = spawnSync(process.execPath, ['--check', scriptPath], { timeout: 10000 });

  assert(checkProc.status === 0, 'Embedded evaluator syntax check failed: ' + (checkProc.stderr || checkProc.stdout));

  return scriptPath;
}

async function runControls(tempConsumer, ledger) {
  console.log('[provider-conformance] Running negative control suites (--controls)...');

  const controlOutcomes = [];

  // Control 1: Production SDK crash fault injection
  const c1InputPath = join(tempConsumer, 'c1-input.json');
  const c1Corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));
  const c1Item = c1Corpus.cases[0];
  const c1Resolved = resolveCaseForExecution(c1Item, Math.floor(Date.now() / 1000), Date.now(), null);

  writeFileSync(c1InputPath, JSON.stringify({ items: [{ resolvedCase: c1Resolved, testCase: c1Item }] }));

  const c1Proc = await runCommand([join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'sdk-crash' },
    timeout: 5000,
  }, ledger);

  assert(c1Proc.status !== 0, 'Control 1 failed: child process crash was not detected as failure');
  controlOutcomes.push({ name: 'control-sdk-crash', passed: true });

  // Control 2: Production SDK hang/timeout fault injection with readiness marker
  const c2ReadyFile = join(tempConsumer, 'c2-hang-ready.txt');
  const c2Start = Date.now();

  const c2Proc = await runCommand([join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'sdk-hang', HANG_READY_FILE: c2ReadyFile },
    timeout: 1000,
  }, ledger);

  const c2Duration = Date.now() - c2Start;

  assert(existsSync(c2ReadyFile), 'Control 2 failed: child process did not enter SDK call before timing out');
  assert(c2Proc.error && c2Proc.error.code === 'ETIMEDOUT', 'Control 2 failed: hanging SDK call was not timed out');
  assert(c2Duration >= 900, 'Control 2 failed: timeout duration was too short');
  controlOutcomes.push({ name: 'control-sdk-hang', passed: true });

  // Control 3: Production SDK unexpected exception (TypeError)
  const c3Proc = await runCommand([join(tempConsumer, 'eval-runner.mjs'), c1InputPath], {
    cwd: tempConsumer,
    env: { ...process.env, FAULT_INJECT: 'unexpected-sdk-exception' },
    timeout: 5000,
    encoding: 'utf8',
  }, ledger);

  const c3Results = JSON.parse(c3Proc.stdout || '[]');
  const c3SdkResult = c3Results[0]?.sdk || {};
  const c3Classify = classifyCaseOutcome(c1Item, c3Results[0]?.hooklatch, c3SdkResult);

  assert(c3SdkResult.infrastructureFailure === true, 'Control 3 failed: unexpected TypeError was not marked infrastructureFailure');
  assert(!c3Classify.passed && c3Classify.reason.includes('Infrastructure failure'), 'Control 3 failed: unexpected TypeError passed qualification');
  controlOutcomes.push({ name: 'control-unexpected-sdk-exception', passed: true });

  // Control 4: Production cleanup failure propagation on actual disposal path
  const c4Consumer = createSafeTempConsumer();

  writeFileSync(join(c4Consumer, 'test.txt'), 'cleanup-test-payload');

  let c4Threw = false;
  const origEnv = process.env.FAULT_INJECT_CLEANUP;

  try {
    process.env.FAULT_INJECT_CLEANUP = '1';

    try {
      cleanupSafeTempConsumer(c4Consumer);
    } finally {
      process.env.FAULT_INJECT_CLEANUP = origEnv;
    }
  } catch (err) {
    if (err.message.includes('Simulated production cleanup failure in disposal path')) {
      c4Threw = true;
    }
  }

  assert(c4Threw, 'Control 4 failed: cleanup error was not thrown on actual disposal path');

  // Safely dispose c4Consumer after fault injection test
  cleanupSafeTempConsumer(c4Consumer);
  assert(!existsSync(c4Consumer), 'Control 4 consumer must be cleanly removed after test');

  // Verify refusal outside tmpdir
  assert.throws(() => {
    cleanupSafeTempConsumer(REPO_ROOT);
  }, /Refusing to clean up directory outside tmpdir/);
  controlOutcomes.push({ name: 'control-cleanup-failure', passed: true });

  // Control 5: Altered bytes detection on protected scratch tree
  const c5Scratch = join(resolve(tmpdir()), 'hooklatch-integrity-test-' + randomUUID());

  mkdirSync(join(c5Scratch, 'dist'), { recursive: true });

  const c5File = join(c5Scratch, 'dist', 'index.js');

  writeFileSync(c5File, 'original-content-pristine', 'utf8');

  try {
    const pristineSnapshot = new Map([
      ['dist/index.js', computeSha256(c5File)],
    ]);

    const pristineCheck = verifyIntegritySnapshot(c5Scratch, pristineSnapshot);

    assert(pristineCheck.ok, 'Pristine scratch tree must pass integrity verification');

    // Mutate file byte
    writeFileSync(c5File, 'tampered-content-mutated', 'utf8');

    const mutatedCheck = verifyIntegritySnapshot(c5Scratch, pristineSnapshot);

    assert(!mutatedCheck.ok && mutatedCheck.violations.length === 1,
      'Control 5 failed: altered file bytes were not detected by verifyIntegritySnapshot');
    assert.strictEqual(mutatedCheck.violations[0].file, 'dist/index.js');

    // Restore pristine byte
    writeFileSync(c5File, 'original-content-pristine', 'utf8');

    const restoredCheck = verifyIntegritySnapshot(c5Scratch, pristineSnapshot);

    assert(restoredCheck.ok, 'Restored scratch tree must pass integrity verification');

    controlOutcomes.push({ name: 'control-altered-dist-bytes', passed: true });
  } finally {
    rmSync(c5Scratch, { recursive: true, force: true });
  }

  // Control 6: Removed corpus provider coverage detection
  const c6Corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));

  c6Corpus.cases = c6Corpus.cases.filter((c) => c.provider !== 'linear');

  while (c6Corpus.cases.length < 50) {
    const clone = { ...c6Corpus.cases[0], id: `pad-case-${c6Corpus.cases.length}` };

    c6Corpus.cases.push(clone);
  }

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

  // Verify unpinned divergence is rejected
  const c7UnpinnedCase = {
    ...c1Corpus.cases[0],
    id: 'unpinned-divergence-test',
    expectedHooklatch: { ok: true },
    expectedSdk: { ok: false },
    classification: 'expected-documented-receiver-policy-divergence',
    divergenceReason: 'arbitrary',
    evidenceReference: 'unreviewed',
  };

  const c7UnpinnedClassify = classifyCaseOutcome(c7UnpinnedCase, c7FakeHookResult, c7FakeSdkResult);

  assert(!c7UnpinnedClassify.passed && c7UnpinnedClassify.reason.includes('Disallowed unpinned divergence'),
    'Control 7 failed: canonical classifier did not reject unpinned divergence ID');

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

  // Point 8: Duplicate negative starting with authentic 32-byte HMAC
  const dupSecret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
  const dupKey = Buffer.from(dupSecret.slice(6), 'base64');
  const dupPayload = '{"test":"dup"}';
  const validId = 'msg_pristine_001';
  const validSig = createHmac('sha256', dupKey).update(`${validId}.${nowSec}.${dupPayload}`).digest('base64');

  // Verify that with single id it PASSES
  const pristineHeaders = new Headers();

  pristineHeaders.set('webhook-id', validId);
  pristineHeaders.set('webhook-timestamp', String(nowSec));
  pristineHeaders.set('webhook-signature', 'v1,' + validSig);

  const pristineRes = await verify({
    rawBody: Buffer.from(dupPayload),
    headers: pristineHeaders,
  }, {
    provider: 'standard-webhooks',
    secrets: [dupSecret],
    now: () => nowSec,
  });

  assert(pristineRes.ok, 'Pristine base request must pass before duplicate header introduction');

  // Now introduce duplicate webhook-id header
  const dupHeaders = new Headers(pristineHeaders);

  dupHeaders.append('webhook-id', 'msg_second_dup');

  const dupRes = await verify({
    rawBody: Buffer.from(dupPayload),
    headers: dupHeaders,
  }, {
    provider: 'standard-webhooks',
    secrets: [dupSecret],
    now: () => nowSec,
  });

  assert(!dupRes.ok && dupRes.reason === 'malformed-signature',
    'WHATWG duplicate header introduction must cause malformed-signature failure due to comma-separated ID');

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

  assert(viewRes.ok, 'Uint8Array non-zero view verification failed');
  console.log('[provider-conformance] Header normalization models and negative edge checks verified.');
}

function generateAuditReport(summary, details, controls) {
  const lines = [];

  lines.push('# Hooklatch Provider Conformance Audit Report (Round 3)');
  lines.push('');
  lines.push('- **Generated At**: ' + new Date().toISOString());
  lines.push('- **Platform**: ' + process.platform + ' (' + process.arch + ')');
  lines.push('- **Node.js**: ' + process.version);
  lines.push('- **Harness**: Isolated Child Process Evaluator with Frozen Transitive Lockfile');
  lines.push('');
  lines.push('## Executive Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('| --- | --- |');
  lines.push('| Total Cases Executed | ' + summary.totalCases + ' |');
  lines.push('| Protocol Agreements | ' + summary.agreements + ' |');
  lines.push('| Expected Documented Policy Divergences | ' + summary.divergences + ' |');
  lines.push('| Docs-Only Probes | ' + summary.docsProbes + ' |');
  lines.push('| Unexpected Mismatches | ' + summary.unexpectedMismatches + ' |');
  lines.push('| Controls Passed | ' + (controls ? controls.filter((c) => c.passed).length + ' / ' + controls.length : 'N/A') + ' |');
  lines.push('');
  lines.push('## Documented Receiver Policy Divergences (Detailed Analysis)');
  lines.push('');
  lines.push('1. **Standard Webhooks Authentication-Before-Freshness Ordering**: Hooklatch evaluates cryptographic authentication prior to timestamp freshness. Expired timestamps with invalid signatures fail with `invalid-signature`; the vendor SDK evaluates timestamp freshness first, throwing `Message timestamp too old`.');
  lines.push('2. **Standard Webhooks Minimum Key Length**: Hooklatch enforces strict `MIN_KEY_BYTES = 24` for symmetric keys, failing at option validation with `invalid-secret`. The vendor SDK permits arbitrary key lengths.');
  lines.push('3. **Paddle Whitespace Resiliency**: Hooklatch trims segment whitespace around semicolons; `@paddle/paddle-node-sdk` splits on `;` without trimming, failing on whitespace.');
  lines.push('4. **Paddle Multi-Signature Rotation Accept-Set**: Hooklatch evaluates all `h1` tokens in `paddle-signature` against configured secrets; Paddle SDK loops and checks only the final `h1` token.');
  lines.push('5. **Paddle Authentication-Before-Freshness Ordering**: Hooklatch evaluates cryptographic authentication prior to timestamp freshness. Expired timestamps with invalid signatures fail with `invalid-signature`; Paddle Node SDK evaluates timestamp freshness first (`new Date() > ...`), returning `false`.');
  lines.push('6. **Sanity Default Freshness Policy**: Hooklatch enforces default 300s freshness window; `@sanity/webhook` does not validate timestamp freshness by default.');
  lines.push('7. **Sanity Empty Body Preservation**: Hooklatch authenticates exact request bytes including empty payloads (`""`); `@sanity/webhook` explicitly throws `WebhookSignatureFormatError` disallowing empty payloads.');
  lines.push('8. **Linear Exact Body Preservation & Zero Parsing in Core**: Hooklatch authenticates visible raw body bytes without parsing JSON or requiring body schemas; `@linear/sdk` parses payload JSON and enforces a 60-second freshness window.');
  lines.push('');

  return lines.join('\n');
}

async function runOfflineConformance(options) {
  console.log('[provider-conformance] Starting offline SDK conformance harness (coordinator)...');

  const cacheStatus = verifyCacheIntegrity();

  if (!cacheStatus.ok) {
    console.error('FATAL [provider-conformance]: Offline cache integrity failed: ' + cacheStatus.reason);

    throw blocked('Offline cache missing: ' + cacheStatus.reason);
  }

  const preSnapshot = takeIntegritySnapshot(REPO_ROOT);

  if (!existsSync(DIST_INDEX)) {
    console.error('FATAL [provider-conformance]: Missing dist/index.js. Build Hooklatch first.');

    throw blocked('Build prerequisite missing');
  }

  const corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'));

  validateCorpus(corpus);

  const falPrivateKey = createPrivateKey({
    key: Buffer.from(corpus.falKeys.privateKeyDerBase64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });

  const tempConsumer = createSafeTempConsumer();
  const processLedger = createHealthLedger();
  let publication;
  let executionError;

  try {
    console.log('  Packaging local Hooklatch from dist...');

    const npmCli = resolveNpmCli();

    const packOutput = (await checkedCommand(
      [npmCli, 'pack', REPO_ROOT, '--offline', '--json', '--cache', join(tempConsumer, 'npm-cache'), '--pack-destination', tempConsumer, '--ignore-scripts'],
      { cwd: tempConsumer, timeout: 300000 }, processLedger,
    )).trim();

    const tarballFileName = JSON.parse(packOutput)[0].filename;
    const localTarball = join(tempConsumer, tarballFileName);

    assert(existsSync(localTarball), 'Local Hooklatch tarball was not created at ' + localTarball);

    console.log('  Setting up temporary consumer and installing cached packages offline...');

    const consumerLock = JSON.parse(readFileSync(FROZEN_LOCK_PATH, 'utf8'));
    const consumerPkgJson = { ...consumerLock.packages[''], type: 'module', private: true };

    mkdirSync(join(tempConsumer, 'vendor'));

    for (const pkg of PINNED_PACKAGES) {
      const target = 'file:vendor/' + pkg.tarball;

      copyFileSync(join(CACHE_DIR, pkg.tarball), join(tempConsumer, 'vendor', pkg.tarball));
      consumerPkgJson.dependencies[pkg.name] = target;
      consumerLock.packages[''].dependencies[pkg.name] = target;
      consumerLock.packages['node_modules/' + pkg.name].resolved = target;
    }

    const localIntegrity = 'sha512-' + createHash('sha512').update(readFileSync(localTarball)).digest('base64');

    consumerPkgJson.dependencies.hooklatch = 'file:' + tarballFileName;
    consumerLock.packages[''].dependencies.hooklatch = 'file:' + tarballFileName;
    consumerLock.packages['node_modules/hooklatch'].resolved = 'file:' + tarballFileName;
    consumerLock.packages['node_modules/hooklatch'].integrity = localIntegrity;
    writeFileSync(join(tempConsumer, 'package.json'), JSON.stringify(consumerPkgJson));
    writeFileSync(join(tempConsumer, 'package-lock.json'), JSON.stringify(consumerLock));

    const expectedLock = computeSha256(join(tempConsumer, 'package-lock.json'));

    await checkedCommand(
      [npmCli, 'ci', '--offline', '--cache', NPM_CACHE_DIR, '--ignore-scripts'],
      { cwd: tempConsumer, timeout: 300000 }, processLedger,
    );
    assert(computeSha256(join(tempConsumer, 'package-lock.json')) === expectedLock, 'Frozen dependency graph changed');

    console.log('  Preparing isolated evaluator runner in consumer...');

    const evalRunnerPath = writeEvaluatorScript(tempConsumer);
    const evaluationItems = [];

    for (const testCase of corpus.cases) {
      evaluationItems.push({ testCase });
    }

    const evalInputPath = join(tempConsumer, 'eval-input.json');

    writeFileSync(evalInputPath, JSON.stringify({
      items: evaluationItems,
      headerChecks: true,
      falPrivateKeyPem: falPrivateKey.export({ type: 'pkcs8', format: 'pem' }),
    }), 'utf8');

    console.log('  Running ' + corpus.cases.length + ' test cases through isolated evaluator...');

    const evalProc = await runCommand([evalRunnerPath, evalInputPath], {
      cwd: tempConsumer, timeout: 120000,
    }, processLedger);

    assert(evalProc.ok, 'Evaluator failed: ' + JSON.stringify(evalProc));

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

      // Unconditional identity & raw bytes assertions across ALL THREE Hooklatch APIs
      if (testCase.expectedHooklatch.ok) {
        const apis = [
          { name: 'direct', res: dRes },
          { name: 'verifier', res: hooklatchOutcome.verifier },
          { name: 'request', res: hooklatchOutcome.request },
        ];

        for (const api of apis) {
          assert(api.res && api.res.ok, `API ${api.name} must be ok=true for ${testCase.id}`);
          assert(isString(api.res.rawBodyBase64), `API ${api.name} must return rawBodyBase64 for ${testCase.id}`);

          const recBytes = Buffer.from(api.res.rawBodyBase64, 'base64');

          assert(recBytes.equals(Buffer.from(resolvedCase.payload)),
            `Raw body bytes mismatch on API ${api.name} for ${testCase.id}`);

          const expId = testCase.expectedHooklatch.identity;

          assert(api.res.identity !== null && api.res.identity !== undefined,
            `API ${api.name} must return identity for ${testCase.id}`);

          if (expId) {
            assert.strictEqual(api.res.identity.deliveryId, expId.deliveryId,
              `deliveryId mismatch on API ${api.name} for ${testCase.id}`);
            assert.strictEqual(api.res.identity.eventId, expId.eventId,
              `eventId mismatch on API ${api.name} for ${testCase.id}`);
            assert.deepStrictEqual(api.res.identity.authenticatedFields, expId.authenticatedFields,
              `authenticatedFields mismatch on API ${api.name} for ${testCase.id}`);

            if (expId.authenticatedFields && expId.authenticatedFields.includes('timestamp')) {
              assert(isNumber(api.res.identity.timestamp),
                `API ${api.name} identity timestamp must be number for ${testCase.id}`);

              const expectedTs = testCase.provider === 'sanity' && testCase.timestampConfig?.unit === 'milliseconds'
                ? Math.floor(resolvedCase.dynamicTs / 1000)
                : resolvedCase.dynamicTs;

              assert.strictEqual(api.res.identity.timestamp, expectedTs,
                `identity timestamp mismatch on API ${api.name} for ${testCase.id}`);
            }
          }
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
        clockMode: testCase.clockMode || 'dynamic',
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
          message: sdkOutcome.message || null,
          infrastructureFailure: Boolean(sdkOutcome.infrastructureFailure),
          unsupportedVendorInterface: Boolean(sdkOutcome.unsupportedVendorInterface),
        },
        matchedExpectation: classificationResult.passed,
      });
    }

    let controlsResult = null;

    if (options.runControls) {
      controlsResult = await runControls(tempConsumer, processLedger);
    }

    const summary = {
      totalCases: corpus.cases.length,
      agreements: agreementCount,
      divergences: divergenceCount,
      docsProbes: docsProbeCount,
      unexpectedMismatches: unexpectedMismatchCount,
      controlsPassed: controlsResult ? controlsResult.every((c) => c.passed) : true,
    };

    const finalReport = {
      schemaVersion: 1,
      docsOnlyRecipes: DOCS_PROBES,
      generatedAt: new Date().toISOString(),
      summary,
      details,
      controls: controlsResult,
    };

    assert(unexpectedMismatchCount === 0, 'Conformance unexpected mismatch');
    publication = { finalReport, auditMarkdown: generateAuditReport(summary, details, controlsResult) };
  } catch (error) {
    executionError = error;
  }

  return finishQualification({
    cleanup: () => {
      const confirmed = confirmTermination(processLedger);

      assert(confirmed.confirmed, 'Cleanup withheld: child close unconfirmed; scratch preserved at ' + tempConsumer);
      cleanupSafeTempConsumer(tempConsumer);
    },
    integrity: () => verifyIntegritySnapshot(REPO_ROOT, preSnapshot),
    publish: () => {
      if (executionError) throw executionError;

      publication.finalReport.execution = { node: process.version, lockfileSha256: cacheStatus.receipt.lockfileSha256, cleanupCompleted: true, integrityPassed: true, dependencyInstall: 'npm ci --offline --ignore-scripts' };

      writeFileSync(RESULTS_PATH, JSON.stringify(publication.finalReport, null, 2) + '\n');
      writeFileSync(REPORT_PATH, publication.auditMarkdown + '\n');
      console.log('PASS: conformance accepted after cleanup and integrity: ' + JSON.stringify(publication.finalReport.summary));

      return publication.finalReport.summary;
    },
  });
}

async function main() {
  const args = process.argv.slice(2);

  const options = {
    prepareOnline: false,
    runControls: false,
  };

  for (const arg of args) {
    if (arg === '--prepare-online') {
      options.prepareOnline = true;
    } else if (arg === '--controls') {
      options.runControls = true;
    } else {
      console.error(`Unknown argument: "${arg}". Only --prepare-online and --controls are supported.`);

      process.exit(2);
    }
  }

  if (options.prepareOnline) {
    throw blocked('Fresh SDK acquisition is not qualified for v2 receipts. Use a reviewed pinned cache; no cache was changed.');
  }

  await runOfflineConformance(options);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('FATAL [provider-conformance]:', err);
    process.exitCode = err.code === 'PREREQUISITE_BLOCKED' ? 3 : 1;
  });
}
