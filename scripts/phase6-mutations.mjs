import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA_VERSION = 1;
const PINNED_BASE_SHA = '292280a14084a8b59f84293ad09d38d0562dc136';
const HISTORICAL_REVIEW_BASE = 'a9433aaea146ad004fb9f35507688314879294d2';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const IS_WINDOWS = process.platform === 'win32';
const MAX_CAPTURE_BYTES = 50000;
const TEMP_DIR_PREFIX = 'hooklatch-gemini-mutations-';

/**
 * Standard mutation catalogue covering visible slices, secret trimming,
 * Stripe/Standard Webhooks key derivation, MAC-before-freshness, tolerance zero,
 * unsigned identity, alien-header rescue, Doppler grammar ordering, and Sanity
 * canonical Base64url pad bits and milliseconds.
 *
 * Preserves the historical 10-mutant disposition from notes/phase-6/inputs/:
 * in old repository suites (base a9433aa), 9 were killed and 1 survived (mutant 10);
 * a subsequent coordinator guard in tests/adapters/phase5-header-isolation.test.ts
 * caught the survivor in Phase 5.
 */
const MUTANT_CATALOGUE = [
  {
    id: 1,
    name: 'whole-body-instead-of-visible-slice',
    category: 'visible Uint8Array slices',
    target: 'src/internal/verification.ts',
    selectedSuites: ['tests/adapters/phase3-byte-contract.test.ts'],
    original: 'const rawBody = new Uint8Array(request.rawBody);',
    replacement: 'const rawBody = new Uint8Array(request.rawBody.buffer);',
    historicalNote: 'Killed by tests/adapters/phase3-byte-contract.test.ts in original replay.',
  },
  {
    id: 2,
    name: 'trimming-literal-signing-secret',
    category: 'literal secret trimming',
    target: 'src/providers/shared.ts',
    selectedSuites: ['tests/providers/doppler.test.ts'],
    original: '  return utf8(secret);',
    replacement: '  return utf8(secret.trim());',
    historicalNote: 'Killed by tests/providers/doppler.test.ts in original replay.',
  },
  {
    id: 3,
    name: 'stripe-literal-secret-treated-as-base64',
    category: 'Stripe/Standard Webhooks key derivation',
    target: 'src/providers/stripe.ts',
    selectedSuites: ['tests/adapters/phase5-header-isolation.test.ts'],
    original: `import { concatBytes, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import {
  decodeHexSignature,
  decodeLiteralSecret,
  failure,
  isCanonicalTimestamp,
  isSchemeToken,
} from './shared.js';

const HEADER = 'stripe-signature';
const SCHEME = 'v1';
const TIMESTAMP_KEY = 't';

/**
 * Stripe \`Stripe-Signature\` header: \`t=<timestamp>,v1=<hex>[,v1=<hex>][,v0=...]\`.
 * Whitespace is permitted around comma-separated items. \`t\` is a singleton and
 * is signed; repeated \`t\` is rejected. The signature covers \`\${t}.<raw body>\`.
 */
export const stripeDescriptor: ProviderDescriptor = {
  provider: 'stripe',

  decodeSecret(secret: string): Uint8Array {
    // Stripe keys the HMAC with the literal secret string, including \`whsec_\`.
    return decodeLiteralSecret(secret, 'Stripe');
  },`,
    replacement: `import { concatBytes, decodeBase64, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import type { EventIdentity } from '../types.js';
import {
  decodeHexSignature,
  decodeLiteralSecret,
  failure,
  isCanonicalTimestamp,
  isSchemeToken,
} from './shared.js';

const HEADER = 'stripe-signature';
const SCHEME = 'v1';
const TIMESTAMP_KEY = 't';

/**
 * Stripe \`Stripe-Signature\` header: \`t=<timestamp>,v1=<hex>[,v1=<hex>][,v0=...]\`.
 * Whitespace is permitted around comma-separated items. \`t\` is a singleton and
 * is signed; repeated \`t\` is rejected. The signature covers \`\${t}.<raw body>\`.
 */
export const stripeDescriptor: ProviderDescriptor = {
  provider: 'stripe',

  decodeSecret(secret: string): Uint8Array {
    const encoded = secret.startsWith('whsec_') ? secret.slice(6) : secret;
    const bytes = decodeBase64(encoded);
    return bytes ?? utf8(secret);
  },`,
    historicalNote: 'Killed by tests/adapters/phase5-header-isolation.test.ts in original replay.',
  },
  {
    id: 4,
    name: 'doppler-deciding-scheme-before-validating-digest',
    category: 'Doppler grammar ordering',
    target: 'src/providers/doppler.ts',
    selectedSuites: ['tests/providers/doppler.test.ts'],
    original: `    const scheme = raw.slice(0, separator);
    const signature = decodeHexSignature(raw.slice(separator + 1));

    if (!isSchemeToken(scheme) || signature === null) {
      return failure('malformed-signature', 'The Doppler signature header is malformed.');
    }

    if (scheme !== SIGNATURE_SCHEME) {
      return failure('unsupported-scheme', 'The Doppler signature scheme is not supported.');
    }`,
    replacement: `    const scheme = raw.slice(0, separator);

    if (scheme !== SIGNATURE_SCHEME) {
      return failure('unsupported-scheme', 'The Doppler signature scheme is not supported.');
    }

    const signature = decodeHexSignature(raw.slice(separator + 1));

    if (!isSchemeToken(scheme) || signature === null) {
      return failure('malformed-signature', 'The Doppler signature header is malformed.');
    }`,
    historicalNote: 'Killed by tests/providers/doppler.test.ts in original replay.',
  },
  {
    id: 5,
    name: 'doppler-trimming-outer-header-whitespace',
    category: 'Doppler grammar ordering',
    target: 'src/providers/doppler.ts',
    selectedSuites: ['tests/integration/phase6-mutation-guards.test.ts'],
    original: `    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      return failure('missing-signature', 'No Doppler signature header was provided.');
    }`,
    replacement: `    const raw = headers.get(SIGNATURE_HEADER)?.trim();

    if (raw === undefined || raw === '') {
      return failure('missing-signature', 'No Doppler signature header was provided.');
    }`,
    historicalNote: 'Killed by tests/providers/doppler.test.ts in original replay.',
  },
  {
    id: 6,
    name: 'sentry-accepting-sha256-prefix',
    category: 'Sentry sha256 prefix',
    target: 'src/providers/sentry.ts',
    selectedSuites: ['tests/integration/phase6-mutation-guards.test.ts'],
    original: '    const signature = decodeHexSignature(raw);',
    replacement: `    const normalized = raw.startsWith('sha256=') ? raw.slice(7) : raw;
    const signature = decodeHexSignature(normalized);`,
    historicalNote: 'Killed by tests/providers/sentry.test.ts in original replay.',
  },
  {
    id: 7,
    name: 'timestamped-provider-skipping-freshness-at-zero-tolerance',
    category: 'tolerance zero',
    target: 'src/internal/verification.ts',
    selectedSuites: ['tests/internal/verification.test.ts'],
    original: `  const timestamp = parsed.identity.timestamp;

  if (timestamp !== null) {
    const age = receivedAt - timestamp;

    if (age > prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-expired', 'Webhook timestamp is outside the allowed past window.');

    if (age < -prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-future', 'Webhook timestamp is outside the allowed future window.');
  }`,
    replacement: `  const timestamp = parsed.identity.timestamp;

  if (timestamp !== null && prepared.options.toleranceSeconds > 0) {
    const age = receivedAt - timestamp;

    if (age > prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-expired', 'Webhook timestamp is outside the allowed past window.');

    if (age < -prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-future', 'Webhook timestamp is outside the allowed future window.');
  }`,
    historicalNote: 'Killed by tests/internal/verification.test.ts in original replay.',
  },
  {
    id: 8,
    name: 'freshness-evaluated-before-mac-on-stale-bad-mac',
    category: 'MAC-before-freshness',
    target: 'src/internal/verification.ts',
    selectedSuites: ['tests/internal/verification.test.ts'],
    original: `  const valid = prepared.descriptor.provider === 'fal'
    ? await verifyEd25519(prepared.keys, parsed.signatures, parsed.signedContent)
    : await verifyHmac(prepared.keys, parsed.signatures, parsed.signedContent, prepared.descriptor.crypto);

  if (!valid || (prepared.options.provider === 'fal'
    && (!('recipient' in parsed) || parsed.recipient !== prepared.options.expectedUserId))) {
    return failure(prepared, 'invalid-signature', 'Webhook signature is invalid.');
  }

  const timestamp = parsed.identity.timestamp;

  if (timestamp !== null) {
    const age = receivedAt - timestamp;

    if (age > prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-expired', 'Webhook timestamp is outside the allowed past window.');

    if (age < -prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-future', 'Webhook timestamp is outside the allowed future window.');
  }`,
    replacement: `  const timestamp = parsed.identity.timestamp;

  if (timestamp !== null) {
    const age = receivedAt - timestamp;

    if (age > prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-expired', 'Webhook timestamp is outside the allowed past window.');

    if (age < -prepared.options.toleranceSeconds) return failure(prepared, 'timestamp-future', 'Webhook timestamp is outside the allowed future window.');
  }

  const valid = prepared.descriptor.provider === 'fal'
    ? await verifyEd25519(prepared.keys, parsed.signatures, parsed.signedContent)
    : await verifyHmac(prepared.keys, parsed.signatures, parsed.signedContent, prepared.descriptor.crypto);

  if (!valid || (prepared.options.provider === 'fal'
    && (!('recipient' in parsed) || parsed.recipient !== prepared.options.expectedUserId))) {
    return failure(prepared, 'invalid-signature', 'Webhook signature is invalid.');
  }`,
    historicalNote: 'Killed by tests/internal/verification.test.ts in original replay.',
  },
  {
    id: 9,
    name: 'github-unsigned-metadata-treated-as-authenticated',
    category: 'unsigned identity',
    target: 'src/providers/github.ts',
    selectedSuites: ['tests/adapters/phase5-header-isolation.test.ts'],
    original: `    const identity: EventIdentity = {
      deliveryId: optionalHeader(headers, DELIVERY_HEADER),
      eventId: null,
      timestamp: null,
      authenticatedFields: [],
    };`,
    replacement: `    const identity: EventIdentity = {
      deliveryId: optionalHeader(headers, DELIVERY_HEADER),
      eventId: null,
      timestamp: null,
      authenticatedFields: optionalHeader(headers, DELIVERY_HEADER) !== null ? ['deliveryId'] : [],
    };`,
    historicalNote: 'Killed by tests/adapters/phase5-header-isolation.test.ts in original replay.',
  },
  {
    id: 10,
    name: 'github-request-rescued-by-alien-bearer-token',
    category: 'alien-header rescue',
    target: 'src/providers/github.ts',
    selectedSuites: ['tests/adapters/phase5-header-isolation.test.ts'],
    original: `    const raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      const legacy = headers.get(LEGACY_SIGNATURE_HEADER);

      if (legacy !== undefined && legacy.trim() !== '') {
        return failure('unsupported-scheme', 'Only the legacy SHA-1 GitHub signature was provided.');
      }

      return failure('missing-signature', 'No GitHub signature header was provided.');
    }`,
    replacement: `    let raw = headers.get(SIGNATURE_HEADER);

    if (raw === undefined || raw.trim() === '') {
      const auth = headers.get('authorization');
      if (auth && auth.startsWith('Bearer ')) {
        return {
          ok: true,
          signatures: [new Uint8Array(32)],
          signedContent: rawBody,
          identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] }
        };
      }
      const legacy = headers.get(LEGACY_SIGNATURE_HEADER);

      if (legacy !== undefined && legacy.trim() !== '') {
        return failure('unsupported-scheme', 'Only the legacy SHA-1 GitHub signature was provided.');
      }

      return failure('missing-signature', 'No GitHub signature header was provided.');
    }`,
    historicalNote: 'SURVIVED 20 adapter tests on base a9433aa; killed subsequently by coordinator regression in tests/adapters/phase5-header-isolation.test.ts.',
  },
  {
    id: 11,
    name: 'standard-webhooks-prefix-not-stripped',
    category: 'Stripe/Standard Webhooks key derivation',
    target: 'src/providers/standard-webhooks-protocol.ts',
    selectedSuites: ['tests/integration/phase6-mutation-guards.test.ts'],
    original: `      const encoded = secret.startsWith(SECRET_PREFIX)
        ? secret.slice(SECRET_PREFIX.length)
        : secret;`,
    replacement: '      const encoded = secret;',
    historicalNote: 'Killed by tests/providers/standard-webhooks.test.ts key derivation assertion.',
  },
  {
    id: 12,
    name: 'sanity-skipping-canonical-pad-bits-check',
    category: 'Sanity canonical Base64url pad bits and milliseconds',
    target: 'src/providers/sanity.ts',
    selectedSuites: ['tests/integration/phase6-mutation-guards.test.ts'],
    original: '  return encodeBase64Url(bytes) === value ? bytes : null;',
    replacement: '  return bytes;',
    historicalNote: 'Killed by tests/providers/sanity.test.ts pad-bit validation tests.',
  },
  {
    id: 13,
    name: 'sanity-milliseconds-not-converted-to-seconds',
    category: 'Sanity canonical Base64url pad bits and milliseconds',
    target: 'src/providers/sanity.ts',
    selectedSuites: ['tests/providers/sanity.test.ts'],
    original: `    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: timestamp / 1000,
      authenticatedFields: ['timestamp'],
    };`,
    replacement: `    const identity: EventIdentity = {
      deliveryId: null,
      eventId: null,
      timestamp: timestamp,
      authenticatedFields: ['timestamp'],
    };`,
    historicalNote: 'Killed by tests/providers/sanity.test.ts timestamp conversion assertions.',
  },
];

/**
 * Compute SHA-256 hash of a buffer.
 */
function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Scan all tracked files in repository and return map of relative paths to SHA-256 hashes.
 */
function scanTrackedHashes(repoPath) {
  const result = {};

  const res = spawnSync('git', ['ls-files'], {
    cwd: repoPath,
    shell: false,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    timeout: 30000,
  });

  if (res.status !== 0) {
    throw new Error(`git ls-files failed: ${res.stderr}`);
  }

  const files = res.stdout.split(/\r?\n/).filter(Boolean);

  for (const file of files) {
    const fullPath = path.resolve(repoPath, file);

    if (existsSync(fullPath)) {
      result[file.replace(/\\/g, '/')] = sha256(readFileSync(fullPath));
    }
  }

  return result;
}

/**
 * Compare two hash maps for exact byte equality.
 */
function hashesEqual(first, second) {
  const firstKeys = Object.keys(first).sort();
  const secondKeys = Object.keys(second).sort();

  if (firstKeys.length !== secondKeys.length) return false;

  for (let i = 0; i < firstKeys.length; i += 1) {
    const k = firstKeys[i];

    if (k !== secondKeys[i] || first[k] !== second[k]) return false;
  }

  return true;
}

/**
 * Check git status in repository. Allows only exact scripts/phase6-mutations.mjs
 * and ignored notes/ files.
 */
function checkGitStatus(repoPath) {
  const res = spawnSync('git', ['status', '--porcelain'], {
    cwd: repoPath,
    shell: false,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    timeout: 30000,
  });

  if (res.status !== 0) {
    return { clean: false, output: res.stderr };
  }

  const lines = res.stdout.split(/\r?\n/).filter(Boolean);

  const dirty = lines.filter((line) => {
    const file = line.slice(3).trim();

    return file !== 'scripts/phase6-mutations.mjs' && !file.startsWith('notes/');
  });

  return {
    clean: dirty.length === 0,
    output: dirty.join('\n'),
  };
}

/**
 * Get current git commit SHA.
 */
function getCurrentSha(repoPath) {
  const res = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repoPath,
    shell: false,
    encoding: 'utf8',
    timeout: 30000,
  });

  return res.status === 0 ? res.stdout.trim() : 'unknown';
}

/**
 * Terminate a spawned child process and all its descendants.
 * Windows: taskkill /PID <pid> /T /F (strictly targets only child pid and descendants).
 * POSIX: SIGKILL to process group (-pid), falling back to child pid.
 */
function terminateChildTree(pid) {
  if (!pid) return;

  if (IS_WINDOWS) {
    try {
      spawnSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
        shell: false,
        windowsHide: true,
        timeout: 10000,
      });
    } catch {
      // Ignore if process already exited
    }
  } else {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // Ignore if process already exited
      }
    }
  }
}

/**
 * Run a child process with shell: false, detached process group on POSIX,
 * strictly bounded stdout/stderr buffers, and enforced execution timeout.
 */
function runProcess(command, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 180000;

  return new Promise((resolve) => {
    let timedOut = false;
    let timer = null;
    let stdout = '';
    let stderr = '';

    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      detached: !IS_WINDOWS,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    child.stdout.on('data', (chunk) => {
      if (stdout.length < MAX_CAPTURE_BYTES) {
        const remaining = MAX_CAPTURE_BYTES - stdout.length;

        stdout += chunk.slice(0, remaining);
      }
    });

    child.stderr.on('data', (chunk) => {
      if (stderr.length < MAX_CAPTURE_BYTES) {
        const remaining = MAX_CAPTURE_BYTES - stderr.length;

        stderr += chunk.slice(0, remaining);
      }
    });

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };

    timer = setTimeout(() => {
      timedOut = true;
      terminateChildTree(child.pid);
    }, timeoutMs);

    child.on('error', (err) => {
      cleanup();
      resolve({
        exitCode: -1,
        signal: null,
        stdout,
        stderr: `${stderr}\n${String(err)}`.slice(-4000),
        timedOut: false,
        error: err,
      });
    });

    child.on('close', (code, signal) => {
      cleanup();
      let exitCode = code;

      if (exitCode === null) {
        exitCode = timedOut ? -1 : (signal ? 128 + 15 : -1);
      }

      resolve({
        exitCode,
        signal,
        stdout,
        stderr: stderr.slice(-4000),
        timedOut,
      });
    });
  });
}

/**
 * Sanitize and redact sensitive tokens, keys, signatures, and byte dumps from error excerpts.
 */
function sanitizeMessage(raw) {
  // Assert the report-string contract at this untyped JSON boundary.
  try { assert.match(raw, /^[\s\S]*$/); }
  catch { return ''; }

  let sanitized = raw;

  // Redact synthetic and standard webhook secret keys
  sanitized = sanitized.replace(/whsec_[A-Za-z0-9_.-]+/g, 'whsec_[REDACTED]');
  sanitized = sanitized.replace(/secret_[A-Za-z0-9_.-]+/g, 'secret_[REDACTED]');
  sanitized = sanitized.replace(/CANARY_SECRET_[A-Za-z0-9_]+/g, '[REDACTED_CANARY_SECRET]');
  sanitized = sanitized.replace(/CANARY_PAYLOAD_[A-Za-z0-9_]+/g, '[REDACTED_CANARY_PAYLOAD]');

  // Redact 64-char hex digests
  sanitized = sanitized.replace(/\b[a-f0-9]{64}\b/gi, '[REDACTED_HEX_64]');

  // Redact Base64 and Base64url signatures
  sanitized = sanitized.replace(/v1,[A-Za-z0-9+/=]+/g, 'v1,[REDACTED_SIG]');
  sanitized = sanitized.replace(/v1=[A-Za-z0-9_-]+/g, 'v1=[REDACTED_SIG]');

  // Redact Bearer authorization tokens
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9_.-]+/g, 'Bearer [REDACTED_TOKEN]');

  // Redact massive Uint8Array byte dumps in expect diffs
  sanitized = sanitized.replace(/Uint8Array\s*\[[\s\d,]+\]/g, 'Uint8Array [ [REDACTED_BYTES] ]');

  // Bound excerpt length
  if (sanitized.length > 600) {
    sanitized = `${sanitized.slice(0, 600)}... [truncated]`;
  }

  return sanitized;
}

/**
 * Determine whether a test failure message represents a genuine executed assertion matcher failure,
 * rather than an unhandled runtime error (such as a ReferenceError or TypeError thrown inside test body).
 */
function isFailedMatcher(detail) {
  try {
    assert.equal(detail.matcherResult.pass, false);
    assert.match(detail.matcherResult.message, /^expect\(/);

    return true;
  } catch { return false; }
}

/**
 * Extract structured assertion failures from Jest JSON report.
 */
function extractFailures(reportData) {
  const failures = [];

  if (!reportData || !Array.isArray(reportData.testResults)) return failures;

  for (const suite of reportData.testResults) {
    if (!Array.isArray(suite.assertionResults)) continue;

    for (const [index, assertion] of suite.assertionResults.entries()) {
      if (assertion.status !== 'failed') continue;
      const details = Array.isArray(assertion.failureDetails) ? assertion.failureDetails.filter(isFailedMatcher) : [];

      if (details.length > 0) {
        // Deliberately omit title, messages, actual/expected and stack values.
        failures.push({
          name: `assertion ${index + 1}`,
          suite: path.basename(suite.name ?? 'unknown-suite'),
          matchers: details.map((detail) => detail.matcherResult.name ?? 'jest-matcher'),
          messages: ['Executed Jest matcher failed; values omitted.'],
        });
      }
    }
  }

  return failures;
}

/**
 * Classify a test execution using strict evidence rules:
 * - Assertion killed: requires Jest JSON report, testsFailed > 0, and executed genuine assertion failures.
 * - Survived: Jest exitCode 0, testsPassed > 0, testsFailed 0.
 * - Compile/Runtime error: Jest crashed, compilation failure, runtimeErrorSuites > 0, unhandled test throw,
 *   or nonzero exit without genuine assertion failures.
 * - Timeout: child process timed out.
 * - Invalid patch: target text not matched exactly once, or no-op mutation.
 */
function classifyExecution({ exitCode, timedOut, reportData, matchCount, isNoOp }) {
  if (isNoOp || matchCount !== 1) {
    return 'invalid-patch';
  }

  if (timedOut) {
    return 'timeout';
  }

  if (!reportData || !Array.isArray(reportData.testResults)) {
    return 'compile-or-runtime-error';
  }

  if (reportData.numRuntimeErrorTestSuites > 0) {
    return 'compile-or-runtime-error';
  }

  // Reject impossible combinations (e.g. exit 0 with failed tests)
  if (exitCode === 0 && reportData.numFailedTests > 0) {
    return 'compile-or-runtime-error';
  }

  if (exitCode === 0 && reportData.numPassedTests > 0 && reportData.numFailedTests === 0) {
    return 'survived';
  }

  if (reportData.numFailedTests > 0) {
    const failures = extractFailures(reportData);

    if (failures.length > 0) {
      return 'assertion-killed';
    }
  }

  return 'compile-or-runtime-error';
}

/**
 * Safely unlink dependency junction or symlink.
 * Fails closed if the path is an ordinary directory or if unlinking fails.
 */
function safeUnlinkJunction(linkPath, expectedParent) {
  const resolved = path.resolve(linkPath);
  const resolvedParent = path.resolve(expectedParent);
  const rel = path.relative(resolvedParent, resolved);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Refusing to remove link outside expected parent: ${resolved}`);
  }

  let stat;

  try {
    stat = lstatSync(resolved);
  } catch (err) {
    if (err.code === 'ENOENT') return;

    throw err;
  }

  let isLink = stat.isSymbolicLink();

  if (!isLink && IS_WINDOWS && stat.isDirectory()) {
    try {
      readlinkSync(resolved);
      isLink = true;
    } catch {
      isLink = false;
    }
  }

  if (!isLink) {
    throw new Error(`Expected junction or symlink at ${resolved}, but found ordinary directory. Refusing to remove.`);
  }

  try {
    unlinkSync(resolved);
  } catch {
    rmdirSync(resolved);
  }

  let remaining = false;

  try {
    lstatSync(resolved);
    remaining = true;
  } catch {
    remaining = false;
  }

  if (remaining) {
    throw new Error(`Failed to unlink junction at ${resolved}; link still exists.`);
  }
}

/**
 * Safely delete temp directory. Validates that it is strictly inside os.tmpdir()
 * with the authorized prefix.
 */
function safeDeleteTempDir(tempDir) {
  const tempParent = path.resolve(os.tmpdir());
  const resolvedTemp = path.resolve(tempDir);
  const rel = path.relative(tempParent, resolvedTemp);

  if (rel.startsWith('..') || path.isAbsolute(rel) || rel === '') {
    throw new Error(`Refusing to delete directory outside OS temp: ${resolvedTemp}`);
  }

  if (!path.basename(resolvedTemp).startsWith(TEMP_DIR_PREFIX)) {
    throw new Error(`Refusing to delete temp directory without expected prefix: ${resolvedTemp}`);
  }

  if (existsSync(resolvedTemp)) {
    rmSync(resolvedTemp, { recursive: true, force: true });
  }

  if (existsSync(resolvedTemp)) {
    throw new Error(`Failed to remove temp directory: ${resolvedTemp}`);
  }
}

/**
 * Create isolated OS-temp snapshot of tracked files.
 */
function createSnapshot(repoPath, scratchDir) {
  const snapshotDir = path.join(scratchDir, 'snapshot');

  mkdirSync(snapshotDir, { recursive: true });

  const trackedFilesRes = spawnSync('git', [
    'ls-files',
    'src',
    'tests',
    'package.json',
    'jest.config.cjs',
    'tsconfig.json',
    'tsconfig.check.json',
    'tsconfig.cli.json',
  ], {
    cwd: repoPath,
    shell: false,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    timeout: 30000,
  });

  if (trackedFilesRes.status !== 0) {
    throw new Error(`git ls-files failed: ${trackedFilesRes.stderr}`);
  }

  const files = trackedFilesRes.stdout.split(/\r?\n/).filter(Boolean);

  for (const file of files) {
    const srcFile = path.resolve(repoPath, file);
    const destFile = path.resolve(snapshotDir, file);
    const rel = path.relative(snapshotDir, destFile);

    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new Error(`Invalid destination path escaping snapshot: ${destFile}`);
    }

    mkdirSync(path.dirname(destFile), { recursive: true });
    copyFileSync(srcFile, destFile);
  }

  const realNodeModules = path.resolve(repoPath, 'node_modules');
  const snapshotNodeModules = path.join(snapshotDir, 'node_modules');

  if (!existsSync(realNodeModules)) {
    throw new Error(`Repository node_modules not found at: ${realNodeModules}`);
  }

  symlinkSync(realNodeModules, snapshotNodeModules, IS_WINDOWS ? 'junction' : 'dir');

  return { snapshotDir, snapshotNodeModules };
}

/**
 * Run Jest suites in the isolated snapshot.
 */
async function runJestInSnapshot(snapshotDir, suites, label) {
  const reportPath = path.join(snapshotDir, `__jest_report_${label}.json`);
  const jestBin = path.join(snapshotDir, 'node_modules', 'jest', 'bin', 'jest.js');

  const args = [
    '--experimental-vm-modules',
    jestBin,
    '--runInBand',
    '--no-cache',
    '--runTestsByPath',
    ...suites,
    '--json',
    '--outputFile',
    reportPath,
  ];

  const exec = await runProcess('node', args, { cwd: snapshotDir, timeoutMs: 120000 });
  let reportData = null;

  if (existsSync(reportPath)) {
    try {
      reportData = JSON.parse(readFileSync(reportPath, 'utf8'));
    } catch {
      reportData = null;
    }

    try {
      unlinkSync(reportPath);
    } catch {
      // Ignore
    }
  }

  const testsPassed = reportData?.numPassedTests ?? 0;
  const testsFailed = reportData?.numFailedTests ?? 0;
  const runtimeErrorSuites = reportData?.numRuntimeErrorTestSuites ?? 0;
  const failures = reportData ? extractFailures(reportData) : [];

  let status = 'passed';

  if (exec.timedOut) {
    status = 'timeout';
  } else if (!reportData || runtimeErrorSuites > 0) {
    status = 'compile-or-runtime-error';
  } else if (exec.exitCode !== 0 || testsFailed > 0) {
    status = failures.length > 0 ? 'assertion-failed' : 'compile-or-runtime-error';
  }

  return {
    command: ['node', ...args],
    exitCode: exec.exitCode,
    signal: exec.signal,
    timedOut: exec.timedOut,
    testsPassed,
    testsFailed,
    runtimeErrorSuites,
    failures,
    status,
    stderr: exec.stderr,
    reportData,
  };
}

/**
 * Validate pure classifier logic with synthetic fixtures.
 */
function validateClassifierDirect() {
  const controlPassed = classifyExecution({
    exitCode: 0,
    timedOut: false,
    reportData: { numPassedTests: 10, numFailedTests: 0, numRuntimeErrorTestSuites: 0, testResults: [] },
    matchCount: 1,
    isNoOp: false,
  });

  assert.equal(controlPassed, 'survived', 'Harmless control must be classified as survived.');

  const controlCompileError = classifyExecution({
    exitCode: 1,
    timedOut: false,
    reportData: { numPassedTests: 0, numFailedTests: 0, numRuntimeErrorTestSuites: 1, testResults: [] },
    matchCount: 1,
    isNoOp: false,
  });

  assert.notEqual(controlCompileError, 'assertion-killed', 'Compile error must never be classified as assertion-killed.');
  assert.equal(controlCompileError, 'compile-or-runtime-error', 'Compile error must be classified as compile-or-runtime-error.');

  const controlAssertionFailed = classifyExecution({
    exitCode: 1,
    timedOut: false,
    reportData: {
      numPassedTests: 5,
      numFailedTests: 1,
      numRuntimeErrorTestSuites: 0,
      testResults: [
        {
          assertionResults: [
            {
              status: 'failed',
              fullName: 'sample assertion',
              failureDetails: [{ matcherResult: { name: 'toBe', message: 'expect(received).toBe(expected)', pass: false } }],
              failureMessages: ['Error: expect(received).toBe(expected)\n\nExpected: true\nReceived: false'],
            },
          ],
        },
      ],
    },
    matchCount: 1,
    isNoOp: false,
  });

  assert.equal(controlAssertionFailed, 'assertion-killed', 'Real assertion failure must be classified as assertion-killed.');

  // Distinguish unhandled runtime throw from assertion failure
  const controlRuntimeThrow = classifyExecution({
    exitCode: 1,
    timedOut: false,
    reportData: {
      numPassedTests: 5,
      numFailedTests: 1,
      numRuntimeErrorTestSuites: 0,
      testResults: [
        {
          assertionResults: [
            {
              status: 'failed',
              fullName: 'runtime throw test',
              failureMessages: ['ReferenceError: unhandledIdentifier is not defined\n    at Object.<anonymous>'],
            },
          ],
        },
      ],
    },
    matchCount: 1,
    isNoOp: false,
  });

  assert.equal(controlRuntimeThrow, 'compile-or-runtime-error', 'Unhandled ReferenceError must classify as compile-or-runtime-error.');
  assert.notEqual(controlRuntimeThrow, 'assertion-killed', 'Unhandled ReferenceError must never count as assertion-killed.');

  const controlTimeout = classifyExecution({
    exitCode: -1,
    timedOut: true,
    reportData: null,
    matchCount: 1,
    isNoOp: false,
  });

  assert.equal(controlTimeout, 'timeout', 'Timeout must be classified as timeout.');
  assert.notEqual(controlTimeout, 'assertion-killed', 'Timeout must never count as killed.');

  const controlInvalidPatch = classifyExecution({
    exitCode: 0,
    timedOut: false,
    reportData: null,
    matchCount: 0,
    isNoOp: false,
  });

  assert.equal(controlInvalidPatch, 'invalid-patch', 'Unmatched patch must be classified as invalid-patch.');
}

/**
 * Validate classifier against real Jest in snapshot using controlled temporary examples:
 * 1. Harmless comment edit -> survived
 * 2. Syntax / startup error -> compile-or-runtime-error (not killed)
 * 3. Runtime throw inside test body -> compile-or-runtime-error (not killed)
 * 4. Real matcher failure -> assertion-killed
 */
async function validateClassifierWithRealJest(snapshotDir) {
  const targetPath = path.join(snapshotDir, 'src', 'internal', 'verification.ts');
  const original = readFileSync(targetPath, 'utf8');
  const targetSuite = 'tests/internal/verification.test.ts';

  try {
    // Control 1: harmless comment mutation -> must survive
    const harmlessMutated = `// runner harmless control comment\n${original}`;

    writeFileSync(targetPath, harmlessMutated, 'utf8');

    const harmlessRun = await runJestInSnapshot(snapshotDir, [targetSuite], 'control-harmless');

    const harmlessClass = classifyExecution({
      exitCode: harmlessRun.exitCode,
      timedOut: harmlessRun.timedOut,
      reportData: harmlessRun.reportData,
      matchCount: 1,
      isNoOp: false,
    });

    assert.equal(harmlessClass, 'survived', 'Real Jest harmless control must survive.');

    // Control 2: syntax / compile error -> must not count as killed
    const syntaxMutated = `const __SYNTAX_ERROR__ = %%%;\n${original}`;

    writeFileSync(targetPath, syntaxMutated, 'utf8');

    const syntaxRun = await runJestInSnapshot(snapshotDir, [targetSuite], 'control-syntax');

    const syntaxClass = classifyExecution({
      exitCode: syntaxRun.exitCode,
      timedOut: syntaxRun.timedOut,
      reportData: syntaxRun.reportData,
      matchCount: 1,
      isNoOp: false,
    });

    assert.notEqual(syntaxClass, 'assertion-killed', 'Real Jest syntax error must never count as assertion-killed.');
    assert.equal(syntaxClass, 'compile-or-runtime-error', 'Real Jest syntax error must classify as compile-or-runtime-error.');

    // Control 3: runtime exception with assertion-like text must not count as a matcher failure.
    let additionalControls;
    const testPath = path.join(snapshotDir, targetSuite);
    const originalTest = readFileSync(testPath, 'utf8');

    try {
      const runtimeThrowMutated = originalTest +
        "\ntest('runtime marker control', () => { const error = new Error('Expected: synthetic-private-value'); error.name = 'HooklatchError'; throw error; });\n";

      writeFileSync(testPath, runtimeThrowMutated, 'utf8');
      writeFileSync(targetPath, original, 'utf8');

      const runtimeThrowRun = await runJestInSnapshot(snapshotDir, [targetSuite], 'control-runtime-throw');

      const runtimeThrowClass = classifyExecution({
        exitCode: runtimeThrowRun.exitCode,
        timedOut: runtimeThrowRun.timedOut,
        reportData: runtimeThrowRun.reportData,
        matchCount: 1,
        isNoOp: false,
      });

      assert.notEqual(runtimeThrowClass, 'assertion-killed', 'Runtime throw inside test body must never count as assertion-killed.');
      assert.equal(runtimeThrowClass, 'compile-or-runtime-error', 'Runtime throw inside test body must classify as compile-or-runtime-error.');
      assert.equal(runtimeThrowRun.testsFailed, 1, 'Runtime control must execute and fail exactly one test.');
      assert.equal(runtimeThrowRun.runtimeErrorSuites, 0, 'Runtime control must not fail suite registration.');

      writeFileSync(testPath, originalTest + "\ntest('real matcher control', () => { expect(1).toBe(2); });\n", 'utf8');
      const matcherRun = await runJestInSnapshot(snapshotDir, [targetSuite], 'control-real-matcher');

      const matcherClass = classifyExecution({
        exitCode: matcherRun.exitCode, timedOut: matcherRun.timedOut,
        reportData: matcherRun.reportData, matchCount: 1, isNoOp: false,
      });

      assert.equal(matcherClass, 'assertion-killed', 'Real executed matcher must count as an assertion kill.');
      additionalControls = { runtimeThrowClass, matcherClass, runtimeFailedTests: runtimeThrowRun.testsFailed, runtimeErrorSuites: runtimeThrowRun.runtimeErrorSuites };

    } finally {
      writeFileSync(testPath, originalTest, 'utf8');
    }

    return {
      harmlessClass,
      syntaxClass,
      ...additionalControls,
      verified: true,
    };
  } finally {
    writeFileSync(targetPath, original, 'utf8');
  }
}

/**
 * Validate output redaction of synthetic canaries across message sanitization.
 */
function validateRedactionCanaries() {
  const canaryInput = 'Error: expect(received).toBe(expected)\n' +
    'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw secret_abcdef123456 ' +
    'CANARY_SECRET_TEST123 CANARY_PAYLOAD_DATA456 ' +
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ' +
    'Bearer eyJhbGciOiJIUzI1NiJ9.test v1,dGVzdF9zaWduYXR1cmU= ' +
    'Uint8Array [ 10, 20, 30, 40, 50 ]';

  const sanitized = sanitizeMessage(canaryInput);

  assert(!sanitized.includes('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'), 'Standard Webhooks secret was not redacted.');
  assert(!sanitized.includes('abcdef123456'), 'Provider secret was not redacted.');
  assert(!sanitized.includes('CANARY_SECRET_TEST123'), 'Canary secret was not redacted.');
  assert(!sanitized.includes('CANARY_PAYLOAD_DATA456'), 'Canary payload was not redacted.');
  assert(!sanitized.includes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), 'Hex signature was not redacted.');
  assert(!sanitized.includes('dGVzdF9zaWduYXR1cmU='), 'Base64 signature was not redacted.');
  assert(!sanitized.includes('eyJhbGciOiJIUzI1NiJ9'), 'Bearer token was not redacted.');
}

/**
 * Parse and validate CLI arguments upfront before any resources are allocated.
 * Rejects unknown options, partial IDs, unknown IDs, and duplicate IDs with code 2.
 */
function parseArgs(argv) {
  const options = {
    selectedIds: null,
    validateClassifierOnly: false,
    includeControls: false,
    selfTest: false,
    help: false,
  };

  const knownIds = new Set(MUTANT_CATALOGUE.map((m) => m.id));

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--validate-classifier') {
      options.validateClassifierOnly = true;
    } else if (arg === '--self-test') {
      options.selfTest = true;
    } else if (arg === '--include-controls') {
      options.includeControls = true;
    } else if (arg === '--id' || arg === '--mutant') {
      i += 1;

      if (i >= argv.length) {
        throw new Error(`Missing value for argument: ${arg}`);
      }

      options.selectedIds = parseAndValidateIds(argv[i], knownIds);
    } else if (arg.startsWith('--id=') || arg.startsWith('--mutant=')) {
      const val = arg.split('=')[1];

      options.selectedIds = parseAndValidateIds(val, knownIds);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

/**
 * Parse and strictly validate mutant IDs.
 */
function parseAndValidateIds(raw, knownIds) {
  if (!raw || raw.trim() === '') {
    throw new Error('Mutant ID list cannot be empty.');
  }

  const pieces = raw.split(',');
  const parsedIds = [];
  const seen = new Set();

  for (const piece of pieces) {
    const trimmed = piece.trim();

    if (!/^[1-9]\d*$/.test(trimmed)) {
      throw new Error(`Invalid mutant ID format: "${trimmed}". IDs must be canonical integers without junk.`);
    }

    const id = Number.parseInt(trimmed, 10);

    if (seen.has(id)) {
      throw new Error(`Duplicate mutant ID: ${id}`);
    }

    seen.add(id);

    if (!knownIds.has(id)) {
      throw new Error(`Unknown mutant ID: ${id}. Available IDs: ${[...knownIds].sort((a, b) => a - b).join(', ')}`);
    }

    parsedIds.push(id);
  }

  return parsedIds;
}

/**
 * Main execution driver. Returns integer exit code. Does not invoke process.exit internally.
 */
async function main() {
  const startTime = Date.now();
  let cliOptions;

  try {
    cliOptions = parseArgs(process.argv);
  } catch (err) {
    console.error(`Invalid invocation: ${err.message}`);

    return 2;
  }

  if (cliOptions.help) {
    console.log(`
Hooklatch Phase 6 Isolated Mutation Runner
Usage: node scripts/phase6-mutations.mjs [options]

Options:
  --id, --mutant <ids>     Comma-separated list of mutant IDs to run (e.g. 1,10)
  --validate-classifier    Run classifier validation against real Jest in isolated snapshot
  --self-test              Run full self-test suite (argument errors, classifiers, canaries, cleanup)
  --include-controls       Include controlled temporary examples in qualification
  --help, -h               Show this help message

Exit codes:
  0 = Completed valid qualification (survivors explicitly reported)
  1 = Baseline, patch, infrastructure, or timeout prevents valid completion
  2 = Invalid invocation
  3 = Cleanup or original-tree integrity failure (takes precedence)
`);

    return 0;
  }

  // Pure logic classifier unit check
  validateClassifierDirect();

  // Validate output redaction of synthetic canaries
  validateRedactionCanaries();

  // Pre-run checkout integrity recording
  const initialHashes = scanTrackedHashes(REPO_ROOT);
  const initialGitStatus = checkGitStatus(REPO_ROOT);
  const currentSha = getCurrentSha(REPO_ROOT);

  if (!initialGitStatus.clean) {
    console.error(`Preflight failure: Real checkout is not clean:\n${initialGitStatus.output}`);

    return 1;
  }

  let tempDir = null;
  let snapshotNodeModules = null;
  let qualificationFailed = false;
  let runError = null;
  let reportOutput = null;
  let finalExitCode = 0;

  try {
    qualification: {
    tempDir = mkdtempSync(path.join(os.tmpdir(), TEMP_DIR_PREFIX));

    const { snapshotDir, snapshotNodeModules: modulesLink } = createSnapshot(REPO_ROOT, tempDir);

    snapshotNodeModules = modulesLink;

    if (cliOptions.selfTest) {
      console.error('Running self-test suite (arguments, classifiers, redaction, lifecycle)...');
      const realControls = await validateClassifierWithRealJest(snapshotDir);

      reportOutput = {
        schemaVersion: SCHEMA_VERSION,
        baseSha: PINNED_BASE_SHA,
        currentSha,
        mode: 'self-test',
        metadata: {
          nodeVersion: process.version,
          platform: process.platform,
          pid: process.pid,
          tool: 'jest',
        },
        controls: realControls,
        redactionVerified: true,
        durationMs: Date.now() - startTime,
        status: 'validated',
      };

      break qualification;
    }

    if (cliOptions.validateClassifierOnly) {
      console.error('Running classifier validation against real Jest in isolated snapshot...');
      const realControls = await validateClassifierWithRealJest(snapshotDir);

      reportOutput = {
        schemaVersion: SCHEMA_VERSION,
        baseSha: PINNED_BASE_SHA,
        currentSha,
        mode: 'classifier-validation-only',
        metadata: {
          nodeVersion: process.version,
          platform: process.platform,
          pid: process.pid,
          tool: 'jest',
        },
        controls: realControls,
        durationMs: Date.now() - startTime,
        status: 'validated',
      };

      break qualification;
    }

    const mutantsToRun = MUTANT_CATALOGUE.filter((m) => {
      if (!cliOptions.selectedIds) return true;

      return cliOptions.selectedIds.includes(m.id);
    });

    // Collect unique suites for unmodified baseline run
    const baselineSuites = [...new Set(mutantsToRun.flatMap((m) => m.selectedSuites))].sort();

    console.error(`Running unmodified baseline across ${baselineSuites.length} suites...`);
    const baselineStart = Date.now();
    const baselineResult = await runJestInSnapshot(snapshotDir, baselineSuites, 'baseline');
    const baselineDurationMs = Date.now() - baselineStart;

    if (baselineResult.status !== 'passed') {
      qualificationFailed = true;
      console.error(`Baseline failed (${baselineResult.status}); raw output omitted.`);

      reportOutput = {
        schemaVersion: SCHEMA_VERSION,
        baseSha: PINNED_BASE_SHA,
        currentSha,
        metadata: {
          nodeVersion: process.version,
          platform: process.platform,
          pid: process.pid,
          tool: 'jest',
        },
        baseline: {
          command: baselineResult.command,
          status: baselineResult.status,
          exitCode: baselineResult.exitCode,
          testsPassed: baselineResult.testsPassed,
          testsFailed: baselineResult.testsFailed,
          runtimeErrorSuites: baselineResult.runtimeErrorSuites,
          durationMs: baselineDurationMs,
        },
        records: [],
        qualificationStatus: 'aborted-baseline-failed',
        durationMs: Date.now() - startTime,
      };

      break qualification;
    }

    console.error(`Baseline PASS: ${baselineResult.testsPassed} tests passed across ${baselineSuites.length} suites.`);

    let controlEvidence = null;

    if (cliOptions.includeControls) {
      controlEvidence = await validateClassifierWithRealJest(snapshotDir);
    }

    const records = [];

    for (const mutant of mutantsToRun) {
      console.error(`Testing mutant ${mutant.id}: ${mutant.name}...`);
      const targetFile = path.resolve(snapshotDir, mutant.target);

      if (!existsSync(targetFile)) {
        records.push({
          id: mutant.id,
          name: mutant.name,
          category: mutant.category,
          target: mutant.target,
          replacementCount: 0,
          selectedSuites: mutant.selectedSuites,
          actualExit: -1,
          classification: 'invalid-patch',
          assertionEvidence: [],
          historicalNote: mutant.historicalNote,
        });
        qualificationFailed = true;
        continue;
      }

      const originalContent = readFileSync(targetFile, 'utf8');
      const isNoOp = mutant.original === mutant.replacement;
      const matchCount = originalContent.split(mutant.original).length - 1;

      if (matchCount !== 1 || isNoOp) {
        records.push({
          id: mutant.id,
          name: mutant.name,
          category: mutant.category,
          target: mutant.target,
          replacementCount: matchCount,
          selectedSuites: mutant.selectedSuites,
          actualExit: -1,
          classification: 'invalid-patch',
          assertionEvidence: [],
          historicalNote: mutant.historicalNote,
        });
        qualificationFailed = true;
        continue;
      }

      const mutatedContent = originalContent.replace(mutant.original, mutant.replacement);

      writeFileSync(targetFile, mutatedContent, 'utf8');

      const mutantStart = Date.now();
      let execution;

      try {
        execution = await runJestInSnapshot(snapshotDir, mutant.selectedSuites, `mutant-${mutant.id}`);
      } finally {
        writeFileSync(targetFile, originalContent, 'utf8');
      }

      const restoredHash = sha256(readFileSync(targetFile));
      const expectedHash = sha256(Buffer.from(originalContent, 'utf8'));

      if (restoredHash !== expectedHash) throw new Error(`Failed to restore pristine bytes in ${mutant.target}`);

      const classification = classifyExecution({
        exitCode: execution.exitCode,
        timedOut: execution.timedOut,
        reportData: execution.reportData,
        matchCount,
        isNoOp,
      });

      if (classification === 'compile-or-runtime-error' || classification === 'timeout') {
        qualificationFailed = true;
      }

      records.push({
        id: mutant.id,
        name: mutant.name,
        category: mutant.category,
        target: mutant.target,
        replacementCount: matchCount,
        selectedSuites: mutant.selectedSuites,
        actualExit: execution.exitCode,
        classification,
        assertionEvidence: execution.failures,
        durationMs: Date.now() - mutantStart,
        historicalNote: mutant.historicalNote,
      });

      console.error(`  Mutant ${mutant.id} result: ${classification}`);
    }

    const summary = {
      total: records.length,
      'assertion-killed': records.filter((r) => r.classification === 'assertion-killed').length,
      survived: records.filter((r) => r.classification === 'survived').length,
      'compile-or-runtime-error': records.filter((r) => r.classification === 'compile-or-runtime-error').length,
      'invalid-patch': records.filter((r) => r.classification === 'invalid-patch').length,
      timeout: records.filter((r) => r.classification === 'timeout').length,
    };

    reportOutput = {
      schemaVersion: SCHEMA_VERSION,
      baseSha: PINNED_BASE_SHA,
      historicalReviewBase: HISTORICAL_REVIEW_BASE,
      currentSha,
      metadata: {
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid,
        tool: 'jest',
      },
      baseline: {
        command: baselineResult.command,
        status: baselineResult.status,
        exitCode: baselineResult.exitCode,
        testsPassed: baselineResult.testsPassed,
        testsFailed: baselineResult.testsFailed,
        runtimeErrorSuites: baselineResult.runtimeErrorSuites,
        durationMs: baselineDurationMs,
      },
      controls: controlEvidence,
      records,
      summary,
      durationMs: Date.now() - startTime,
    };
    }
  } catch (err) {
    runError = err;
    qualificationFailed = true;
    console.error('Execution error while running qualification.');
  } finally {
    let junctionUnlinked = false;
    let tempDirDeleted = false;
    let cleanupOk = true;
    let integrityOk = true;

    // Cleanup junction first
    try {
      if (tempDir) {
        const linkPath = snapshotNodeModules ?? path.join(tempDir, 'snapshot', 'node_modules');

        safeUnlinkJunction(linkPath, path.join(tempDir, 'snapshot'));
        junctionUnlinked = true;
      }
    } catch (err) {
      console.error(`Junction unlink error: ${err.message}`);
      cleanupOk = false;
    }

    // Only recursively delete temp directory if junction unlink succeeded
    try {
      if (junctionUnlinked && tempDir) {
        safeDeleteTempDir(tempDir);
        tempDirDeleted = !existsSync(tempDir);

        if (!tempDirDeleted) {
          cleanupOk = false;
        }
      }
    } catch (err) {
      console.error(`Temp directory deletion error: ${err.message}`);
      cleanupOk = false;
    }

    // Verify tracked checkout integrity
    try {
      const finalHashes = scanTrackedHashes(REPO_ROOT);

      if (!hashesEqual(initialHashes, finalHashes)) {
        console.error('Integrity failure: Tracked file hashes modified in real checkout!');
        integrityOk = false;
      }

      const finalGitStatus = checkGitStatus(REPO_ROOT);

      if (!finalGitStatus.clean) {
        console.error(`Integrity failure: Real checkout modified:\n${finalGitStatus.output}`);
        integrityOk = false;
      }
    } catch (err) {
      console.error(`Integrity check error: ${err.message}`);
      integrityOk = false;
    }

    if (!reportOutput) {
      reportOutput = {
        schemaVersion: SCHEMA_VERSION,
        baseSha: PINNED_BASE_SHA,
        currentSha,
        metadata: {
          nodeVersion: process.version,
          platform: process.platform,
          pid: process.pid,
          tool: 'jest',
        },
        error: runError ? { code: 'execution-failed' } : null,
        durationMs: Date.now() - startTime,
      };
    }

    reportOutput.cleanup = {
      cleanupOk,
      integrityOk,
      junctionUnlinked,
      tempDirDeleted,
    };

    // Emit single machine-readable JSON output strictly AFTER cleanup and integrity checks
    console.log(JSON.stringify(reportOutput, null, 2));

    if (!cleanupOk || !integrityOk) {
      console.error('CRITICAL: Cleanup or original checkout integrity check failed. Exit code 3.');

      finalExitCode = 3;
    } else if (qualificationFailed || runError) {
      finalExitCode = 1;
    }
  }

  return finalExitCode;
}

main().then((code) => {
  process.exit(code);
}).catch(() => {
  console.error('Unexpected unhandled runner failure.');
  process.exit(1);
});
