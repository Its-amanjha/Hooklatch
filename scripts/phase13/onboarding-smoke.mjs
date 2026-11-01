#!/usr/bin/env node
/**
 * Phase 13 newcomer onboarding smoke (Codebuff DeepSeek owner).
 *
 * Proves ONE newcomer workflow against ONE explicit, already-built package
 * tarball. It never packs, builds or installs inside this checkout:
 *
 *   1. the explicit artifact is hashed before use; a missing, non-regular or
 *      non-gzip file is BLOCKED before any temporary directory exists;
 *   2. `tasks/phase-13/onboarding-examples.json` must equal the frozen literals
 *      in this module (4 ids, exact language + code), so a rewritten example is
 *      reported as a defect instead of being "fixed up";
 *   3. with `--guide`, every `<-- hooklatch:example:ID -->` marker must be
 *      followed by a fence whose language and code match exactly, for all four
 *      ids, with no duplicate or unknown markers; without `--guide`, guide
 *      documentation parity is reported `not-run` and is never claimed;
 *   4. a checked OS-temp consumer is created with an isolated npm cache and the
 *      artifact is installed through `node npm-cli.js install --offline
 *      --ignore-scripts --no-audit --no-fund` (no repository install, no shared
 *      cache writes, no scripts);
 *   5. the installed manifest, the absence of optional framework packages and
 *      the six public subpaths are inspected; `express`/`hono` are optional
 *      peers that must be absent, and if an optional-peer entry point fails it
 *      must fail with exactly the documented missing-peer module error;
 *   6. the frozen ESM `.mjs` and CommonJS `.cjs` examples are written byte for
 *      byte and executed; each must print exactly `verified` and exit 0;
 *   7. the two frozen CLI examples run through the host `npx-cli.js` with
 *      `--no-install` in a controlled offline environment, with the actual
 *      launcher/argv mapping recorded instead of a shell string; `--help` must
 *      expose usage and `--dry-run` must create no file anywhere in the
 *      consumer (full-tree snapshot that never follows links);
 *   8. negative controls must fail for the intended reason, never on an
 *      unrelated crash: an unresolvable package import and a wrong-MAC
 *      verification; unknown provider / invalid credential flag must exit 2
 *      with no write and no synthetic secret or payload in the output.
 *
 * Exit codes follow the phase contract:
 *   0  ready — every required check passed, cleanup confirmed, integrity kept
 *   1  failed — a real check, integrity or cleanup failure
 *   2  usage error (invalid, duplicate or missing option value)
 *   3  blocked — no explicit artifact, missing prerequisite, unknown guide file
 *
 * Limits: one host runtime only (the version is recorded; no other Node
 * version is qualified), no network, no npm authentication, no npm ci and no
 * live provider calls. A BLOCKED or failed run is never a passing onboarding
 * result, and a harness `--self-test` is never product evidence.
 */
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { UsageError, validateResultsDestination } from '../phase11/package-contract.mjs';
import {
  compareCheckout, createHealthLedger, disposeWorkspace, runChild, snapshotCheckout,
} from '../phase11/mixed-format-runtime.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
export const EXAMPLES_RELATIVE = 'tasks/phase-13/onboarding-examples.json';

const TEMP_PREFIX = 'hooklatch-phase13-onboarding-';
const OUTPUT_LIMIT = 256 * 1024;
const INSTALL_TIMEOUT_MS = 300_000;
const CHILD_TIMEOUT_MS = 120_000;

export const EXIT = Object.freeze({ READY: 0, FAILED: 1, USAGE: 2, BLOCKED: 3 });

export const SYNTHETIC_SECRET = 'hooklatch-synthetic-onboarding';
export const SYNTHETIC_BODY = 'hooklatch onboarding';

/**
 * Frozen literal examples. `tasks/phase-13/onboarding-examples.json` must match
 * these exactly; the runner never edits an example to make a guide pass.
 */
export const FROZEN_EXAMPLES = Object.freeze([
  Object.freeze({
    id: 'core-esm',
    language: 'js',
    code: 'import { createHmac } from \'node:crypto\';\n'
      + 'import { verify } from \'hooklatch\';\n'
      + '\n'
      + 'const rawBody = new TextEncoder().encode(\'hooklatch onboarding\');\n'
      + 'const secret = \'hooklatch-synthetic-onboarding\';\n'
      + 'const signature = createHmac(\'sha256\', secret).update(rawBody).digest(\'hex\');\n'
      + 'const result = await verify(\n'
      + '  { rawBody, headers: { \'x-hub-signature-256\': `sha256=${signature}` } },\n'
      + '  { provider: \'github\', secrets: [secret] },\n'
      + ');\n'
      + '\n'
      + 'if (!result.ok) throw new Error(\'Verification failed.\');\n'
      + 'console.log(\'verified\');',
  }),
  Object.freeze({
    id: 'core-commonjs',
    language: 'js',
    code: 'const { createHmac } = require(\'node:crypto\');\n'
      + 'const { verify } = require(\'hooklatch\');\n'
      + '\n'
      + 'async function main() {\n'
      + '  const rawBody = new TextEncoder().encode(\'hooklatch onboarding\');\n'
      + '  const secret = \'hooklatch-synthetic-onboarding\';\n'
      + '  const signature = createHmac(\'sha256\', secret).update(rawBody).digest(\'hex\');\n'
      + '  const result = await verify(\n'
      + '    { rawBody, headers: { \'x-hub-signature-256\': `sha256=${signature}` } },\n'
      + '    { provider: \'github\', secrets: [secret] },\n'
      + '  );\n'
      + '\n'
      + '  if (!result.ok) throw new Error(\'Verification failed.\');\n'
      + '  console.log(\'verified\');\n'
      + '}\n'
      + '\n'
      + 'main().catch(() => {\n'
      + '  console.error(\'Verification failed.\');\n'
      + '  process.exitCode = 1;\n'
      + '});',
  }),
  Object.freeze({
    id: 'cli-help',
    language: 'bash',
    code: 'npx --no-install hooklatch --help',
  }),
  Object.freeze({
    id: 'cli-dry-run',
    language: 'bash',
    code: 'npx --no-install hooklatch init webhook --provider github --framework express --dry-run',
  }),
]);

/** Public subpath inventory and the exports each one must expose. */
export const SUBPATH_EXPORTS = Object.freeze([
  Object.freeze({ spec: 'hooklatch', names: Object.freeze(['HooklatchError', 'createVerifier', 'verify', 'verifyRequest']) }),
  Object.freeze({ spec: 'hooklatch/diagnostics', names: Object.freeze(['diagnose']) }),
  Object.freeze({ spec: 'hooklatch/nextjs', names: Object.freeze(['createWebhookHandler']) }),
  Object.freeze({ spec: 'hooklatch/cloudflare', names: Object.freeze(['createWebhookHandler']) }),
  Object.freeze({ spec: 'hooklatch/express', names: Object.freeze(['createWebhookMiddleware']) }),
  Object.freeze({ spec: 'hooklatch/hono', names: Object.freeze(['createWebhookMiddleware']) }),
]);

const OPTIONAL_PEER_SUBPATHS = Object.freeze(['hooklatch/express', 'hooklatch/hono']);
const ALLOWED_NODE_MODULES_ENTRIES = Object.freeze(['.bin', '.package-lock.json', 'hooklatch']);

const PEER_PROBE_SOURCE = [
  'const specs = [',
  "  'hooklatch', 'hooklatch/diagnostics', 'hooklatch/nextjs',",
  "  'hooklatch/cloudflare', 'hooklatch/express', 'hooklatch/hono',",
  '];',
  'for (const spec of specs) {',
  '  try {',
  '    const loaded = await import(spec);',
  "    console.log(JSON.stringify({ spec, kind: 'loaded', names: Object.keys(loaded) }));",
  '  } catch (error) {',
  '    const firstLine = String(error && error.message ? error.message : error).split(/\\r?\\n/)[0];',
  "    console.log(JSON.stringify({ spec, kind: 'failed', code: error && error.code ? error.code : null, firstLine }));",
  '  }',
  '}',
].join('\n');

const MISSING_PACKAGE_SOURCE = [
  'try {',
  "  await import('hooklatch');",
  "  console.log(JSON.stringify({ kind: 'resolved' }));",
  '} catch (error) {',
  '  const firstLine = String(error && error.message ? error.message : error).split(/\\r?\\n/)[0];',
  "  console.log(JSON.stringify({ kind: 'failed', code: error && error.code ? error.code : null, firstLine }));",
  '}',
].join('\n');

const WRONG_MAC_SOURCE = [
  "import { createHmac } from 'node:crypto';",
  "import { verify } from 'hooklatch';",
  '',
  `const rawBody = new TextEncoder().encode('${SYNTHETIC_BODY}');`,
  `const secret = '${SYNTHETIC_SECRET}';`,
  "const wrongSignature = createHmac('sha256', 'hooklatch-control-key').update(rawBody).digest('hex');",
  'const result = await verify(',
  "  { rawBody, headers: { 'x-hub-signature-256': `sha256=${wrongSignature}` } },",
  "  { provider: 'github', secrets: [secret] },",
  ');',
  'console.log(JSON.stringify({ ok: result.ok, reason: result.ok ? null : result.reason }));',
].join('\n');

export const USAGE = [
  'Phase 13 newcomer onboarding smoke',
  '',
  'Usage:',
  '  node scripts/phase13/onboarding-smoke.mjs --tarball FILE [--guide FILE] [--results FILE]',
  '  node scripts/phase13/onboarding-smoke.mjs --self-test',
  '  node scripts/phase13/onboarding-smoke.mjs --help',
  '',
  'Required for a ready run:',
  '  --tarball FILE    Explicit built package tarball (never packed from this checkout).',
  '',
  'Options:',
  '  --guide FILE      Onboarding guide whose four example markers and fences must',
  '                    match tasks/phase-13/onboarding-examples.json exactly.',
  '  --results FILE    Write the JSON evidence report to a new file only.',
  '  --self-test       Run harness-only controls; no install, no temporary project.',
  '  --help, -h        Show this help.',
  '',
  'Guide marker convention (one per frozen example id, in any order):',
  '  <!-- hooklatch:example:ID -->',
  '  ```js',
  '  ...exact frozen code...',
  '  ```',
  '',
  'Exit codes:',
  '  0  Ready (also for --help and a passing --self-test)',
  '  1  Failed check, integrity or cleanup failure',
  '  2  Invalid usage',
  '  3  Blocked: no explicit --tarball, bad artifact, or a missing guide/prerequisite',
  '',
  'One host runtime only; the exact version is recorded. Without --guide, guide',
  'documentation parity is reported not-run and is never claimed.',
].join('\n');

/* ------------------------------------------------------------------ *
 * Boundary helpers
 * ------------------------------------------------------------------ */

function kindOf(value) {
  return Object.prototype.toString.call(value).slice(8, -1);
}

function isRecord(value) {
  return kindOf(value) === 'Object';
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(file) {
  return sha256(readFileSync(file));
}

function sameStrings(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }

  return true;
}

/* ------------------------------------------------------------------ *
 * Frozen examples and guide parity (pure)
 * ------------------------------------------------------------------ */

export function validateExamplesDocument(document, examples = FROZEN_EXAMPLES) {
  if (!isRecord(document)) return { ok: false, problems: ['examples-document-not-object'] };

  const listed = document.examples;

  if (!Array.isArray(listed)) return { ok: false, problems: ['examples-list-missing'] };

  const problems = [];

  if (listed.length !== examples.length) problems.push(`example-count:${listed.length}`);

  for (let index = 0; index < examples.length; index += 1) {
    const expected = examples[index];
    const observed = listed[index];

    if (!isRecord(observed)) {
      problems.push(`example-missing:${expected.id}`);
      continue;
    }

    if (observed.id !== expected.id) {
      problems.push(`example-id:${index}`);
      continue;
    }

    if (observed.language !== expected.language) problems.push(`example-language:${expected.id}`);

    if (observed.code !== expected.code) problems.push(`example-code:${expected.id}`);
  }

  return { ok: problems.length === 0, problems };
}

export function loadExamplesFile(repoRoot = REPO_ROOT) {
  const file = path.join(repoRoot, EXAMPLES_RELATIVE);

  if (!existsSync(file)) return { ok: false, problems: ['examples-file-missing'], file };

  const stat = lstatSync(file);

  if (stat.isSymbolicLink() || !stat.isFile()) return { ok: false, problems: ['examples-file-not-regular'], file };

  let document;

  try {
    document = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    return { ok: false, problems: [`examples-file-invalid-json:${messageOf(error)}`], file };
  }

  return { ...validateExamplesDocument(document), file };
}

const GUIDE_MARKER = /^\s*<!--\s*hooklatch:example:([A-Za-z0-9_-]+)\s*-->\s*$/;
const GUIDE_FENCE_OPEN = /^```([A-Za-z0-9+#-]+)\s*$/;
const GUIDE_FENCE_CLOSE = /^```\s*$/;

/**
 * A guide marker must be followed immediately by a fenced block whose language
 * and body match the frozen example exactly. Every frozen id must appear once.
 */
export function parseGuide(text, examples = FROZEN_EXAMPLES) {
  if (kindOf(text) !== 'String') return { ok: false, problems: ['guide-not-text'], matched: [] };

  const problems = [];
  const matched = [];
  const byId = new Map(examples.map((example) => [example.id, example]));
  const counts = new Map();
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const marker = GUIDE_MARKER.exec(lines[index]);

    if (marker === null) continue;

    const id = marker[1];
    const count = (counts.get(id) ?? 0) + 1;

    counts.set(id, count);

    if (count > 1) {
      problems.push(`guide-duplicate-id:${id}`);
      continue;
    }

    const expected = byId.get(id);

    if (expected === undefined) {
      problems.push(`guide-unknown-id:${id}`);
      continue;
    }

    const fenceLine = lines[index + 1];
    const fence = fenceLine === undefined ? null : GUIDE_FENCE_OPEN.exec(fenceLine);

    if (fence === null) {
      problems.push(`guide-fence-missing:${id}`);
      continue;
    }

    const body = [];
    let closed = false;

    for (let cursor = index + 2; cursor < lines.length; cursor += 1) {
      if (GUIDE_FENCE_CLOSE.test(lines[cursor])) {
        closed = true;
        index = cursor;
        break;
      }

      body.push(lines[cursor]);
    }

    if (!closed) {
      problems.push(`guide-fence-unterminated:${id}`);
      continue;
    }

    if (fence[1] !== expected.language) {
      problems.push(`guide-fence-language:${id}`);
      continue;
    }

    if (body.join('\n') !== expected.code) {
      problems.push(`guide-fence-code:${id}`);
      continue;
    }

    matched.push(id);
  }

  for (const example of examples) {
    if (!counts.has(example.id)) problems.push(`guide-missing-id:${example.id}`);
  }

  return { ok: problems.length === 0, problems, matched };
}

/** Render the frozen examples as the canonical guide blocks used by controls. */
export function renderGuide(examples = FROZEN_EXAMPLES) {
  return examples
    .map((example) => `<!-- hooklatch:example:${example.id} -->\n\`\`\`${example.language}\n${example.code}\n\`\`\``)
    .join('\n\n');
}

/* ------------------------------------------------------------------ *
 * Discriminating classifiers (pure)
 * ------------------------------------------------------------------ */

/**
 * Only a module-not-found error that names the peer package itself is the
 * documented missing-peer condition; anything else is an unexpected failure.
 */
/** Node's module-not-found message prefix; the captured name is what failed. */
const MISSING_MODULE_PREFIX = /^Cannot find (?:package|module) '([^']+)'/;

export function classifyPeerFailure(spec, code, message) {
  const peer = spec.startsWith('hooklatch/') ? spec.slice('hooklatch/'.length) : spec;
  const firstLine = String(message ?? '').split(/\r?\n/)[0].trim();

  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return 'unexpected-failure';

  const referenced = MISSING_MODULE_PREFIX.exec(firstLine);

  return referenced !== null && referenced[1] === peer ? 'missing-peer' : 'unexpected-failure';
}

export function classifyMissingPackage(code, message) {
  const firstLine = String(message ?? '').split(/\r?\n/)[0].trim();

  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return 'unexpected-failure';

  const referenced = MISSING_MODULE_PREFIX.exec(firstLine);

  return referenced !== null && referenced[1] === 'hooklatch' ? 'missing-package' : 'unexpected-failure';
}

/* ------------------------------------------------------------------ *
 * Consumer tree snapshots (links are recorded, never followed)
 * ------------------------------------------------------------------ */

export function snapshotTree(root) {
  const entries = new Map();

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      const relative = path.relative(root, target).split(path.sep).join('/');
      const stat = lstatSync(target);

      if (stat.isSymbolicLink()) {
        entries.set(relative, 'link');
        continue;
      }

      if (stat.isDirectory()) {
        entries.set(relative, 'dir');
        visit(target);
        continue;
      }

      entries.set(relative, stat.isFile() ? `file:${stat.size}:${sha256File(target)}` : 'other');
    }
  };

  if (existsSync(root)) {
    entries.set('.', 'dir');
    visit(root);
  }

  return entries;
}

export function compareTreeSnapshots(before, after) {
  const problems = [];

  for (const [relative, value] of after) {
    if (!before.has(relative)) problems.push(`tree-added:${relative}`);
    else if (before.get(relative) !== value) problems.push(`tree-changed:${relative}`);
  }

  for (const relative of before.keys()) {
    if (!after.has(relative)) problems.push(`tree-removed:${relative}`);
  }

  return problems;
}

/* ------------------------------------------------------------------ *
 * CLI example mapping (no shell, args preserved)
 * ------------------------------------------------------------------ */

export function parseCliExample(code) {
  const shell = kindOf(code) === 'String' ? code.trim() : '';

  if (shell.length === 0) return { ok: false, problem: 'cli-example-empty' };

  const tokens = shell.split(/\s+/);

  if (tokens[0] !== 'npx') return { ok: false, problem: 'cli-example-not-npx' };

  if (!tokens.includes('--no-install')) return { ok: false, problem: 'cli-example-missing-no-install' };

  return { ok: true, shell, argv: tokens.slice(1) };
}

/* ------------------------------------------------------------------ *
 * Installed artifact inspection (pure)
 * ------------------------------------------------------------------ */

export function validateInstalledManifest(manifest) {
  if (!isRecord(manifest)) return ['manifest-not-object'];

  const problems = [];

  if (manifest.name !== 'hooklatch') problems.push(`manifest-name:${String(manifest.name)}`);

  if (kindOf(manifest.version) !== 'String' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) {
    problems.push('manifest-version');
  }

  if (manifest.type !== 'module') problems.push('manifest-type');

  if (!isRecord(manifest.engines) || manifest.engines.node !== '>=22') problems.push('manifest-engines');

  for (const field of ['dependencies', 'optionalDependencies']) {
    const declared = manifest[field];

    if (declared !== undefined && (!isRecord(declared) || Object.keys(declared).length > 0)) {
      problems.push(`manifest-${field}`);
    }
  }

  const exportsField = manifest.exports;

  const expectedExports = ['.', './cloudflare', './diagnostics', './express', './hono', './nextjs'];

  if (!isRecord(exportsField)) {
    problems.push('manifest-exports');
  } else if (!sameStrings(Object.keys(exportsField).sort(), expectedExports)) {
    problems.push('manifest-exports-keys');
  }

  if (!isRecord(manifest.bin) || manifest.bin.hooklatch !== './dist/cli/index.js') problems.push('manifest-bin');

  const peers = isRecord(manifest.peerDependencies) ? manifest.peerDependencies : {};
  const meta = isRecord(manifest.peerDependenciesMeta) ? manifest.peerDependenciesMeta : {};

  for (const peer of ['express', 'hono']) {
    if (!(peer in peers)) problems.push(`manifest-peer-declared:${peer}`);

    if (!isRecord(meta[peer]) || meta[peer].optional !== true) problems.push(`manifest-peer-optional:${peer}`);
  }

  return problems;
}

export function unexpectedInstalledEntries(entries) {
  const allowed = new Set(ALLOWED_NODE_MODULES_ENTRIES);

  return entries.filter((entry) => !allowed.has(entry));
}

/* ------------------------------------------------------------------ *
 * Environment and location helpers
 * ------------------------------------------------------------------ */

const BASE_ENV_KEYS = Object.freeze([
  'PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'SystemDrive', 'WINDIR', 'ComSpec', 'COMSPEC',
  'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'LANG', 'LC_ALL',
]);

const NPM_OFFLINE_ENV = Object.freeze({
  npm_config_offline: 'true',
  npm_config_audit: 'false',
  npm_config_fund: 'false',
  npm_config_update_notifier: 'false',
  npm_config_yes: 'false',
  npm_config_progress: 'false',
});

function baseEnv(overrides = {}) {
  const env = {};

  for (const key of BASE_ENV_KEYS) {
    const value = process.env[key];

    if (value !== undefined) env[key] = value;
  }

  env.NO_COLOR = '1';

  return { ...env, ...overrides };
}

function offlineEnv(workspace) {
  const binDirectory = path.join(workspace.consumer, 'node_modules', '.bin');
  const base = baseEnv(NPM_OFFLINE_ENV);
  const pathKey = process.platform === 'win32' ? 'Path' : 'PATH';
  const existing = base[pathKey] ?? '';

  return { ...base, [pathKey]: `${binDirectory}${path.delimiter}${existing}`, npm_config_cache: workspace.cache };
}

function snippetEnv() {
  return baseEnv();
}

export function locateNpmCli() {
  const candidates = [
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    'C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js',
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  return null;
}

export function locateNpxCli(npmCli = locateNpmCli()) {
  if (npmCli === null) return null;

  const npxCli = path.join(path.dirname(npmCli), 'npx-cli.js');

  return existsSync(npxCli) ? npxCli : null;
}

export function isInsideOsTemp(target) {
  const relative = path.relative(path.resolve(os.tmpdir()), path.resolve(target));

  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

/* ------------------------------------------------------------------ *
 * Verdict
 * ------------------------------------------------------------------ */

export function resolveOnboardingExit(report) {
  if (!isRecord(report)) return EXIT.FAILED;

  if (report.status === 'blocked') return EXIT.BLOCKED;

  const checks = Array.isArray(report.checks) ? report.checks : [];

  const failed = checks.some((check) => check.required !== false
    && (check.status === 'failed' || check.status === 'not-run'));

  const cleanupConfirmed = isRecord(report.cleanup) && report.cleanup.confirmed === true;

  const integrityKept = isRecord(report.integrity)
    && report.integrity.artifactUnchanged === true
    && report.integrity.checkoutUnchanged === true;

  return failed || !cleanupConfirmed || !integrityKept ? EXIT.FAILED : EXIT.READY;
}

/* ------------------------------------------------------------------ *
 * Argument parsing
 * ------------------------------------------------------------------ */

export function parseArguments(argv) {
  const options = { tarball: null, guide: null, results: null, help: false, selfTest: false };
  const seen = new Set();

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }

    if (argument === '--self-test') {
      options.selfTest = true;
      continue;
    }

    const fields = { '--tarball': 'tarball', '--guide': 'guide', '--results': 'results' };
    const field = Object.hasOwn(fields, argument) ? fields[argument] : null;

    if (field === null) throw new UsageError(`unknown argument: ${argument}`);

    if (seen.has(argument)) throw new UsageError(`duplicate option: ${argument}`);

    seen.add(argument);

    const value = argv[index + 1];

    if (value === undefined || value.startsWith('--')) throw new UsageError(`${argument} requires a value`);

    options[field] = value;
    index += 1;
  }

  return options;
}

/* ------------------------------------------------------------------ *
 * Check recording
 * ------------------------------------------------------------------ */

function recordCheck(checks, id, status, detail, required = true) {
  checks.push({ id, status, detail, required });

  return status;
}

function summarizeChild(evidence) {
  return {
    exitCode: evidence.exitCode,
    signal: evidence.signal,
    timedOut: evidence.timedOut,
    outputLimitExceeded: evidence.outputLimitExceeded,
    spawnError: evidence.spawnError,
    closeConfirmed: evidence.closeConfirmed,
    stdoutBytes: evidence.stdout.length,
    stderrBytes: evidence.stderr.length,
    durationMs: evidence.durationMs,
  };
}

/* ------------------------------------------------------------------ *
 * Main workflow
 * ------------------------------------------------------------------ */

async function inspectArtifact(tarballPath) {
  if (tarballPath === null || tarballPath === undefined) return { ok: false, blocked: true, problem: 'missing-explicit-tarball' };

  if (!existsSync(tarballPath)) return { ok: false, blocked: true, problem: 'tarball-missing' };

  const stat = lstatSync(tarballPath);

  if (stat.isSymbolicLink() || !stat.isFile()) return { ok: false, blocked: true, problem: 'tarball-not-regular-file' };

  const bytes = readFileSync(tarballPath);

  if (bytes.byteLength < 2 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) {
    return { ok: false, blocked: true, problem: 'tarball-not-gzip', bytes: bytes.byteLength };
  }

  return {
    ok: true, blocked: false, bytes: bytes.byteLength, sha256: sha256(bytes), fileName: path.basename(tarballPath), path: tarballPath,
  };
}

async function runOnboarding(settings) {
  const checks = [];
  const notRun = [];
  const startedAt = Date.now();
  const ledger = createHealthLedger();

  const report = {
    schemaVersion: 1,
    phase: '13 newcomer onboarding smoke',
    owner: 'deepseek-codebuff',
    script: 'scripts/phase13/onboarding-smoke.mjs',
    status: 'failed',
    exit: EXIT.FAILED,
    hostRuntime: { version: process.version, platform: process.platform, arch: process.arch },
    artifact: null,
    examples: { source: EXAMPLES_RELATIVE, ids: FROZEN_EXAMPLES.map((example) => example.id), documentationParity: 'not-run' },
    installed: null,
    optionalPeerImports: [],
    cliExecutions: [],
    checks,
    notRun,
    limits: [
      'One host runtime only; the recorded version is the only version exercised here.',
      'Offline install from the explicit artifact only; this is not evidence for `npm ci`, a registry install or an online first-run.',
      'Optionally-typed framework peers are inspected at import time; no real Express/Hono request is served.',
      'This is a newcomer workflow check, not a 21-provider crypto matrix, sandbox delivery or release authorization.',
      'Temporary consumer paths are reported redacted; exact paths stay in local ignored logs.',
    ],
    cleanup: { createdInsideOsTemp: false, removed: false, confirmed: true, childClosure: 'not-created' },
    integrity: { artifactUnchanged: true, checkoutUnchanged: true },
    elapsedMs: 0,
  };

  const finish = (status, exit) => {
    report.status = status;
    report.exit = exit;
    report.elapsedMs = Date.now() - startedAt;

    return { report, exit };
  };

  // Frozen inputs are checked before any artifact or temporary directory.
  const examples = loadExamplesFile();

  recordCheck(checks, 'examples-frozen-match', examples.ok ? 'passed' : 'failed', examples.ok
    ? 'tasks/phase-13/onboarding-examples.json matches the four frozen literals'
    : examples.problems.join(','));

  if (!examples.ok) return finish('failed', EXIT.FAILED);

  if (settings.guide !== null) {
    const guidePath = path.resolve(settings.guide);

    if (!existsSync(guidePath)) {
      recordCheck(checks, 'guide-present', 'failed', 'guide file is missing', false);

      return finish('blocked', EXIT.BLOCKED);
    }

    const parsed = parseGuide(readFileSync(guidePath, 'utf8'));

    report.examples.documentationParity = parsed.ok ? 'checked' : 'failed';

    if (!parsed.ok) {
      recordCheck(checks, 'guide-parity', 'failed', parsed.problems.join(','));

      return finish('failed', EXIT.FAILED);
    }

    recordCheck(checks, 'guide-parity', 'passed', `all four frozen example fences matched (${parsed.matched.join(',')})`);
  } else {
    recordCheck(checks, 'guide-parity', 'not-run', 'no --guide supplied; documentation parity was never evaluated', false);
    notRun.push({ id: 'guide-documentation-parity', reason: 'No --guide supplied; the newcomer guide is owned by another partner and was not present in this checkout.' });
  }

  const artifact = await inspectArtifact(settings.tarball === null ? null : path.resolve(settings.tarball));

  if (!artifact.ok) {
    recordCheck(checks, 'artifact-explicit', 'failed', artifact.problem);

    return finish('blocked', EXIT.BLOCKED);
  }

  report.artifact = { fileName: artifact.fileName, bytes: artifact.bytes, sha256: artifact.sha256 };
  recordCheck(checks, 'artifact-explicit', 'passed', `${artifact.fileName} ${artifact.sha256}`);

  const major = Number(process.versions.node.split('.')[0]);

  if (!Number.isInteger(major) || major < 22) {
    recordCheck(checks, 'host-runtime-at-least-22', 'failed', `host runtime ${process.version} is below the >=22 engine floor`);

    return finish('blocked', EXIT.BLOCKED);
  }

  recordCheck(checks, 'host-runtime-at-least-22', 'passed', `host runtime ${process.version}`);

  const npmCli = locateNpmCli();
  const npxCli = locateNpxCli(npmCli);

  if (npmCli === null || npxCli === null) {
    recordCheck(checks, 'npm-toolchain-present', 'failed', 'npm-cli.js/npx-cli.js not found next to the host Node executable');

    return finish('blocked', EXIT.BLOCKED);
  }

  recordCheck(checks, 'npm-toolchain-present', 'passed', 'host npm-cli.js and npx-cli.js located');

  let checkoutBefore;

  try {
    checkoutBefore = snapshotCheckout();
  } catch (error) {
    recordCheck(checks, 'checkout-snapshot', 'failed', messageOf(error));

    return finish('failed', EXIT.FAILED);
  }

  const workspace = createWorkspace();

  report.cleanup.createdInsideOsTemp = true;
  report.cleanup.confirmed = false;

  let cleanupError = null;

  try {
    await runConsumerWorkflow({ workspace, artifact, npxCli, ledger, checks, report, notRun });
  } catch (error) {
    recordCheck(checks, 'workflow', 'failed', messageOf(error));
  } finally {
    try {
      disposeWorkspace(workspace, { ledger });
      report.cleanup.removed = !existsSync(workspace.root);
      report.cleanup.confirmed = report.cleanup.removed;
      report.cleanup.childClosure = ledger.uncertain ? 'uncertain' : 'confirmed';
    } catch (error) {
      cleanupError = error;
      report.cleanup.removed = false;
      report.cleanup.confirmed = false;
      report.cleanup.childClosure = ledger.uncertain ? 'uncertain' : 'confirmed';
    }
  }

  if (cleanupError !== null) {
    recordCheck(checks, 'cleanup-confirmed', 'failed', messageOf(cleanupError));

    return finish('failed', EXIT.FAILED);
  }

  recordCheck(checks, 'cleanup-confirmed', 'passed', 'OS-temp consumer removed and child closure confirmed');

  let artifactAfter = null;

  try {
    artifactAfter = sha256File(artifact.path);
  } catch (error) {
    recordCheck(checks, 'artifact-unmodified', 'failed', messageOf(error));
  }

  report.integrity.artifactUnchanged = artifactAfter === artifact.sha256;

  if (artifactAfter !== null && !report.integrity.artifactUnchanged) {
    recordCheck(checks, 'artifact-unmodified', 'failed', 'input artifact bytes changed during the run');
  } else if (artifactAfter !== null) {
    recordCheck(checks, 'artifact-unmodified', 'passed', 'input artifact unchanged before and after');
  }

  try {
    const diffs = compareCheckout(checkoutBefore, snapshotCheckout());

    report.integrity.checkoutUnchanged = diffs.length === 0;

    recordCheck(checks, 'checkout-unmodified', diffs.length === 0 ? 'passed' : 'failed',
      diffs.length === 0 ? 'tracked checkout bytes unchanged' : diffs.join('; '));
  } catch (error) {
    report.integrity.checkoutUnchanged = false;
    recordCheck(checks, 'checkout-unmodified', 'failed', messageOf(error));
  }

  const resolved = resolveOnboardingExit(report);

  return finish(resolved === EXIT.READY ? 'ready' : 'failed', resolved);
}

function createWorkspace() {
  const root = mkdtempSync(path.join(os.tmpdir(), TEMP_PREFIX));

  if (!isInsideOsTemp(root)) throw new Error('temporary workspace is outside the OS temp directory');

  const consumer = path.join(root, 'consumer');
  const cache = path.join(root, 'npm-cache');
  const snippets = path.join(root, 'snippets');
  const isolated = path.join(root, 'no-package');

  for (const directory of [consumer, cache, snippets, isolated]) mkdirSync(directory, { recursive: true });

  writeFileSync(
    path.join(consumer, 'package.json'),
    `${JSON.stringify({ name: 'hooklatch-onboarding-consumer', version: '0.0.0', private: true, type: 'module' }, null, 2)}\n`,
    'utf8',
  );

  return { root, consumer, cache, snippets, isolated, links: [] };
}

async function runConsumerWorkflow(context) {
  const { workspace, artifact, npxCli, ledger, checks, report, notRun } = context;

  // 1. Offline install of the explicit artifact only.
  const npmArgs = [
    'install', artifact.path, '--no-save', '--ignore-scripts', '--offline',
    '--no-audit', '--no-fund', '--cache', workspace.cache,
  ];

  const install = await runChild(process.execPath, [locateNpmCli(), ...npmArgs], {
    cwd: workspace.consumer, env: offlineEnv(workspace), ledger, timeoutMs: INSTALL_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });

  const installedRoot = path.join(workspace.consumer, 'node_modules', 'hooklatch');
  const installedManifestPath = path.join(installedRoot, 'package.json');

  if (!install.ok || !existsSync(installedManifestPath)) {
    recordCheck(checks, 'offline-install', 'failed', `offline install failed (${JSON.stringify(summarizeChild(install))})`);

    return;
  }

  recordCheck(checks, 'offline-install', 'passed', 'explicit artifact installed offline with an isolated cache');

  let manifest;

  try {
    manifest = JSON.parse(readFileSync(installedManifestPath, 'utf8'));
  } catch (error) {
    recordCheck(checks, 'installed-manifest', 'failed', `installed package.json is unreadable: ${messageOf(error)}`);

    return;
  }

  const manifestFindings = validateInstalledManifest(manifest);
  const installedEntries = readdirSync(path.join(workspace.consumer, 'node_modules')).sort();
  const unexpected = unexpectedInstalledEntries(installedEntries);

  report.installed = {
    version: kindOf(manifest.version) === 'String' ? manifest.version : null,
    nodeModulesEntries: installedEntries,
    optionalPeersInstalled: installedEntries.filter((entry) => entry === 'express' || entry === 'hono'),
  };

  recordCheck(checks, 'installed-manifest', manifestFindings.length === 0 ? 'passed' : 'failed',
    manifestFindings.length === 0
      ? `installed manifest: hooklatch ${report.installed.version}, type module, engines >=22, six entries, no runtime dependencies`
      : manifestFindings.join(','));

  recordCheck(checks, 'no-optional-peer-auto-install', unexpected.length === 0
    ? 'passed'
    : 'failed',
  unexpected.length === 0
    ? 'node_modules holds only hooklatch (express/hono absent; optional peers not auto-installed)'
    : `unexpected node_modules entries: ${unexpected.join(',')}`);

  // 2. Public subpaths and optional peers.
  writeFileSync(path.join(workspace.consumer, 'peer-probe.mjs'), PEER_PROBE_SOURCE, 'utf8');

  const peerRun = await runChild(process.execPath, ['peer-probe.mjs'], {
    cwd: workspace.consumer, env: snippetEnv(), ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });

  if (!peerRun.ok) {
    recordCheck(checks, 'installed-subpaths', 'failed', `peer probe failed (${JSON.stringify(summarizeChild(peerRun))})`);

    return;
  }

  const probes = peerRun.stdout.split(/\r?\n/).filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));

  const probeFindings = [];
  const peerFailures = [];

  for (const entry of SUBPATH_EXPORTS) {
    const probe = probes.find((item) => item.spec === entry.spec);

    if (probe === undefined) {
      probeFindings.push(`probe-missing:${entry.spec}`);
      continue;
    }

    if (probe.kind === 'loaded') {
      if (!sameStrings([...probe.names].sort(), [...entry.names].sort())) {
        probeFindings.push(`probe-exports:${entry.spec}`);
      }

      continue;
    }

    const classification = classifyPeerFailure(entry.spec, probe.code, probe.firstLine);

    if (OPTIONAL_PEER_SUBPATHS.includes(entry.spec) && classification === 'missing-peer') {
      report.optionalPeerImports.push({ spec: entry.spec, kind: 'missing-peer', accepted: true });
      continue;
    }

    peerFailures.push(`probe-failed:${entry.spec}:${probe.code ?? 'no-code'}:${probe.firstLine ?? ''}`);
  }

  for (const probe of probes) {
    if (probe.kind === 'loaded' && OPTIONAL_PEER_SUBPATHS.includes(probe.spec)) {
      report.optionalPeerImports.push({ spec: probe.spec, kind: 'loaded', accepted: true });
    }
  }

  recordCheck(checks, 'installed-subpaths', probeFindings.length === 0 ? 'passed' : 'failed',
    probeFindings.length === 0 ? 'six public subpaths resolve from the installed package' : probeFindings.join(','));

  recordCheck(checks, 'optional-peer-imports', peerFailures.length === 0 ? 'passed' : 'failed',
    peerFailures.length === 0
      ? 'optional-peer entries load or fail only with the documented missing-peer module error'
      : peerFailures.join(','));

  // 3. Frozen ESM and CommonJS examples, written byte for byte.
  const snippetResults = [];

  for (const example of FROZEN_EXAMPLES.filter((item) => item.id === 'core-esm' || item.id === 'core-commonjs')) {
    const fileName = example.id === 'core-esm' ? 'onboarding-core-esm.mjs' : 'onboarding-core-commonjs.cjs';
    const target = path.join(workspace.consumer, fileName);

    writeFileSync(target, example.code, 'utf8');

    const literal = sha256File(target) === sha256(Buffer.from(example.code, 'utf8'));

    const run = await runChild(process.execPath, [fileName], {
      cwd: workspace.consumer, env: snippetEnv(), ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
    });

    const verified = literal && run.ok && run.stdout.trim() === 'verified';

    snippetResults.push({ id: example.id, literal, exitCode: run.exitCode, stdout: run.stdout.trim().slice(0, 40) });

    recordCheck(checks, `example-${example.id}`, verified ? 'passed' : 'failed',
      verified ? 'literal frozen bytes printed exactly "verified" and exited 0'
        : `literal=${String(literal)} ${JSON.stringify(summarizeChild(run))}`);
  }

  report.examples.executed = snippetResults;

  // 4. CLI examples through the host npx launcher, no shell.
  const treeBeforeCli = snapshotTree(workspace.consumer);
  const helpExample = FROZEN_EXAMPLES.find((example) => example.id === 'cli-help');
  const dryRunExample = FROZEN_EXAMPLES.find((example) => example.id === 'cli-dry-run');

  const helpMapping = parseCliExample(helpExample.code);

  const helpRun = helpMapping.ok
    ? await runCli(npxCli, helpMapping.argv, workspace, ledger)
    : null;

  report.cliExecutions.push(helpMapping.ok ? cliEvidence('cli-help', helpMapping, npxCli, helpRun) : { id: 'cli-help', mapping: 'invalid' });

  const helpPassed = helpMapping.ok && helpRun !== null && helpRun.ok
    && helpRun.stdout.includes('Usage: hooklatch init webhook');

  recordCheck(checks, 'cli-help', helpPassed ? 'passed' : 'failed',
    helpPassed ? 'installed CLI printed usage and exited 0' : `cli help did not expose usage (${helpMapping.ok ? JSON.stringify(summarizeChild(helpRun)) : helpMapping.problem})`);

  const dryMapping = parseCliExample(dryRunExample.code);

  const dryRun = dryMapping.ok
    ? await runCli(npxCli, dryMapping.argv, workspace, ledger)
    : null;

  report.cliExecutions.push(dryMapping.ok ? cliEvidence('cli-dry-run', dryMapping, npxCli, dryRun) : { id: 'cli-dry-run', mapping: 'invalid' });

  const dryRunPassed = dryMapping.ok && dryRun !== null && dryRun.ok
    && dryRun.stdout.split(/\r?\n/)[0].trim() === 'hooklatch/github.express.ts'
    && dryRun.stdout.includes("from 'hooklatch/express'");

  recordCheck(checks, 'cli-dry-run', dryRunPassed ? 'passed' : 'failed',
    dryRunPassed ? 'installed CLI dry run printed the target path and template and exited 0'
      : `cli dry run did not produce the expected preview (${dryMapping.ok ? JSON.stringify(summarizeChild(dryRun)) : dryMapping.problem})`);

  const cliWrites = compareTreeSnapshots(treeBeforeCli, snapshotTree(workspace.consumer));

  recordCheck(checks, 'cli-no-writes', cliWrites.length === 0 ? 'passed' : 'failed',
    cliWrites.length === 0 ? 'help and dry run created no file anywhere in the consumer tree' : cliWrites.join(','));

  // 5. Negative controls that must fail for the intended reason.
  writeFileSync(path.join(workspace.isolated, 'missing-package.mjs'), MISSING_PACKAGE_SOURCE, 'utf8');

  const missingRun = await runChild(process.execPath, ['missing-package.mjs'], {
    cwd: workspace.isolated, env: snippetEnv(), ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });

  const missingReport = parseLastJson(missingRun.stdout);

  const missingClassification = missingReport === null
    ? 'unexpected-failure'
    : classifyMissingPackage(missingReport.code, missingReport.firstLine);

  recordCheck(checks, 'negative-missing-package', missingClassification === 'missing-package' ? 'passed' : 'failed',
    missingClassification === 'missing-package'
      ? 'an unresolvable package import failed as module-not-found for hooklatch'
      : `expected module-not-found for hooklatch, observed ${JSON.stringify(summarizeChild(missingRun))}`);

  writeFileSync(path.join(workspace.consumer, 'wrong-mac.mjs'), WRONG_MAC_SOURCE, 'utf8');

  const wrongMacRun = await runChild(process.execPath, ['wrong-mac.mjs'], {
    cwd: workspace.consumer, env: snippetEnv(), ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });

  const wrongMacReport = parseLastJson(wrongMacRun.stdout);

  recordCheck(checks, 'negative-wrong-mac',
    wrongMacRun.ok && wrongMacReport !== null && wrongMacReport.ok === false && wrongMacReport.reason === 'invalid-signature'
      ? 'passed'
      : 'failed',
    wrongMacRun.ok && wrongMacReport !== null && wrongMacReport.ok === false && wrongMacReport.reason === 'invalid-signature'
      ? 'a wrong-MAC verification returned ok:false with reason invalid-signature (no crash)'
      : `wrong-MAC control did not fail for the intended reason (${JSON.stringify(summarizeChild(wrongMacRun))})`);

  // 6. CLI argument negatives: exit 2, no write, no synthetic material echoed.
  const unknownProvider = await runArgumentNegative(npxCli, workspace, ledger,
    ['--no-install', 'hooklatch', 'init', 'webhook', '--provider', 'not-a-provider', '--framework', 'express'],
    'Unsupported provider.');

  recordCheck(checks, 'cli-unknown-provider', unknownProvider.passed ? 'passed' : 'failed', unknownProvider.detail);

  const invalidCredential = await runArgumentNegative(npxCli, workspace, ledger,
    ['--no-install', 'hooklatch', 'init', 'webhook', '--provider', 'github', '--framework', 'express', '--secret-env', '9invalid-name'],
    'Invalid --secret-env');

  recordCheck(checks, 'cli-invalid-credential-flag', invalidCredential.passed ? 'passed' : 'failed', invalidCredential.detail);

  const leaked = [helpRun, dryRun, unknownProvider.run, invalidCredential.run]
    .filter((run) => run !== null && run !== undefined)
    .some((run) => `${run.stdout}${run.stderr}`.includes(SYNTHETIC_SECRET) || `${run.stdout}${run.stderr}`.includes(SYNTHETIC_BODY));

  recordCheck(checks, 'no-synthetic-material-in-output', leaked ? 'failed' : 'passed',
    leaked ? 'CLI output contained the synthetic secret or payload' : 'CLI output never echoed the synthetic secret or payload');

  notRun.push({ id: 'npm-ci-online-install', reason: 'An offline tarball consumer is not evidence for `npm ci` or a registry install.' });
  notRun.push({ id: 'other-node-versions', reason: `Only ${process.version} was executed; no other Node version is qualified by this run.` });
  notRun.push({ id: 'live-framework-requests', reason: 'No real Express/Hono/Next/Workers request was served.' });
}

async function runCli(npxCli, argv, workspace, ledger) {
  return await runChild(process.execPath, [npxCli, ...argv], {
    cwd: workspace.consumer, env: offlineEnv(workspace), ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });
}

function cliEvidence(id, mapping, npxCli, run) {
  return {
    id,
    shell: mapping.shell,
    launcher: 'node',
    npxCli: path.basename(npxCli),
    args: mapping.argv,
    shellInterpolation: false,
    evidence: run === null ? null : summarizeChild(run),
  };
}

function parseLastJson(stdout) {
  const lines = stdout.split(/\r?\n/).filter((line) => line.trim().length > 0);

  if (lines.length === 0) return null;

  try {
    const parsed = JSON.parse(lines[lines.length - 1]);

    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function runArgumentNegative(npxCli, workspace, ledger, argv, expectedStderr) {
  const before = snapshotTree(workspace.consumer);
  const run = await runCli(npxCli, argv, workspace, ledger);
  const writes = compareTreeSnapshots(before, snapshotTree(workspace.consumer));
  const stderrMatched = run.stderr.includes(expectedStderr);

  const leaked = `${run.stdout}${run.stderr}`.includes(SYNTHETIC_SECRET)
    || `${run.stdout}${run.stderr}`.includes(SYNTHETIC_BODY);

  const passed = !run.timedOut && run.exitCode === EXIT.USAGE && run.signal === null && run.closeConfirmed
    && stderrMatched && writes.length === 0 && !leaked;

  return {
    passed,
    run,
    detail: passed
      ? `exited 2 with "${expectedStderr}", wrote no file and printed no synthetic material`
      : `expected exit 2 + "${expectedStderr}" + no writes; observed ${JSON.stringify(summarizeChild(run))} writes=${writes.join(',') || 'none'} stderrMatched=${String(stderrMatched)}`,
  };
}

/* ------------------------------------------------------------------ *
 * Redacted summary
 * ------------------------------------------------------------------ */

export function summarizeReport(report) {
  const checks = Array.isArray(report.checks) ? report.checks : [];

  return {
    schemaVersion: report.schemaVersion,
    phase: report.phase,
    script: report.script,
    status: report.status,
    exit: report.exit,
    hostRuntime: report.hostRuntime,
    artifact: report.artifact,
    examples: report.examples,
    installed: report.installed,
    optionalPeerImports: report.optionalPeerImports,
    checks: checks.map((check) => ({ id: check.id, status: check.status, required: check.required !== false, detail: check.detail })),
    notRun: report.notRun,
    cleanup: report.cleanup,
    integrity: report.integrity,
    limits: report.limits,
    elapsedMs: report.elapsedMs,
  };
}

/* ------------------------------------------------------------------ *
 * Harness-only self-test (pure controls; no install, no temp project)
 * ------------------------------------------------------------------ */

export function runSelfTest() {
  const controls = [];

  const record = (id, run) => {
    try {
      const detail = run();

      controls.push({ id, passed: detail.passed === true, detail: detail.detail });
    } catch (error) {
      controls.push({ id, passed: false, detail: messageOf(error) });
    }
  };

  record('frozen-examples-file-matches', () => {
    const loaded = loadExamplesFile();

    return { passed: loaded.ok, detail: loaded.problems };
  });

  record('good-guide-parity', () => {
    const parsed = parseGuide(renderGuide());

    return { passed: parsed.ok && parsed.matched.length === 4, detail: parsed.problems };
  });

  record('guide-defects-detected', () => {
    const guide = renderGuide();
    const missing = parseGuide(guide.replace('<!-- hooklatch:example:cli-help -->', '<!-- removed -->'));
    const duplicated = parseGuide(`${guide}\n\n${renderGuide([FROZEN_EXAMPLES[0]])}`);
    const wrongLanguage = parseGuide(guide.replace('```js\nimport { createHmac }', '```ts\nimport { createHmac }'));
    const wrongCode = parseGuide(guide.replace("console.log('verified');", "console.log('ok');"));
    const unknownId = parseGuide(`${guide}\n\n<!-- hooklatch:example:extra -->\n\`\`\`js\nx\n\`\`\``);

    const found = [
      missing.problems.some((problem) => problem.startsWith('guide-missing-id:')),
      duplicated.problems.some((problem) => problem.startsWith('guide-duplicate-id:')),
      wrongLanguage.problems.some((problem) => problem.startsWith('guide-fence-language:')),
      wrongCode.problems.some((problem) => problem.startsWith('guide-fence-code:')),
      unknownId.problems.some((problem) => problem.startsWith('guide-unknown-id:')),
    ];

    return { passed: found.every((value) => value === true), detail: { found } };
  });

  record('altered-example-rejected', () => {
    const document = {
      examples: FROZEN_EXAMPLES.map((example) => ({ id: example.id, language: example.language, code: example.code })),
    };

    const pristine = validateExamplesDocument(document);
    const altered = structuredClone(document);

    altered.examples[0].code = `${altered.examples[0].code}\nconsole.log('extra');`;

    const alteredEsm = validateExamplesDocument(altered);
    const alteredCjs = structuredClone(document);

    alteredCjs.examples[1].code = alteredCjs.examples[1].code.replace("console.log('verified');", "console.log('ok');");

    const cjs = validateExamplesDocument(alteredCjs);

    return {
      passed: pristine.ok
        && alteredEsm.problems.includes('example-code:core-esm')
        && cjs.problems.includes('example-code:core-commonjs'),
      detail: { pristine: pristine.problems, alteredEsm: alteredEsm.problems, alteredCjs: cjs.problems },
    };
  });

  record('peer-classification-discriminating', () => {
    const missingPeer = classifyPeerFailure('hooklatch/express', 'ERR_MODULE_NOT_FOUND', "Cannot find package 'express' imported from x");
    const wrongPeer = classifyPeerFailure('hooklatch/hono', 'ERR_MODULE_NOT_FOUND', "Cannot find package 'express' imported from x");
    const otherCrash = classifyPeerFailure('hooklatch/express', 'TypeError', 'createWebhookMiddleware is not a function');
    const noCode = classifyPeerFailure('hooklatch/express', null, "Cannot find package 'express'");

    return {
      passed: missingPeer === 'missing-peer' && wrongPeer === 'unexpected-failure'
        && otherCrash === 'unexpected-failure' && noCode === 'unexpected-failure',
      detail: { missingPeer, wrongPeer, otherCrash, noCode },
    };
  });

  record('missing-package-classification', () => {
    return {
      passed: classifyMissingPackage('ERR_MODULE_NOT_FOUND', "Cannot find package 'hooklatch' imported from x") === 'missing-package'
        && classifyMissingPackage('ERR_MODULE_NOT_FOUND', "Cannot find package 'other'") === 'unexpected-failure'
        && classifyMissingPackage('TypeError', "Cannot find package 'hooklatch'") === 'unexpected-failure',
      detail: 'module-not-found for hooklatch only',
    };
  });

  record('tree-diff-detects-writes', () => {
    const before = new Map([['.', 'dir'], ['package.json', 'file:2:aa'], ['node_modules', 'dir']]);
    const after = new Map([['.', 'dir'], ['package.json', 'file:2:bb'], ['node_modules', 'dir'], ['hooklatch/github.express.ts', 'file:9:cc']]);
    const problems = compareTreeSnapshots(before, after);

    return {
      passed: problems.includes('tree-changed:package.json') && problems.includes('tree-added:hooklatch/github.express.ts'),
      detail: problems,
    };
  });

  record('verdict-requires-cleanup-and-integrity', () => {
    const passing = {
      status: 'ready',
      checks: [{ id: 'a', status: 'passed' }, { id: 'b', status: 'not-run', required: false }],
      cleanup: { confirmed: true },
      integrity: { artifactUnchanged: true, checkoutUnchanged: true },
    };

    return {
      passed: resolveOnboardingExit(passing) === EXIT.READY
        && resolveOnboardingExit({ ...passing, cleanup: { confirmed: false } }) === EXIT.FAILED
        && resolveOnboardingExit({ ...passing, integrity: { artifactUnchanged: false, checkoutUnchanged: true } }) === EXIT.FAILED
        && resolveOnboardingExit({ ...passing, checks: [{ id: 'a', status: 'not-run' }] }) === EXIT.FAILED
        && resolveOnboardingExit({ ...passing, status: 'blocked' }) === EXIT.BLOCKED,
      detail: 'cleanup, integrity, required checks and blocked mapping',
    };
  });

  record('cli-example-mapping', () => {
    const help = parseCliExample(FROZEN_EXAMPLES[2].code);
    const noNpx = parseCliExample('npm exec hooklatch --help');
    const withoutNoInstall = parseCliExample('npx hooklatch --help');

    return {
      passed: help.ok && sameStrings(help.argv, ['--no-install', 'hooklatch', '--help'])
        && noNpx.ok === false && withoutNoInstall.ok === false,
      detail: { help: help.argv, noNpx: noNpx.problem, withoutNoInstall: withoutNoInstall.problem },
    };
  });

  const passed = controls.every((control) => control.passed === true);

  return {
    status: passed ? 'CONTROLS-PASS' : 'CONTROLS-FAILED',
    controlsOnly: true,
    note: 'Pure harness controls only: frozen input equality, guide/fence rejection, classifiers, tree diff and verdict mapping. Not product or install evidence.',
    controls,
  };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function writeResults(resultsPath, report) {
  const destination = path.resolve(resultsPath);

  mkdirSync(path.dirname(destination), { recursive: true });
  writeFileSync(destination, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
}

export async function main(argv = process.argv.slice(2)) {
  let options;

  try {
    options = parseArguments(argv);
  } catch (error) {
    console.error(`Usage error: ${messageOf(error)}\n\n${USAGE}`);

    return EXIT.USAGE;
  }

  if (options.help) {
    console.log(USAGE);

    return EXIT.READY;
  }

  if (options.results !== null) {
    try {
      validateResultsDestination(path.resolve(options.results), REPO_ROOT);
    } catch (error) {
      if (!(error instanceof UsageError)) throw error;

      console.error(`Results destination rejected: ${error.message}`);

      return EXIT.USAGE;
    }
  }

  if (options.selfTest) {
    const controls = runSelfTest();

    console.log(JSON.stringify(controls, null, 2));

    return controls.status === 'CONTROLS-PASS' ? EXIT.READY : EXIT.FAILED;
  }

  const outcome = await runOnboarding({ tarball: options.tarball, guide: options.guide });
  const summary = summarizeReport(outcome.report);

  if (outcome.report.status === 'blocked') {
    const blocked = outcome.report.checks.find((check) => check.status === 'failed');

    console.error(`BLOCKED: ${blocked === undefined ? 'prerequisite missing' : blocked.detail}`);
  }

  // Results are evidence only: written after cleanup and integrity are known,
  // and withheld when either could not be confirmed.
  if (options.results !== null) {
    if (outcome.report.cleanup.confirmed === true && outcome.report.integrity.artifactUnchanged === true
      && outcome.report.integrity.checkoutUnchanged === true) {
      try {
        writeResults(options.results, { ...outcome.report, summaryRedacted: summary });
        summary.resultsWritten = true;
      } catch (error) {
        console.error(`Results were not written: ${messageOf(error)}`);

        return EXIT.FAILED;
      }
    } else {
      summary.resultsWritten = false;
      summary.resultsWithheld = 'cleanup or integrity was not confirmed';
    }
  }

  console.log(JSON.stringify(summary, null, 2));

  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = await main();
}
