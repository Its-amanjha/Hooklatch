#!/usr/bin/env node
/**
 * Phase 11 minimum-runtime gate (big-pickle owner).
 *
 * Proves the candidate package on the ACTUAL Node 22.0.0 runtime floor:
 *
 *   - the prerequisite executable must report exactly `v22.0.0` (22.latest is
 *     not floor evidence), and every target child is a plain `.mjs` entry that
 *     imports only Node builtins plus the installed package;
 *   - the candidate tarball is inspected in memory (gzip + tar header walk)
 *     for the canonical CJS graph, ESM facades and frozen export map BEFORE any
 *     temporary directory exists;
 *   - the package is installed offline into an OS-temp consumer root with the
 *     host Node 24 toolchain (npm/tsc never run on the target runtime);
 *   - two bounded child runs execute the checked consumer: the floor tuple with
 *     no compatibility flags, and an optional later-22 repeat with exactly
 *     `--no-experimental-require-module` (never passed on 22.0.0);
 *   - reports are validated against an exact check inventory and on-disk
 *     resolution paths, then the temp tree is removed with confirmation and the
 *     repository status is compared before/after.
 *
 * Usage:
 *   node scripts/phase11/runtime-floor.mjs --tarball FILE --node22-floor FILE
 *        [--node22 FILE] [--results FILE]
 *   node scripts/phase11/runtime-floor.mjs --self-test [--tarball FILE] [--results FILE]
 *   node scripts/phase11/runtime-floor.mjs --help
 *
 * Exit: 0 ready, 1 failed, 2 usage, 3 prerequisite BLOCKED. A BLOCKED run is
 * never reported as a passing SDK result.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CONSUMER_SOURCE = path.join(REPO_ROOT, 'tests', 'runtime', 'phase11-floor-consumer.mjs');
const REPORT_PREFIX = 'PHASE11_FLOOR_REPORT ';

const EXIT_READY = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;
const EXIT_BLOCKED = 3;

const FLOOR_VERSION = 'v22.0.0';
const NODE22_FLAG = '--no-experimental-require-module';
const CHILD_TIMEOUT_MS = 300000;
const KILL_GRACE_MS = 10000;
const HANG_TIMEOUT_MS = 1200;
const OUTPUT_LIMIT = 1048576;
const STDERR_EVIDENCE_LIMIT = 4000;

/** Frozen export policy: specifier, dist base name, public export names. */
const EXPORTS_POLICY = Object.freeze([
  ['.', 'index', ['HooklatchError', 'createVerifier', 'verify', 'verifyRequest']],
  ['./diagnostics', 'diagnostics/index', ['diagnose']],
  ['./express', 'adapters/express', ['createWebhookMiddleware']],
  ['./nextjs', 'adapters/nextjs', ['createWebhookHandler']],
  ['./cloudflare', 'adapters/cloudflare', ['createWebhookHandler']],
  ['./hono', 'adapters/hono', ['createWebhookMiddleware']],
]);

const EXPECTED_EXPORTS_KEYS = EXPORTS_POLICY.map(([specifier]) => specifier);

/** Map a package `exports` key to the public request specifier (`hooklatch/...`). */
function packageSpecifier(exportKey) {
  return exportKey === '.' ? 'hooklatch' : `hooklatch/${exportKey.slice(2)}`;
}

/** Exact check inventory emitted by tests/runtime/phase11-floor-consumer.mjs. */
const EXPECTED_CHECK_IDS = Object.freeze([
  'env-runtime-identity',
  'env-exec-argv-exact',
  'env-no-compat-overrides',
  'env-require-module-feature',
  'env-resolution-commonjs',
  'env-resolution-esm-facades',
  'env-no-peer-packages',
  'subpaths-import-inventory',
  'subpaths-require-inventory',
  'identity-cross-format',
  'identity-error-instance-both-directions',
  'identity-diagnostics-error',
  'diagnostics-verification-detail',
  'diagnostics-setup-guidance',
  'adapter-express-bound',
  'adapter-hono-bound',
  'adapter-nextjs-bound',
  'adapter-cloudflare-bound',
  'provider-github-valid',
  'provider-github-tamper',
  'provider-vercel-valid',
  'provider-vercel-tamper',
  'provider-fal-valid',
  'provider-fal-tamper',
  'provider-fal-wrong-account',
  'provider-fal-boundary-expired',
  'provider-fal-boundary-expired-edge',
  'provider-fal-boundary-future',
  'provider-fal-boundary-future-edge',
  'provider-fal-zero-tolerance',
  'provider-grafana-timestamped-valid',
  'provider-grafana-timestamped-tamper',
  'provider-grafana-timestamped-expired',
  'provider-grafana-required-header',
  'provider-polar-current-valid',
  'provider-polar-legacy-valid',
  'provider-polar-mode-separation',
  'binary-offset-view-exact',
  'binary-offset-view-outside-tamper',
  'binary-offset-view-inside-tamper',
  'cli-help',
  'cli-dry-run-github',
  'cli-dry-run-fal',
  'cli-no-writes',
]);

const TARGET_ENV_KEYS = Object.freeze([
  'PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'COMSPEC',
  'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'LANG', 'LC_ALL',
]);

const STDERR_ALLOWED = Object.freeze([
  /^\(node:\d+\) ExperimentalWarning: The Ed25519 Web Crypto API algorithm is an experimental feature/,
  /^ExperimentalWarning: The Ed25519 Web Crypto API algorithm is an experimental feature/,
  /^\(Use `[^`]+ --trace-warnings \.\.\.` to show where the warning was created\)$/,
]);

const HELP_TEXT = `Phase 11 Node 22.0 minimum-runtime gate

Usage:
  node scripts/phase11/runtime-floor.mjs --tarball FILE --node22-floor FILE [options]
  node scripts/phase11/runtime-floor.mjs --self-test [--tarball FILE] [--results FILE]
  node scripts/phase11/runtime-floor.mjs --help

Required for a ready run:
  --tarball FILE        Candidate package tarball (inspected, then installed offline).
                        Without it the checkout itself is classified and the run is BLOCKED.
  --node22-floor FILE   Executable that must report exactly v22.0.0.

Options:
  --node22 FILE         Later Node 22 executable for the --no-experimental-require-module repeat.
  --results FILE        Write the JSON evidence report to FILE.
  --self-test           Run harness negative controls in OS temp; no repository writes.
  --help, -h            Show this help.

Exit codes:
  0  Ready (or help / passing self-test)
  1  Failed check
  2  Invalid usage
  3  Prerequisite BLOCKED (never a passing SDK result)
`;

/* ------------------------------------------------------------------ *
 * Small shared helpers
 * ------------------------------------------------------------------ */

function objectTag(value) {
  return Object.prototype.toString.call(value);
}

function asRecord(value) {
  if (value === null || value === undefined) return null;

  if (Array.isArray(value)) return null;

  if (objectTag(value) !== '[object Object]') return null;

  return value;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(filePath) {
  return sha256(readFileSync(filePath));
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isProcessAlive(pid) {
  if (pid === null) return false;

  try {
    process.kill(pid, 0);

    return true;
  } catch {
    return false;
  }
}

function targetEnv() {
  const env = {};

  for (const key of TARGET_ENV_KEYS) {
    const value = process.env[key];

    if (value !== undefined) env[key] = value;
  }

  env.NO_COLOR = '1';

  return env;
}

function hostEnv() {
  const env = {};

  for (const [key, value] of Object.entries(process.env)) {
    if (key === 'NODE_OPTIONS' || value === undefined) continue;

    env[key] = value;
  }

  return env;
}

function resolveInput(value) {
  return path.isAbsolute(value) ? value : path.resolve(process.cwd(), value);
}

/* ------------------------------------------------------------------ *
 * Bounded child execution with explicit termination evidence
 * ------------------------------------------------------------------ */

function runChild(executable, args, options = {}) {
  const { cwd = REPO_ROOT, timeoutMs = CHILD_TIMEOUT_MS, env = process.env, limit = OUTPUT_LIMIT } = options;

  const evidence = {
    executable,
    args: [...args],
    cwd,
    pid: null,
    exitCode: null,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    outputLimitExceeded: false,
    spawnError: null,
    closeConfirmed: false,
    killAttempted: false,
    killConfirmed: false,
    durationMs: 0,
  };

  return new Promise((resolve) => {
    const startedAt = Date.now();
    let settled = false;
    let child = null;
    let timer = null;
    let graceTimer = null;

    const settle = () => {
      if (settled) return;

      settled = true;

      if (timer !== null) clearTimeout(timer);

      if (graceTimer !== null) clearTimeout(graceTimer);

      evidence.durationMs = Date.now() - startedAt;

      if (evidence.killAttempted) {
        evidence.killConfirmed = evidence.closeConfirmed && !isProcessAlive(evidence.pid);
      }

      resolve(evidence);
    };

    const append = (channel, chunk) => {
      const next = evidence[channel] + chunk.toString('utf8');

      if (next.length > limit) {
        evidence[channel] = next.slice(0, limit);
        evidence[`${channel}Truncated`] = true;
        evidence.outputLimitExceeded = true;

        if (child !== null) {
          evidence.killAttempted = true;
          child.kill('SIGKILL');
        }

        return;
      }

      evidence[channel] = next;
    };

    try {
      child = spawn(executable, args, {
        cwd, env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      evidence.spawnError = messageOf(error);
      settle();

      return;
    }

    evidence.pid = child.pid === undefined ? null : child.pid;

    child.stdout.on('data', (chunk) => { append('stdout', chunk); });
    child.stderr.on('data', (chunk) => { append('stderr', chunk); });

    child.on('error', (error) => {
      evidence.spawnError = messageOf(error);

      if (evidence.pid === null) settle();
    });

    child.on('close', (code, signal) => {
      evidence.exitCode = code === undefined ? null : code;
      evidence.signal = signal === undefined ? null : signal;
      evidence.closeConfirmed = true;
      settle();
    });

    timer = setTimeout(() => {
      evidence.timedOut = true;
      evidence.killAttempted = true;

      if (child !== null) child.kill('SIGKILL');

      graceTimer = setTimeout(settle, KILL_GRACE_MS);
    }, timeoutMs);
  });
}

function summarizeChild(evidence) {
  return {
    executable: evidence.executable,
    args: evidence.args,
    cwd: evidence.cwd,
    pid: evidence.pid,
    exitCode: evidence.exitCode,
    signal: evidence.signal,
    stdoutBytes: evidence.stdout.length,
    stderr: evidence.stderr.slice(0, STDERR_EVIDENCE_LIMIT),
    stdoutTruncated: evidence.stdoutTruncated,
    stderrTruncated: evidence.stderrTruncated,
    timedOut: evidence.timedOut,
    outputLimitExceeded: evidence.outputLimitExceeded,
    spawnError: evidence.spawnError,
    closeConfirmed: evidence.closeConfirmed,
    killAttempted: evidence.killAttempted,
    killConfirmed: evidence.killConfirmed,
    durationMs: evidence.durationMs,
  };
}

/* ------------------------------------------------------------------ *
 * Runtime probes and the exact floor gate
 * ------------------------------------------------------------------ */

function classifyFloor(probe) {
  if (probe.kind === 'missing') return 'blocked';

  if (probe.kind === 'probe-failed') return 'failed';

  if (probe.version !== FLOOR_VERSION) return 'failed';

  return 'ready';
}

async function probeRuntime(executable) {
  if (!existsSync(executable)) return { kind: 'missing', executable, version: null };

  const stats = statSync(executable);

  if (!stats.isFile()) return { kind: 'missing', executable, version: null };

  const run = await runChild(executable, ['--version'], {
    cwd: os.tmpdir(), timeoutMs: 60000, env: targetEnv(),
  });

  if (run.spawnError !== null || run.exitCode !== 0 || run.timedOut) {
    return {
      kind: 'probe-failed',
      executable,
      version: null,
      sha256: sha256File(executable),
      bytes: stats.size,
      probe: summarizeChild(run),
    };
  }

  return {
    kind: 'version',
    executable,
    version: run.stdout.trim(),
    sha256: sha256File(executable),
    bytes: stats.size,
  };
}

/* ------------------------------------------------------------------ *
 * Tarball inspection (no external tools, no writes)
 * ------------------------------------------------------------------ */

function readTarString(header, offset, length) {
  const slice = header.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  const bytes = end === -1 ? slice : slice.subarray(0, end);

  return bytes.toString('utf8').trim();
}

function decodeTarEntries(buffer) {
  const entries = new Map();
  let offset = 0;
  let pendingName = null;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);

    if (header.every((byte) => byte === 0)) break;

    const type = String.fromCharCode(header[156] === 0 ? 48 : header[156]);
    const size = Number.parseInt(readTarString(header, 124, 12) || '0', 8) || 0;
    const prefix = readTarString(header, 345, 155);
    const baseName = readTarString(header, 0, 100);

    const name = pendingName === null
      ? (prefix.length > 0 ? `${prefix}/${baseName}` : baseName)
      : pendingName;

    const dataStart = offset + 512;
    const data = buffer.subarray(dataStart, dataStart + size);

    if (type === 'L') {
      pendingName = data.toString('utf8').replace(/\0+$/, '').trim();
    } else if (type === '0' || type === '7') {
      entries.set(name, data);
      pendingName = null;
    } else if (type !== 'x' && type !== 'g') {
      pendingName = null;
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return entries;
}

function checkExportEntry(problems, exportsField, specifier, base) {
  const entry = asRecord(exportsField[specifier]);

  if (entry === null) {
    problems.push(`exports-entry-missing:${specifier}`);

    return null;
  }

  const node = asRecord(entry.node);

  if (node === null) {
    problems.push(`exports-node-condition-missing:${specifier}`);

    return null;
  }

  const nodeImport = asRecord(node.import);
  const nodeRequire = asRecord(node.require);

  if (nodeImport === null || nodeImport.default !== `./dist/node/${base}.js`) {
    problems.push(`exports-node-import:${specifier}`);
  }

  if (nodeImport === null || nodeImport.types !== `./dist/node/${base}.d.ts`) {
    problems.push(`exports-node-import-types:${specifier}`);
  }

  if (nodeRequire === null || nodeRequire.default !== `./dist/cjs/${base}.cjs`) {
    problems.push(`exports-node-require:${specifier}`);
  }

  if (nodeRequire === null || nodeRequire.types !== `./dist/cjs/${base}.d.cts`) {
    problems.push(`exports-node-require-types:${specifier}`);
  }

  if (entry.types !== `./dist/${base}.d.ts`) problems.push(`exports-neutral-types:${specifier}`);

  if (entry.import !== `./dist/${base}.js`) problems.push(`exports-neutral-import:${specifier}`);

  if (entry.default !== `./dist/${base}.js`) problems.push(`exports-neutral-default:${specifier}`);

  return {
    specifier,
    import: nodeImport === null ? null : nodeImport.default,
    require: nodeRequire === null ? null : nodeRequire.default,
  };
}

function inspectCandidateTarball(tarballPath) {
  const problems = [];

  const evidence = {
    mode: 'tarball',
    path: tarballPath,
    bytes: null,
    sha256: null,
    packageVersion: null,
    exportsKeys: null,
    entries: [],
    problems,
  };

  if (!existsSync(tarballPath)) {
    problems.push('tarball-missing');

    return { ok: false, blocked: true, evidence };
  }

  const raw = readFileSync(tarballPath);

  evidence.bytes = raw.byteLength;
  evidence.sha256 = sha256(raw);

  let listing;

  try {
    listing = decodeTarEntries(gunzipSync(raw));
  } catch (error) {
    problems.push(`tarball-not-gzip: ${messageOf(error)}`);

    return { ok: false, blocked: true, evidence };
  }

  const manifestBytes = listing.get('package/package.json');

  if (manifestBytes === undefined) {
    problems.push('tarball-package-json-missing');

    return { ok: false, blocked: true, evidence };
  }

  let manifest;

  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    problems.push(`tarball-package-json-invalid: ${messageOf(error)}`);

    return { ok: false, blocked: true, evidence };
  }

  const manifestRecord = asRecord(manifest);

  if (manifestRecord === null) {
    problems.push('tarball-package-json-not-object');

    return { ok: false, blocked: true, evidence };
  }

  evidence.packageVersion = manifestRecord.version === undefined ? null : manifestRecord.version;

  const exportsField = asRecord(manifestRecord.exports);

  if (exportsField === null) {
    problems.push('tarball-exports-missing');

    return { ok: false, blocked: true, evidence };
  }

  evidence.exportsKeys = Object.keys(exportsField);

  if (!sameJson(evidence.exportsKeys, EXPECTED_EXPORTS_KEYS)) {
    problems.push(`tarball-exports-order: ${evidence.exportsKeys.join(',')}`);
  }

  const files = [];

  for (const [specifier, base] of EXPORTS_POLICY) {
    const checked = checkExportEntry(problems, exportsField, specifier, base);

    if (checked !== null) evidence.entries.push(checked);

    for (const required of [
      `package/dist/cjs/${base}.cjs`,
      `package/dist/cjs/${base}.d.cts`,
      `package/dist/node/${base}.js`,
      `package/dist/node/${base}.d.ts`,
      `package/dist/${base}.js`,
      `package/dist/${base}.d.ts`,
    ]) {
      const data = listing.get(required);

      if (data === undefined) {
        problems.push(`tarball-file-missing:${required}`);
        continue;
      }

      files.push({ path: required, bytes: data.byteLength, sha256: sha256(data) });
    }
  }

  const binField = asRecord(manifestRecord.bin);

  if (binField === null || binField.hooklatch !== './dist/cli/index.js') {
    problems.push('tarball-bin-entry');
  }

  const cliEntry = listing.get('package/dist/cli/index.js');

  if (cliEntry === undefined) problems.push('tarball-cli-missing');

  evidence.files = files;

  return { ok: problems.length === 0, blocked: problems.length > 0, evidence };
}

/**
 * Directory candidate used for the unsupported-branch control and for a run
 * without `--tarball`. Read-only: it never creates a workspace.
 */
function inspectCandidateDirectory(directory) {
  const problems = [];

  const evidence = {
    mode: 'directory',
    path: directory,
    packageVersion: null,
    exportsKeys: null,
    cjsPresent: false,
    problems,
  };

  const manifestPath = path.join(directory, 'package.json');

  if (!existsSync(manifestPath)) {
    problems.push('checkout-package-json-missing');

    return { ok: false, blocked: true, evidence };
  }

  let manifest;

  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    problems.push(`checkout-package-json-invalid: ${messageOf(error)}`);

    return { ok: false, blocked: true, evidence };
  }

  const manifestRecord = asRecord(manifest);

  if (manifestRecord === null) {
    problems.push('checkout-package-json-not-object');

    return { ok: false, blocked: true, evidence };
  }

  evidence.packageVersion = manifestRecord.version === undefined ? null : manifestRecord.version;

  const exportsField = asRecord(manifestRecord.exports);

  if (exportsField === null) {
    problems.push('checkout-exports-missing');

    return { ok: false, blocked: true, evidence };
  }

  evidence.exportsKeys = Object.keys(exportsField);

  if (!sameJson(evidence.exportsKeys, EXPECTED_EXPORTS_KEYS)) {
    problems.push(`checkout-exports-order: ${evidence.exportsKeys.join(',')}`);
  }

  for (const [specifier, base] of EXPORTS_POLICY) {
    checkExportEntry(problems, exportsField, specifier, base);

    if (!existsSync(path.join(directory, 'dist', 'cjs', `${base}.cjs`))) {
      problems.push(`checkout-cjs-missing:${base}.cjs`);
    }

    if (!existsSync(path.join(directory, 'dist', 'node', `${base}.js`))) {
      problems.push(`checkout-facade-missing:${base}.js`);
    }
  }

  evidence.cjsPresent = existsSync(path.join(directory, 'dist', 'cjs', 'index.cjs'));

  return { ok: problems.length === 0, blocked: problems.length > 0, evidence };
}

/* ------------------------------------------------------------------ *
 * Workspace, install and report validation
 * ------------------------------------------------------------------ */

function locateNpmCli() {
  const candidates = [
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  try {
    return createRequire(import.meta.url).resolve('npm/bin/npm-cli.js');
  } catch {
    return null;
  }
}

function createWorkspace() {
  const root = path.join(os.tmpdir(), `phase11-floor-${randomUUID()}`);
  const consumer = path.join(root, 'consumer');
  const cache = path.join(root, 'npm-cache');

  mkdirSync(consumer, { recursive: true });
  mkdirSync(cache, { recursive: true });

  writeFileSync(
    path.join(consumer, 'package.json'),
    `${JSON.stringify({ name: 'phase11-floor-consumer', version: '0.0.0', private: true, type: 'module' }, null, 2)}\n`,
  );

  const consumerScript = path.join(consumer, 'phase11-floor-consumer.mjs');

  copyFileSync(CONSUMER_SOURCE, consumerScript);

  return {
    root,
    consumer,
    cache,
    consumerScript,
    sourceSha256: sha256File(CONSUMER_SOURCE),
    copySha256: sha256File(consumerScript),
  };
}

function removeWorkspace(workspace) {
  rmSync(workspace.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });

  return { root: workspace.root, removed: !existsSync(workspace.root), confirmed: !existsSync(workspace.root) };
}

async function installCandidate(workspace, tarballPath, npmCli) {
  const args = [
    npmCli, 'install', tarballPath, '--no-save', '--ignore-scripts', '--offline',
    '--no-audit', '--no-fund', '--legacy-peer-deps', '--cache', workspace.cache,
  ];

  const run = await runChild(process.execPath, args, {
    cwd: workspace.consumer, timeoutMs: 300000, env: hostEnv(),
  });

  const installedRoot = path.join(workspace.consumer, 'node_modules', 'hooklatch');
  const installedManifest = path.join(installedRoot, 'package.json');
  const nodeModules = path.join(workspace.consumer, 'node_modules');

  const entries = existsSync(nodeModules)
    ? readdirSync(nodeModules).sort()
    : [];

  return {
    evidence: summarizeChild(run),
    ok: run.exitCode === 0 && run.spawnError === null && !run.timedOut && existsSync(installedManifest),
    installedRoot,
    installedManifest,
    installedVersion: existsSync(installedManifest)
      ? JSON.parse(readFileSync(installedManifest, 'utf8')).version
      : null,
    nodeModulesEntries: entries,
  };
}

function installedFileEvidence(installedRoot, files) {
  const problems = [];
  const verified = [];

  for (const file of files) {
    const relative = file.path.replace(/^package\//, '');
    const target = path.join(installedRoot, relative);

    if (!existsSync(target)) {
      problems.push(`installed-file-missing:${relative}`);
      continue;
    }

    const digest = sha256File(target);

    if (digest !== file.sha256) problems.push(`installed-file-hash:${relative}`);

    verified.push({ path: relative, sha256: digest });
  }

  return { ok: problems.length === 0, problems, verified };
}

function parseReport(stdout) {
  const lines = stdout.split(/\r?\n/).filter((line) => line.startsWith(REPORT_PREFIX));

  if (lines.length !== 1) return { report: null, problem: `report-lines: ${lines.length}` };

  try {
    return { report: JSON.parse(lines[0].slice(REPORT_PREFIX.length)), problem: null };
  } catch (error) {
    return { report: null, problem: `report-json: ${messageOf(error)}` };
  }
}

function unexpectedStderr(stderr) {
  const unexpected = [];

  for (const raw of stderr.split(/\r?\n/)) {
    const line = raw.trim();

    if (line.length === 0) continue;

    if (STDERR_ALLOWED.some((pattern) => pattern.test(line))) continue;

    unexpected.push(line);
  }

  return unexpected;
}

function validateResolution(report, consumerRoot, problems) {
  const resolution = asRecord(report.resolution);
  const requireMap = resolution === null ? null : asRecord(resolution.require);
  const importMap = resolution === null ? null : asRecord(resolution.import);
  const installedPrefix = path.join(consumerRoot, 'node_modules', 'hooklatch').toLowerCase();

  for (const [specifier, base] of EXPORTS_POLICY) {
    const packageId = packageSpecifier(specifier);
    const requireFile = requireMap === null ? undefined : requireMap[packageId];

    if (requireFile === undefined) {
      problems.push(`require-resolution-missing:${packageId}`);
    } else {
      const resolved = path.resolve(requireFile);

      if (!requireFile.endsWith(`/dist/cjs/${base}.cjs`)) problems.push(`require-resolution:${packageId}`);

      if (!resolved.toLowerCase().startsWith(installedPrefix)) problems.push(`require-outside-install:${packageId}`);

      if (!existsSync(resolved)) problems.push(`require-target-missing:${packageId}`);
    }

    const importFile = importMap === null ? undefined : importMap[packageId];

    if (importFile === undefined) {
      problems.push(`import-resolution-missing:${packageId}`);
    } else {
      const resolved = path.resolve(importFile);

      if (!importFile.endsWith(`/dist/node/${base}.js`)) problems.push(`import-resolution:${packageId}`);

      if (!resolved.toLowerCase().startsWith(installedPrefix)) problems.push(`import-outside-install:${packageId}`);

      if (!existsSync(resolved)) problems.push(`import-target-missing:${packageId}`);
    }
  }
}

function validateReport({ report, evidence, expectedVersion, expectedArgv, consumerRoot }) {
  const problems = [];

  if (evidence.spawnError !== null) problems.push(`spawn-error: ${evidence.spawnError}`);

  if (evidence.outputLimitExceeded) problems.push('output-limit-exceeded');

  if (evidence.timedOut) problems.push('timed-out');

  if (!evidence.closeConfirmed) problems.push('close-unconfirmed');

  if (evidence.exitCode !== 0) problems.push(`exit-code: ${evidence.exitCode}`);

  if (evidence.signal !== null) problems.push(`signal: ${evidence.signal}`);

  if (report === null) {
    problems.push('report-missing');

    return { ok: false, problems, checkIds: [], passed: 0, failed: 0 };
  }

  const record = asRecord(report);

  if (record === null) {
    problems.push('report-not-object');

    return { ok: false, problems, checkIds: [], passed: 0, failed: 0 };
  }

  if (record.kind !== 'phase11-floor-consumer') problems.push(`report-kind: ${String(record.kind)}`);

  if (record.fatal !== undefined) problems.push(`report-fatal: ${String(record.fatal)}`);

  if (record.runtime !== expectedVersion) {
    problems.push(`report-runtime: ${String(record.runtime)} != ${expectedVersion}`);
  }

  if (!sameJson(record.execArgv, expectedArgv)) {
    problems.push(`report-exec-argv: ${JSON.stringify(record.execArgv)}`);
  }

  if (record.platform !== process.platform) problems.push(`report-platform: ${String(record.platform)}`);

  const checks = Array.isArray(record.checks) ? record.checks : [];
  const ids = [];
  const failedChecks = [];

  for (const entry of checks) {
    const checkRecord = asRecord(entry);

    if (checkRecord === null || checkRecord.ok !== true) {
      failedChecks.push(checkRecord === null || checkRecord.id === undefined ? 'unknown' : String(checkRecord.id));
    }

    ids.push(checkRecord === null || checkRecord.id === undefined ? null : String(checkRecord.id));
  }

  const sortedIds = [...ids].sort();
  const sortedExpected = [...EXPECTED_CHECK_IDS].sort();

  if (!sameJson(sortedIds, sortedExpected)) problems.push('check-inventory-mismatch');

  if (new Set(ids).size !== ids.length) problems.push('duplicate-check-id');

  if (failedChecks.length > 0) problems.push(`failed-checks: ${failedChecks.join(',')}`);

  const summary = asRecord(record.summary);

  if (summary === null) {
    problems.push('summary-missing');
  } else {
    if (summary.total !== EXPECTED_CHECK_IDS.length) problems.push(`summary-total: ${String(summary.total)}`);

    if (summary.failed !== 0) problems.push(`summary-failed: ${String(summary.failed)}`);

    if (summary.passed !== summary.total) problems.push(`summary-passed: ${String(summary.passed)}`);
  }

  if (expectedVersion !== FLOOR_VERSION && record.requireModuleFeature !== false) {
    problems.push(`require-module-feature: ${String(record.requireModuleFeature)}`);
  }

  validateResolution(record, consumerRoot, problems);

  const passed = checks.length - failedChecks.length;

  return { ok: problems.length === 0, problems, checkIds: ids, passed, failed: failedChecks.length };
}

async function runTuple({ label, executable, expectedVersion, argv, workspace, cliPath }) {
  const execution = await runChild(
    executable,
    [...argv, workspace.consumerScript, '--cli', cliPath, '--expect-exec-argv', JSON.stringify(argv)],
    { cwd: workspace.consumer, timeoutMs: CHILD_TIMEOUT_MS, env: targetEnv() },
  );

  const parsed = parseReport(execution.stdout);
  const stderrUnexpected = unexpectedStderr(execution.stderr);

  const validation = validateReport({
    report: parsed.report,
    evidence: execution,
    expectedVersion,
    expectedArgv: argv,
    consumerRoot: workspace.consumer,
  });

  if (parsed.problem !== null) validation.problems.unshift(parsed.problem);

  if (stderrUnexpected.length > 0) validation.problems.push(`unexpected-stderr: ${stderrUnexpected.slice(0, 5).join(' | ')}`);

  if (parsed.problem !== null || stderrUnexpected.length > 0) validation.ok = false;

  return {
    label,
    tuple: {
      executable,
      expectedVersion,
      execArgv: argv,
      platform: process.platform,
      arch: process.arch,
      consumerSha256: workspace.copySha256,
      installedRoot: path.join(workspace.consumer, 'node_modules', 'hooklatch'),
      resolution: parsed.report === null || asRecord(parsed.report) === null ? null : parsed.report.resolution,
    },
    execution: summarizeChild(execution),
    report: parsed.report,
    unexpectedStderr: stderrUnexpected,
    validation,
  };
}

function gitStatus() {
  const run = spawnSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd: REPO_ROOT, encoding: 'utf8', timeout: 60000, windowsHide: true,
  });

  return {
    exitCode: run.status,
    stdout: run.stdout === null || run.stdout === undefined ? '' : run.stdout,
    stderr: run.stderr === null || run.stderr === undefined ? '' : run.stderr,
    error: run.error === undefined ? null : messageOf(run.error),
  };
}

/* ------------------------------------------------------------------ *
 * Outcomes
 * ------------------------------------------------------------------ */

function outcome(result, exitCode, summary, evidence) {
  return { result, exitCode, summary: { result, exitCode, generatedAt: new Date().toISOString(), ...summary }, evidence };
}

function failed(summary, evidence) {
  return outcome('failed', EXIT_FAILED, summary, evidence);
}

function blocked(reason, summary, evidence) {
  return outcome('blocked', EXIT_BLOCKED, { reason, ...summary }, evidence);
}

function ready(summary, evidence) {
  return outcome('ready', EXIT_READY, summary, evidence);
}

/* ------------------------------------------------------------------ *
 * Ready-run flow
 * ------------------------------------------------------------------ */

async function runFloor(options) {
  const startedAt = new Date().toISOString();

  const host = {
    node: process.version,
    nodeMajor: process.versions.node.split('.')[0],
    platform: process.platform,
    arch: process.arch,
    executable: process.execPath,
  };

  const integrityBefore = gitStatus();

  const base = {
    schemaVersion: 1,
    kind: 'phase11-runtime-floor',
    startedAt,
    host,
    inputs: {},
    candidate: null,
    workspace: null,
    tuples: [],
    controls: [],
    cleanup: null,
    integrity: { before: integrityBefore, after: null, unchanged: null },
    limitations: [
      'Local evidence only: this Windows host cannot replace the coordinator Linux Node 22.0.0 job.',
      'The candidate seed is an explicit input, not shipped product support.',
      'No network access is used; the install is offline from the provided tarball.',
    ],
  };

  if (options.tarball === null) {
    const checkout = inspectCandidateDirectory(REPO_ROOT);
    const reason = checkout.ok ? 'checkout-run-requires-tarball' : 'checkout-not-cjs-candidate';

    return blocked(reason, {
      checkout: checkout.evidence,
      detail: checkout.ok
        ? 'This checkout has canonical CJS output but a directory candidate cannot prove installed packaging; pass --tarball.'
        : 'This checkout does not export canonical CJS entries, so no SDK result may be claimed.',
    }, { ...base, candidate: checkout.evidence });
  }

  const tarballPath = resolveInput(options.tarball);
  const candidateResult = inspectCandidateTarball(tarballPath);

  base.inputs.tarball = { path: tarballPath, sha256: candidateResult.evidence.sha256, bytes: candidateResult.evidence.bytes };
  base.candidate = candidateResult.evidence;

  if (!candidateResult.ok) {
    return blocked('candidate-tarball-not-cjs', {
      detail: 'The provided tarball lacks the canonical CJS graph, ESM facades or frozen export map.',
      problems: candidateResult.evidence.problems,
    }, base);
  }

  const floor = options.node22Floor === null
    ? { kind: 'missing', executable: null, version: null }
    : await probeRuntime(resolveInput(options.node22Floor));

  base.inputs.node22Floor = {
    path: floor.executable, version: floor.version, sha256: floor.sha256 === undefined ? null : floor.sha256, bytes: floor.bytes === undefined ? null : floor.bytes,
  };

  if (classifyFloor(floor) === 'blocked') {
    return blocked('node22-floor-missing', {
      detail: options.node22Floor === null
        ? 'No --node22-floor executable was provided; no minimum-runtime claim is possible.'
        : 'The Node 22.0.0 floor executable is unavailable; no minimum-runtime claim is possible.',
      executable: floor.executable,
    }, base);
  }

  if (classifyFloor(floor) === 'failed') {
    return failed({
      reason: 'node22-floor-version',
      detail: `The floor executable must report exactly ${FLOOR_VERSION}; observed ${String(floor.version)}.`,
      probe: floor.probe === undefined ? null : floor.probe,
    }, base);
  }

  let repeat = null;

  if (options.node22 !== null) {
    repeat = await probeRuntime(resolveInput(options.node22));

    base.inputs.node22 = {
      path: repeat.executable, version: repeat.version, sha256: repeat.sha256 === undefined ? null : repeat.sha256, bytes: repeat.bytes === undefined ? null : repeat.bytes,
    };

    if (classifyFloor(repeat) === 'blocked' && repeat.kind === 'missing') {
      return blocked('node22-runtime-missing', {
        detail: 'A later Node 22 executable was requested for the repeat run but is unavailable.',
        executable: repeat.executable,
      }, base);
    }

    const repeatVersion = repeat.version === null ? '' : repeat.version;

    if (repeat.kind !== 'version' || !repeatVersion.startsWith('v22.') || repeatVersion === FLOOR_VERSION) {
      return failed({
        reason: 'node22-runtime-version',
        detail: `--node22 must be a later Node 22 runtime (not ${FLOOR_VERSION}); observed ${String(repeat.version)}.`,
        probe: repeat.probe === undefined ? null : repeat.probe,
      }, base);
    }
  }

  const npmCli = locateNpmCli();

  if (npmCli === null) {
    return blocked('npm-cli-missing', {
      detail: 'The host npm CLI is required to install the candidate tarball offline.',
    }, base);
  }

  const workspace = createWorkspace();

  const workspaceEvidence = {
    root: workspace.root,
    consumer: workspace.consumer,
    consumerSource: CONSUMER_SOURCE,
    consumerSourceSha256: workspace.sourceSha256,
    consumerCopySha256: workspace.copySha256,
    consumerCopyMatchesSource: workspace.sourceSha256 === workspace.copySha256,
  };

  base.workspace = workspaceEvidence;

  if (!workspaceEvidence.consumerCopyMatchesSource) {
    const cleanup = removeWorkspace(workspace);

    return failed({ reason: 'consumer-copy-hash', cleanup }, { ...base, cleanup });
  }

  const install = await installCandidate(workspace, tarballPath, npmCli);

  const fileEvidence = install.ok
    ? installedFileEvidence(install.installedRoot, candidateResult.evidence.files)
    : { ok: false, problems: ['install-failed'], verified: [] };

  const installEvidence = {
    ...install.evidence,
    ok: install.ok,
    installedVersion: install.installedVersion,
    nodeModulesEntries: install.nodeModulesEntries,
    files: fileEvidence,
  };

  base.install = installEvidence;

  if (!install.ok || !fileEvidence.ok) {
    const cleanup = removeWorkspace(workspace);
    const integrityAfter = gitStatus();

    base.cleanup = cleanup;
    base.integrity.after = integrityAfter;
    base.integrity.unchanged = integrityAfter.stdout === integrityBefore.stdout;

    return failed({
      reason: install.ok ? 'installed-file-mismatch' : 'install-failed',
      install: installEvidence,
      cleanup,
      integrityUnchanged: base.integrity.unchanged,
    }, base);
  }

  const cliPath = path.join(install.installedRoot, 'dist', 'cli', 'index.js');

  const floorTuple = await runTuple({
    label: 'node22.0.0-floor',
    executable: floor.executable,
    expectedVersion: FLOOR_VERSION,
    argv: [],
    workspace,
    cliPath,
  });

  base.tuples.push(floorTuple);

  if (repeat !== null) {
    const repeatTuple = await runTuple({
      label: `node${String(repeat.version)}-repeat`,
      executable: repeat.executable,
      expectedVersion: repeat.version,
      argv: [NODE22_FLAG],
      workspace,
      cliPath,
    });

    base.tuples.push(repeatTuple);
  }

  const cleanup = removeWorkspace(workspace);
  const integrityAfter = gitStatus();

  base.cleanup = cleanup;
  base.integrity.after = integrityAfter;
  base.integrity.unchanged = integrityAfter.stdout === integrityBefore.stdout;

  const tupleProblems = [];

  for (const tuple of base.tuples) {
    if (!tuple.validation.ok) tupleProblems.push(`${tuple.label}: ${tuple.validation.problems.join('; ')}`);
  }

  if (!cleanup.confirmed) tupleProblems.push('cleanup-unconfirmed');

  if (!base.integrity.unchanged) tupleProblems.push('repository-status-changed');

  if (base.tuples.length !== (options.node22 === null ? 1 : 2)) tupleProblems.push('tuple-count');

  base.finishedAt = new Date().toISOString();

  if (tupleProblems.length > 0) {
    return failed({
      reason: 'gate-checks',
      problems: tupleProblems,
      tuples: base.tuples.map((tuple) => ({
        label: tuple.label,
        validation: tuple.validation,
        execution: tuple.execution,
        unexpectedStderr: tuple.unexpectedStderr,
      })),
      cleanup,
      integrityUnchanged: base.integrity.unchanged,
    }, base);
  }

  return ready({
    floor: { executable: floor.executable, version: floor.version, sha256: floor.sha256 },
    repeat: repeat === null ? null : { executable: repeat.executable, version: repeat.version, sha256: repeat.sha256 },
    tarball: { path: tarballPath, sha256: candidateResult.evidence.sha256, bytes: candidateResult.evidence.bytes },
    checkInventories: base.tuples.map((tuple) => ({ label: tuple.label, checks: tuple.validation.checkIds.length, passed: tuple.validation.passed })),
    cleanup,
    integrityUnchanged: base.integrity.unchanged,
    limitations: base.limitations,
  }, base);
}

/* ------------------------------------------------------------------ *
 * Self-test controls
 * ------------------------------------------------------------------ */

async function runSelfTest(options) {
  const controls = [];

  const base = {
    schemaVersion: 1,
    kind: 'phase11-runtime-floor-self-test',
    startedAt: new Date().toISOString(),
    host: { node: process.version, platform: process.platform, arch: process.arch },
    controls,
  };

  async function control(id, run) {
    try {
      const detail = await run();

      controls.push({ id, ok: true, detail: detail === undefined ? null : detail });
    } catch (error) {
      controls.push({ id, ok: false, error: messageOf(error) });
    }
  }

  await control('control-floor-version-exact', () => {
    const accepted = classifyFloor({ kind: 'version', version: FLOOR_VERSION });
    const later = classifyFloor({ kind: 'version', version: 'v22.23.4' });
    const earlier = classifyFloor({ kind: 'version', version: 'v21.7.3' });

    if (accepted !== 'ready') throw new Error(`v22.0.0 must be ready, observed ${accepted}`);

    if (later !== 'failed') throw new Error(`v22.23.4 must not be accepted as floor, observed ${later}`);

    if (earlier !== 'failed') throw new Error(`v21.7.3 must not be accepted as floor, observed ${earlier}`);

    return { accepted, later, earlier };
  });

  await control('control-floor-missing-is-blocked', async () => {
    const missing = path.join(os.tmpdir(), `phase11-missing-${randomUUID()}.exe`);
    const probe = await probeRuntime(missing);
    const classification = classifyFloor(probe);

    if (probe.kind !== 'missing') throw new Error(`expected a missing probe, observed ${probe.kind}`);

    if (classification !== 'blocked') throw new Error(`missing floor must block, observed ${classification}`);

    return { probe: probe.kind, classification };
  });

  await control('control-host-runtime-is-not-floor', async () => {
    const probe = await probeRuntime(process.execPath);
    const classification = classifyFloor(probe);

    if (probe.kind !== 'version') throw new Error(`host probe failed: ${probe.kind}`);

    if (probe.version === FLOOR_VERSION) throw new Error('the host runtime must be newer than the floor');

    if (classification !== 'failed') throw new Error(`a non-floor host must fail the floor gate, observed ${classification}`);

    return { version: probe.version, classification };
  });

  await control('control-unsupported-branch-blocked-before-workspace', () => {
    const root = path.join(os.tmpdir(), `phase11-unsupported-${randomUUID()}`);

    mkdirSync(root, { recursive: true });
    writeFileSync(
      path.join(root, 'package.json'),
      `${JSON.stringify({ name: 'phase11-esm-only', version: '0.0.0', type: 'module', exports: { '.': { types: './dist/index.d.ts', import: './dist/index.js' } } }, null, 2)}\n`,
    );

    const candidate = inspectCandidateDirectory(root);
    const workspaceUntouched = readdirSync(root).sort();

    rmSync(root, { recursive: true, force: true });

    if (candidate.ok) throw new Error('an ESM-only candidate must not be reported ready');

    if (!candidate.blocked) throw new Error('an ESM-only candidate must be BLOCKED');

    if (!candidate.evidence.problems.some((problem) => problem.startsWith('exports-node-condition-missing'))) {
      throw new Error(`expected a missing node condition, observed ${candidate.evidence.problems.join(',')}`);
    }

    if (!sameJson(workspaceUntouched, ['package.json'])) throw new Error('inspection must not create files');

    if (existsSync(root)) throw new Error('the control directory must be removed');

    return { problems: candidate.evidence.problems.length, files: workspaceUntouched };
  });

  await control('control-checkout-blocked-without-tarball', async () => {
    const result = await runFloor({ tarball: null, node22Floor: null, node22: null, results: null });

    if (result.exitCode !== EXIT_BLOCKED) {
      throw new Error(`a run without a tarball must be BLOCKED, observed exit ${String(result.exitCode)} (${String(result.summary.result)})`);
    }

    if (!String(result.summary.reason).startsWith('checkout-')) {
      throw new Error(`expected a checkout classification, observed ${String(result.summary.reason)}`);
    }

    if (result.evidence.workspace !== null) throw new Error('a BLOCKED run must not create a workspace');

    return { reason: result.summary.reason, exitCode: result.exitCode };
  });

  await control('control-child-crash-failed', async () => {
    const run = await runChild(process.execPath, ['-e', 'process.exit(7)'], {
      cwd: os.tmpdir(), timeoutMs: 30000, env: targetEnv(),
    });

    const parsed = parseReport(run.stdout);

    const validation = validateReport({
      report: parsed.report,
      evidence: run,
      expectedVersion: FLOOR_VERSION,
      expectedArgv: [],
      consumerRoot: os.tmpdir(),
    });

    if (run.exitCode !== 7) throw new Error(`expected exit 7, observed ${String(run.exitCode)}`);

    if (validation.ok) throw new Error('a crashed child must not validate');

    if (!validation.problems.some((problem) => problem.startsWith('exit-code'))) {
      throw new Error(`expected an exit-code problem, observed ${validation.problems.join(',')}`);
    }

    return { exitCode: run.exitCode, problems: validation.problems };
  });

  await control('control-child-hang-killed-confirmed', async () => {
    const run = await runChild(
      process.execPath,
      ['-e', 'setInterval(() => {}, 1000);'],
      { cwd: os.tmpdir(), timeoutMs: HANG_TIMEOUT_MS, env: targetEnv() },
    );

    if (!run.timedOut) throw new Error('the hang control must time out');

    if (!run.killAttempted) throw new Error('the hang control must attempt termination');

    if (!run.closeConfirmed) throw new Error('the hang control must observe child close');

    if (!run.killConfirmed) throw new Error('termination must be confirmed, not assumed');

    if (isProcessAlive(run.pid)) throw new Error('the killed child must not still be alive');

    return { pid: run.pid, timedOut: run.timedOut, closeConfirmed: run.closeConfirmed, killConfirmed: run.killConfirmed };
  });

  await control('control-report-mismatch-rejected', async () => {
    const script = [
      'process.stdout.write("PHASE11_FLOOR_REPORT " + JSON.stringify({',
      '  kind: "phase11-floor-consumer", runtime: "v22.0.0", platform: process.platform,',
      '  execArgv: [], resolution: { import: {}, require: {} },',
      '  checks: [{ id: "env-runtime-identity", ok: true }],',
      '  summary: { total: 1, passed: 1, failed: 0 }',
      '}) + "\\n");',
    ].join('\n');

    const run = await runChild(process.execPath, ['-e', script], {
      cwd: os.tmpdir(), timeoutMs: 30000, env: targetEnv(),
    });

    const parsed = parseReport(run.stdout);

    const validation = validateReport({
      report: parsed.report,
      evidence: run,
      expectedVersion: FLOOR_VERSION,
      expectedArgv: [],
      consumerRoot: os.tmpdir(),
    });

    if (validation.ok) throw new Error('an incomplete report must not validate');

    if (!validation.problems.includes('check-inventory-mismatch')) {
      throw new Error(`expected an inventory mismatch, observed ${validation.problems.join(',')}`);
    }

    return { problems: validation.problems };
  });

  await control('control-cleanup-requires-confirmation', () => {
    const root = path.join(os.tmpdir(), `phase11-cleanup-${randomUUID()}`);

    mkdirSync(root, { recursive: true });
    writeFileSync(path.join(root, 'file.txt'), 'synthetic');

    const cleanup = removeWorkspace({ root });

    if (!cleanup.removed || !cleanup.confirmed) throw new Error('cleanup must be confirmed');

    if (existsSync(root)) throw new Error('the directory must be gone');

    return cleanup;
  });

  if (options.tarball !== null) {
    await control('control-tarball-inspection', () => {
      const realPath = resolveInput(options.tarball);
      const real = inspectCandidateTarball(realPath);
      const corruptPath = path.join(os.tmpdir(), `phase11-corrupt-${randomUUID()}.tgz`);
      const raw = readFileSync(realPath);
      const corrupt = Buffer.from(raw);

      corrupt[Math.floor(corrupt.length / 2)] ^= 0xff;
      writeFileSync(corruptPath, corrupt);

      const tampered = inspectCandidateTarball(corruptPath);

      rmSync(corruptPath, { force: true });

      if (!real.ok) throw new Error(`the real tarball must inspect clean: ${real.evidence.problems.join(',')}`);

      if (tampered.ok) throw new Error('a corrupted tarball must not inspect clean');

      return { sha256: real.evidence.sha256, entries: real.evidence.entries.length, tamperedProblems: tampered.evidence.problems };
    });
  }

  const failures = controls.filter((entry) => !entry.ok);

  base.finishedAt = new Date().toISOString();

  if (failures.length > 0) {
    return outcome('self-test-failed', EXIT_FAILED, {
      controls: controls.length,
      failed: failures.map((entry) => entry.id),
    }, base);
  }

  return outcome('self-test-passed', EXIT_READY, {
    controls: controls.length,
    failed: [],
  }, base);
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

class UsageError extends Error {}

function parseArguments(argv) {
  const options = {
    tarball: null, node22Floor: null, node22: null, results: null, selfTest: false, help: false,
  };

  const flags = new Map([
    ['--tarball', 'tarball'],
    ['--node22-floor', 'node22Floor'],
    ['--node22', 'node22'],
    ['--results', 'results'],
  ]);

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];

    if (flag === '--help' || flag === '-h') {
      options.help = true;
      continue;
    }

    if (flag === '--self-test') {
      options.selfTest = true;
      continue;
    }

    const key = flags.get(flag);

    if (key === undefined) throw new UsageError(`Unknown argument: ${flag}`);

    const value = argv[index + 1];

    if (value === undefined || value.startsWith('--')) throw new UsageError(`Missing value for ${flag}.`);

    if (options[key] !== null) throw new UsageError(`Duplicate flag: ${flag}.`);

    options[key] = value;
    index += 1;
  }

  if (options.help) return options;

  return options;
}

function writeResults(resultsPath, value) {
  if (resultsPath === null) return { path: null, written: false };

  const target = resolveInput(resultsPath);

  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);

  return { path: target, written: existsSync(target), bytes: statSync(target).size };
}

async function main() {
  let options;

  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    const reason = messageOf(error);

    process.stderr.write(`${reason}\n`);
    process.stdout.write(HELP_TEXT);

    return { exitCode: EXIT_USAGE, summary: { result: 'usage', exitCode: EXIT_USAGE, reason }, evidence: null, results: null };
  }

  if (options.help) {
    process.stdout.write(HELP_TEXT);

    return { exitCode: EXIT_READY, summary: { result: 'help', exitCode: EXIT_READY }, evidence: null, results: null };
  }

  const run = options.selfTest ? await runSelfTest(options) : await runFloor(options);

  return { ...run, results: options.results };
}

const run = await main();

if (run.results !== null) {
  const written = writeResults(run.results, {
    summary: run.summary,
    evidence: run.evidence,
    results: null,
  });

  run.summary.resultsFile = written.path;
}

process.stdout.write(`PHASE11_FLOOR_RESULT ${JSON.stringify(run.summary)}\n`);

if (run.summary.reason !== undefined) {
  process.stdout.write(`PHASE11_FLOOR_REASON ${run.summary.reason}\n`);
}

process.exitCode = run.exitCode;
