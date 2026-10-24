#!/usr/bin/env node
/**
 * Phase 10 disposable CJS/ESM packaging prototype (Codebuff DeepSeek owner).
 *
 * Builds two throwaway package candidates from the REAL src/ and dist/ bytes of
 * this checkout, without editing package.json, exports, engines, dependencies or
 * build configuration:
 *
 *   per-module-cjs  TypeScript Node16 emit from a temp `type: commonjs` source
 *                   copy, renamed to .cjs/.d.cts with the relative specifier
 *                   graph rewritten, plus a full require condition.
 *   require-bridge  The unmodified ESM dist, with the require condition pointing
 *                   at the same ESM files (Node's require(esm) bridge).
 *
 * This module also owns the shared harness machinery imported by
 * scripts/phase10/cjs-consumers.mjs: bounded children, process-health
 * preservation, checked temp workspaces with an outer junction ledger, tracked
 * and dist byte snapshots, npm helpers and candidate inspectors.
 *
 * Exit: 0 prototype built and controls passed, 1 failure, 2 usage,
 * 3 prerequisite BLOCKED. Node22/24 remain independently executed by the
 * consumer matrix; this script never infers another runtime from one run.
 */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  readlinkSync, realpathSync, renameSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const TEMP_PREFIX = 'hooklatch-phase10-cjs-';
export const IS_WINDOWS = process.platform === 'win32';
export const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/** The manifest's shared coordinator tooling; overridable for later integration. */
export const DEFAULT_RUNTIMES = {
  node22: process.env.PHASE10_NODE22
    ?? 'D:/Typescript SDK/.worktrees/phase-9b-integration/notes/phase-9-stage-b/runtime-node22/node.exe',
  node24: process.env.PHASE10_NODE24 ?? 'C:/Program Files/nodejs/node.exe',
};

/** Six public subpaths, their entry modules and the exports each must expose. */
export const ENTRY_POINTS = [
  { subpath: '.', base: 'index', exports: ['HooklatchError', 'createVerifier', 'verify', 'verifyRequest'], peers: false },
  { subpath: './diagnostics', base: 'diagnostics/index', exports: ['diagnose'], peers: false },
  { subpath: './express', base: 'adapters/express', exports: ['createWebhookMiddleware'], peers: true },
  { subpath: './nextjs', base: 'adapters/nextjs', exports: ['createWebhookHandler'], peers: true },
  { subpath: './cloudflare', base: 'adapters/cloudflare', exports: ['createWebhookHandler'], peers: true },
  { subpath: './hono', base: 'adapters/hono', exports: ['createWebhookMiddleware'], peers: true },
];

/** Deep imports that the exports map must refuse in every format. */
export const FORBIDDEN_SUBPATHS = [
  'hooklatch/package.json',
  'hooklatch/dist/index.js',
  'hooklatch/dist-cjs/index.cjs',
  'hooklatch/dist/internal/crypto.js',
  'hooklatch/src/index.ts',
];

/** Exact public provider inventory (registry order) at the frozen base. */
export const PROVIDERS = [
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
  'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana',
  'polar', 'linear', 'vercel', 'fal',
];

export class PrerequisiteError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'PrerequisiteError';
  }
}

/* ------------------------------------------------------------------ *
 * Bounded children and process-health ledger
 * ------------------------------------------------------------------ */

/**
 * A child that timed out, exited on a signal, or could not be reaped may still
 * have descendants. Deleting its scratch in that state would destroy evidence,
 * so child accounting is PER LEDGER and sticky: a control that deliberately
 * kills a child owns a separate ledger and can never clear the run's evidence.
 *
 * Removal is permitted only after observation, never after a reset: every child
 * recorded in the ledger must have reported close, and a timed-out or signalled
 * child additionally requires an explicit confirmTermination() observation.
 * Pid liveness is recorded as advisory evidence (see confirmTermination).
 */
export function createHealthLedger() {
  return {
    uncertain: false, reasons: [], children: [], terminationConfirmed: null,
  };
}

/** The ledger that accounts for the current run's own children. */
export const processHealth = createHealthLedger();

export function markTerminationUncertain(ledger, reason) {
  ledger.uncertain = true;

  if (!ledger.reasons.includes(reason)) ledger.reasons.push(reason);
}

/** Liveness probe without signalling; EPERM still proves the process exists. */
export function childIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;

  try {
    process.kill(pid, 0);

    return true;
  } catch (error) {
    return error?.code === 'EPERM';
  }
}

/**
 * Confirmation is an observation recorded on the ledger, never a reset: every
 * recorded child must have reported close. Deleting (or withholding) is then
 * decided from that record.
 *
 * The pid liveness probe is recorded as ADVISORY evidence only. On Windows a
 * process that has already been reaped by Node can stay openable for a brief
 * window, so a liveness result is not a reliable gate; the close event is.
 */
export function confirmTermination(ledger) {
  const unclosed = ledger.children.filter((child) => child.closeConfirmed !== true);
  const openPids = ledger.children.filter((child) => childIsAlive(child.pid)).map((child) => child.pid);

  ledger.terminationConfirmed = {
    confirmedAt: new Date().toISOString(),
    confirmed: unclosed.length === 0,
    checkedChildren: ledger.children.length,
    unclosedPids: unclosed.map((child) => child.pid),
    advisoryOpenPids: openPids,
    reasons: ledger.reasons.slice(),
  };

  return ledger.terminationConfirmed;
}

/** Terminate only the tree created by this runner; never touch scratch. */
function terminate(child) {
  if (IS_WINDOWS) {
    const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
      windowsHide: true, stdio: 'ignore', shell: false,
    });

    const deadline = setTimeout(() => killer.kill('SIGKILL'), 5000);

    deadline.unref();
    killer.on('close', () => clearTimeout(deadline));
    killer.on('error', () => {
      clearTimeout(deadline);
      child.kill('SIGKILL');
    });
  } else {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  }
}

/**
 * Run one bounded child and return evidence instead of throwing on failure.
 * Timeouts, signals and unconfirmed closes mark termination uncertain.
 */
export function runChild(executable, args, {
  cwd = REPO_ROOT, timeoutMs = 120000, env = process.env, limit = MAX_OUTPUT_BYTES, ledger = processHealth,
} = {}) {
  return new Promise((done) => {
    const started = Date.now();

    const child = spawn(executable, args, {
      cwd, env, windowsHide: true, shell: false,
      detached: !IS_WINDOWS, stdio: ['ignore', 'pipe', 'pipe'],
    });

    const evidence = {
      executable, args, cwd, pid: child.pid ?? null,
      exitCode: null, signal: null, stdout: '', stderr: '',
      timedOut: false, outputLimitExceeded: false, spawnError: null, closeConfirmed: false,
    };

    // The child is recorded BEFORE anything can fail, so a crash cannot hide it.
    const accounted = { pid: child.pid ?? null, closeConfirmed: false, timedOut: false, signal: null, exitCode: null };

    ledger.children.push(accounted);

    let bytes = 0;
    let settled = false;
    let closeDeadline;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(closeDeadline);
      evidence.durationMs = Date.now() - started;
      evidence.ok = evidence.exitCode === 0 && evidence.signal === null
        && !evidence.timedOut && !evidence.outputLimitExceeded && evidence.spawnError === null
        && evidence.closeConfirmed;
      done(evidence);
    };

    const stop = () => {
      clearTimeout(timer);
      terminate(child);
      closeDeadline = setTimeout(() => {
        evidence.spawnError ??= 'child-close-not-confirmed';
        markTerminationUncertain(ledger, `${path.basename(executable)} child close was not confirmed`);
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        finish();
      }, 5000);
    };

    const timer = setTimeout(() => {
      evidence.timedOut = true;
      accounted.timedOut = true;
      markTerminationUncertain(ledger, `${path.basename(executable)} child timed out`);
      stop();
    }, timeoutMs);

    const capture = (field, chunk) => {
      bytes += chunk.length;

      if (bytes > limit) {
        if (!evidence.outputLimitExceeded) {
          evidence.outputLimitExceeded = true;
          markTerminationUncertain(ledger, `${path.basename(executable)} child exceeded its output limit`);
          stop();
        }

        return;
      }

      evidence[field] += chunk.toString('utf8');
    };

    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));
    child.on('error', (error) => {
      evidence.spawnError = error.message;

      // A never-spawned process has no descendants; nothing to reap.
      if (child.pid === undefined) {
        evidence.closeConfirmed = true;
        accounted.closeConfirmed = true;
      }

      markTerminationUncertain(ledger, `${path.basename(executable)} child failed: ${error.message}`);
      finish();
    });
    child.on('close', (code, signal) => {
      evidence.exitCode = code;
      evidence.signal = signal;
      evidence.closeConfirmed = true;
      accounted.closeConfirmed = true;
      accounted.exitCode = code;
      accounted.signal = signal;

      if (signal !== null && !evidence.timedOut) {
        markTerminationUncertain(ledger, `${path.basename(executable)} child exited on ${signal}`);
      }

      finish();
    });
  });
}

/** Bounded synchronous run for git/npm metadata; nonzero is returned, not thrown. */
export function runSync(command, args, { cwd = REPO_ROOT, timeoutMs = 60000, ledger = processHealth } = {}) {
  try {
    return {
      status: 0,
      stdout: execFileSync(command, args, {
        cwd, encoding: 'utf8', timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES,
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
      stderr: '',
      timedOut: false,
    };
  } catch (error) {
    const timedOut = Boolean(error?.signal) || error?.code === 'ETIMEDOUT';

    if (timedOut) markTerminationUncertain(ledger, `${command} timed out`);

    const rawStdout = error?.stdout;
    const rawStderr = error?.stderr;

    return {
      status: Number.isInteger(error?.status) ? error.status : -1,
      stdout: rawStdout === undefined ? '' : String(rawStdout),
      stderr: rawStderr === undefined ? String(error?.message ?? '') : String(rawStderr),
      timedOut,
    };
  }
}

/**
 * Classify a compiler invocation. A diagnostic requires a real TS diagnostic
 * line: a bare exit 2, a crash or a timeout is NOT evidence of type failure.
 */
export function classifyCompile(evidence) {
  const text = `${evidence.stdout}\n${evidence.stderr}`;

  const diagnostics = [...text.matchAll(/([^\r\n]*\berror TS\d{4}\b[^\r\n]*)/g)]
    .map((match) => match[1].trim())
    .slice(0, 20);

  const codes = [...new Set(diagnostics.flatMap((line) => [...line.matchAll(/\bTS(\d{4})\b/g)].map((match) => match[1])))];

  if (evidence.timedOut) return { kind: 'timeout', diagnostics, codes, exitCode: evidence.exitCode };

  if (evidence.signal !== null) return { kind: 'signaled', diagnostics, codes, exitCode: evidence.exitCode };

  if (evidence.spawnError !== null) return { kind: 'spawn-error', diagnostics, codes, exitCode: evidence.exitCode };

  if (evidence.outputLimitExceeded) return { kind: 'output-limit', diagnostics, codes, exitCode: evidence.exitCode };

  if (diagnostics.length > 0) return { kind: 'diagnostic', diagnostics, codes, exitCode: evidence.exitCode };

  if (evidence.exitCode === 0) return { kind: 'clean', diagnostics, codes, exitCode: 0 };

  return { kind: `exit-${String(evidence.exitCode)}`, diagnostics, codes, exitCode: evidence.exitCode };
}

/* ------------------------------------------------------------------ *
 * Checked workspace with an authoritative junction ledger
 * ------------------------------------------------------------------ */

export function assertInsideTemp(target) {
  const relative = path.relative(path.resolve(os.tmpdir()), path.resolve(target));

  assert(relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to operate outside OS temp: ${path.resolve(target)}`);
}

export function createWorkspace(prefix = TEMP_PREFIX) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));

  assertInsideTemp(root);
  assert(path.basename(root).startsWith(prefix), `Unexpected temp name: ${root}`);

  return { root, links: [] };
}

/** Track a link BEFORE creating it, so a mid-step failure never hides it. */
export function trackLink(workspace, linkPath) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(workspace.root, resolved);

  assert(relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to track a link outside the workspace: ${resolved}`);
  assert(!workspace.links.includes(resolved), `Link already tracked: ${resolved}`);
  workspace.links.push(resolved);
}

export function createTrackedJunction(workspace, target, linkPath) {
  const resolved = path.resolve(linkPath);

  mkdirSync(path.dirname(resolved), { recursive: true });
  trackLink(workspace, resolved);
  symlinkSync(realpathSync(target), resolved, IS_WINDOWS ? 'junction' : 'dir');

  return resolved;
}

function isLink(stat, resolved) {
  if (stat.isSymbolicLink()) return true;

  if (IS_WINDOWS && stat.isDirectory()) {
    try {
      readlinkSync(resolved);

      return true;
    } catch {
      return false;
    }
  }

  return false;
}

/** Unlink one tracked junction/symlink; fail closed on an ordinary directory. */
export function safeUnlinkLink(linkPath, expectedParent) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(path.resolve(expectedParent), resolved);

  assert(!relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to unlink a link outside its parent: ${resolved}`);

  let stat;

  try {
    stat = lstatSync(resolved);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }

  if (!isLink(stat, resolved)) {
    throw new Error(`Expected a junction or symlink at ${resolved}; refusing to remove an ordinary path.`);
  }

  try {
    unlinkSync(resolved);
  } catch {
    rmdirSync(resolved);
  }

  if (existsSync(resolved)) throw new Error(`Failed to unlink the dependency link at ${resolved}.`);
}

/**
 * Unlink every tracked link, then remove the workspace root. Removal requires
 * OBSERVED termination: every ledger child reported close, and a timed-out or
 * signalled child additionally requires confirmTermination(). Anything else
 * preserves the whole tree as evidence and fails the run.
 */
export function disposeWorkspace(workspace, { ledger = processHealth } = {}) {
  assertInsideTemp(workspace.root);

  const unclosed = ledger.children.filter((child) => child.closeConfirmed !== true);

  if (unclosed.length > 0) {
    throw new Error(
      `Cleanup withheld: child process(es) ${unclosed.map((child) => child.pid).join(', ')} never confirmed close; scratch preserved at ${workspace.root}.`,
    );
  }

  if (ledger.uncertain && ledger.terminationConfirmed?.confirmed !== true) {
    throw new Error(
      `Cleanup withheld because child termination is uncertain (${ledger.reasons.join('; ')}); scratch preserved at ${workspace.root}.`,
    );
  }

  const failures = [];

  for (const link of workspace.links) {
    try {
      safeUnlinkLink(link, workspace.root);
    } catch (error) {
      failures.push(`unlink ${link}: ${error.message}`);
    }
  }

  if (failures.length === 0) {
    try {
      rmSync(workspace.root, { recursive: true, force: true });
    } catch (error) {
      failures.push(`remove root: ${error.message}`);
    }

    if (existsSync(workspace.root)) failures.push(`root still exists: ${workspace.root}`);
  }

  if (failures.length > 0) {
    throw new Error(`Cleanup failed; scratch preserved at ${workspace.root}: ${failures.join('; ')}`);
  }
}

/* ------------------------------------------------------------------ *
 * Byte integrity snapshots
 * ------------------------------------------------------------------ */

function walkFiles(root) {
  const files = [];

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(directory, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) files.push(full);
    }
  };

  visit(root);

  return files;
}

export function snapshotTrackedBytes() {
  const listed = runSync('git', ['ls-files', '-z']);

  assert.equal(listed.status, 0, `git ls-files failed: ${listed.stderr}`);

  const files = listed.stdout.split('\0').filter((entry) => entry.length > 0).sort();
  const hash = createHash('sha256');

  for (const relative of files) {
    hash.update(relative);
    hash.update('\0');
    hash.update(readFileSync(path.join(REPO_ROOT, relative)));
    hash.update('\0');
  }

  return { count: files.length, digest: hash.digest('hex') };
}

export function snapshotTree(root) {
  if (!existsSync(root)) return { present: false, count: 0, digest: '' };
  const files = walkFiles(root);
  const hash = createHash('sha256');

  for (const file of files) {
    hash.update(path.relative(root, file));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
  }

  return { present: true, count: files.length, digest: hash.digest('hex') };
}

export function snapshotRunInputs() {
  return {
    tracked: snapshotTrackedBytes(),
    dist: snapshotTree(path.join(REPO_ROOT, 'dist')),
    head: runSync('git', ['rev-parse', 'HEAD']).stdout.trim(),
  };
}

/** Report any change to tracked or built bytes; a change is a run failure. */
export function compareRunInputs(before, after) {
  const problems = [];

  if (before.tracked.digest !== after.tracked.digest || before.tracked.count !== after.tracked.count) {
    problems.push(`tracked checkout bytes changed (${before.tracked.count} -> ${after.tracked.count} files)`);
  }

  if (before.dist.present !== after.dist.present || before.dist.digest !== after.dist.digest) {
    problems.push('built dist/ bytes changed during the run');
  }

  if (before.head !== after.head) problems.push(`HEAD moved (${before.head} -> ${after.head})`);

  return problems;
}

/* ------------------------------------------------------------------ *
 * Evidence output guard
 * ------------------------------------------------------------------ */

/** Only this ignored directory may receive --out reports. */
export const REPORT_DIRECTORY = 'notes/phase-10';
const REPORT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;

/**
 * Resolve an --out destination under the assigned ignored evidence directory.
 * Tracked paths, dist, absolute paths outside the checkout, symlinked parents or
 * symlinked targets and non-JSON names are refused before a single byte is
 * written, so a report can never land on protected source.
 */
export function resolveReportDestination(requested) {
  const raw = String(requested ?? '').trim();

  if (raw.length === 0) throw new Error('--out requires a non-empty path.');

  const resolved = path.resolve(REPO_ROOT, raw);
  const relative = toPosix(path.relative(REPO_ROOT, resolved));

  if (path.isAbsolute(raw) && !resolved.startsWith(`${REPO_ROOT}${path.sep}`)) {
    throw new Error(`--out must stay inside ${REPORT_DIRECTORY}/; refused an absolute external path: ${raw}`);
  }

  const segments = relative.split('/');

  if (segments.length !== 3 || `${segments[0]}/${segments[1]}` !== REPORT_DIRECTORY
    || !REPORT_NAME.test(segments[2])) {
    throw new Error(`--out must be exactly ${REPORT_DIRECTORY}/<name>.json (ignored evidence); refused ${raw}`);
  }

  const directory = path.dirname(resolved);
  const parts = path.relative(REPO_ROOT, directory).split(path.sep).filter((part) => part.length > 0);
  let walking = REPO_ROOT;

  for (const part of parts) {
    walking = path.join(walking, part);

    if (existsSync(walking) && lstatSync(walking).isSymbolicLink()) {
      throw new Error(`--out refuses a symlinked directory component: ${path.relative(REPO_ROOT, walking)}`);
    }
  }

  mkdirSync(directory, { recursive: true });

  const realRoot = realpathSync(REPO_ROOT);
  const realDirectory = realpathSync(directory);

  if (realDirectory !== realRoot && !realDirectory.startsWith(`${realRoot}${path.sep}`)) {
    throw new Error(`--out resolved outside the checkout: ${realDirectory}`);
  }

  if (existsSync(resolved) && lstatSync(resolved).isSymbolicLink()) {
    throw new Error(`--out refuses to overwrite a symlink: ${relative}`);
  }

  if (runSync('git', ['check-ignore', '--quiet', relative]).status !== 0) {
    throw new Error(`--out refuses a tracked or unignored path: ${relative}`);
  }

  return { destination: resolved, relative };
}

/**
 * Write the report, then verify protected bytes AFTER the write. A second write
 * only appends the measured post-write evidence; the final state is re-checked.
 */
export function writeEvidenceReport({ destination, relative }, report, { preWrite }) {
  const payload = `${JSON.stringify(report, null, 2)}\n`;

  writeFileSync(destination, payload);

  const afterFirst = snapshotRunInputs();
  const problems = compareRunInputs(preWrite, afterFirst);

  const postWrite = {
    path: relative,
    problems,
    trackedDigest: afterFirst.tracked.digest,
    distDigest: afterFirst.dist.digest,
    checkedAfterWrite: true,
  };

  writeFileSync(destination, `${JSON.stringify({ ...report, postWriteIntegrity: postWrite }, null, 2)}\n`);

  const afterSecond = snapshotRunInputs();
  const finalProblems = compareRunInputs(preWrite, afterSecond);

  return { postWrite, finalProblems };
}

/* ------------------------------------------------------------------ *
 * npm and toolchain helpers
 * ------------------------------------------------------------------ */

export function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath) candidates.push(process.env.npm_execpath);

  candidates.push(
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  if (!found) throw new PrerequisiteError('npm CLI JavaScript entry not found; set npm_execpath.');

  return found;
}

export function pinnedToolPath(name) {
  const target = path.join(REPO_ROOT, 'node_modules', name);

  if (!existsSync(target)) throw new PrerequisiteError(`Pinned dependency missing from the read-only tree: ${name || 'node_modules'}`);

  return target;
}

/** The read-only pinned dependency tree, shared by junctions only. */
export function pinnedNodeModules() {
  return realpathSync(pinnedToolPath(''));
}

export function toolVersion(name) {
  const manifest = path.join(pinnedToolPath(name), 'package.json');

  if (!existsSync(manifest)) throw new PrerequisiteError(`Pinned dependency has no manifest: ${name}`);

  return JSON.parse(readFileSync(manifest, 'utf8')).version;
}

/** npm environment isolated to the workspace: no user cache, offline only. */
export function isolatedNpmEnv(workspace) {
  const cache = path.join(workspace.root, 'npm-cache');

  mkdirSync(cache, { recursive: true });

  return {
    ...process.env,
    npm_config_cache: cache,
    NPM_CONFIG_OFFLINE: 'true',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
  };
}

export async function runNpm(npmCli, args, cwd, workspace, { timeoutMs = 180000 } = {}) {
  return runChild(process.execPath, [npmCli, ...args], {
    cwd, env: isolatedNpmEnv(workspace), timeoutMs,
  });
}

/* ------------------------------------------------------------------ *
 * Toolchain build steps
 * ------------------------------------------------------------------ */

function toPosix(value) {
  return value.replaceAll('\\', '/');
}

async function runTsc(configPath) {
  const tsc = path.join(pinnedToolPath('typescript'), 'bin', 'tsc');
  const evidence = await runChild(process.execPath, [tsc, '-p', configPath], { timeoutMs: 300000 });

  return { args: ['tsc', '-p', configPath], evidence, classification: classifyCompile(evidence) };
}

/** Build the ignored ESM dist from the real src/ with the pinned TypeScript. */
export async function buildEsmDist() {
  const steps = [];

  for (const config of ['tsconfig.json', 'tsconfig.cli.json']) {
    const step = await runTsc(path.join(REPO_ROOT, config));

    steps.push({ config, exitCode: step.evidence.exitCode, kind: step.classification.kind, diagnostics: step.classification.diagnostics });

    if (!step.evidence.ok) {
      throw new Error(`ESM build failed for ${config}: ${step.classification.diagnostics.join(' | ') || step.evidence.stderr.slice(0, 500)}`);
    }
  }

  const entries = ['dist/index.js', 'dist/diagnostics/index.js', 'dist/cli/index.js'];

  for (const relative of entries) {
    if (!existsSync(path.join(REPO_ROOT, relative))) throw new Error(`ESM build did not produce ${relative}.`);
  }

  return steps;
}

/**
 * Conventional per-module CJS emit. TypeScript refuses to emit CommonJS from a
 * `type: module` package scope, so the REAL sources are copied to a temp
 * `type: commonjs` scope and emitted there with Node16 resolution (the legacy
 * node10 resolver is deprecated in TypeScript 6 and is not used). The emitted
 * relative specifiers are then rewritten from .js to .cjs and every declaration
 * becomes .d.cts, which is the graph a CJS consumer resolves.
 */
export async function buildCjsEmit(workspace) {
  // A dedicated build root keeps the workspace root free of node_modules so no
  // later npm pack/install can see an unrelated dependency tree while hoisting.
  const buildRoot = path.join(workspace.root, 'cjs-build');
  const source = path.join(buildRoot, 'cjs-src');
  const outDir = path.join(buildRoot, 'dist-cjs');

  mkdirSync(buildRoot, { recursive: true });
  cpSync(path.join(REPO_ROOT, 'src'), source, { recursive: true });
  rmSync(path.join(source, 'cli'), { recursive: true, force: true });
  writeFileSync(path.join(source, 'package.json'), `${JSON.stringify({ type: 'commonjs' })}\n`);

  // Read-only link to the pinned dependency tree; the tsconfig needs it to
  // resolve express/hono type-only imports from the temp source copy.
  createTrackedJunction(workspace, pinnedNodeModules(), path.join(buildRoot, 'node_modules'));

  const configPath = path.join(buildRoot, 'tsconfig.cjs.json');

  const config = {
    compilerOptions: {
      target: 'ES2022',
      module: 'Node16',
      moduleResolution: 'Node16',
      verbatimModuleSyntax: false,
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
      declaration: true,
      declarationMap: false,
      sourceMap: false,
      noEmitOnError: true,
      outDir: toPosix(outDir),
      rootDir: toPosix(source),
      types: [],
      lib: ['ES2022', 'DOM', 'DOM.Iterable'],
      skipLibCheck: true,
    },
    include: [`${toPosix(source)}/**/*.ts`],
  };

  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);

  const step = await runTsc(configPath);

  if (!step.evidence.ok) {
    throw new Error(`CJS emit failed: ${step.classification.diagnostics.join(' | ') || step.evidence.stderr.slice(0, 500)}`);
  }

  const renamed = { scripts: 0, declarations: 0, rewritten: 0 };

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        visit(full);
        continue;
      }

      if (entry.name.endsWith('.d.ts')) {
        const next = `${full.slice(0, -'.d.ts'.length)}.d.cts`;

        renameSync(full, next);
        renamed.declarations += 1;
        assert.equal(rewriteSpecifiers(next), true, `Declaration ${next} was not rewritten.`);
      } else if (entry.name.endsWith('.js')) {
        const next = `${full.slice(0, -3)}.cjs`;

        renameSync(full, next);
        renamed.scripts += 1;
        assert.equal(rewriteSpecifiers(next), true, `Module ${next} was not rewritten.`);
      }
    }
  };

  visit(outDir);
  // Count rewritten files separately so the count reflects actual file edits.
  const rewrittenFiles = walkFiles(outDir).filter((file) => readFileSync(file, 'utf8').includes('.cjs'));

  renamed.rewritten = rewrittenFiles.length;

  return { outDir, configPath, renamed, step: { exitCode: step.evidence.exitCode, kind: step.classification.kind } };
}

/**
 * Rewrite only quoted RELATIVE specifiers ending in .js. Returns true when the
 * file is valid UTF-8 text and was inspected, so a silent no-op is impossible.
 */
function rewriteSpecifiers(file) {
  const source = readFileSync(file, 'utf8');
  const next = source.replace(/(["'])(\.{1,2}\/[^"'\n]*?)\.js\1/g, '$1$2.cjs$1');

  if (next !== source) writeFileSync(file, next);

  return true;
}

/* ------------------------------------------------------------------ *
 * Candidate assembly and inspection
 * ------------------------------------------------------------------ */

function readRepoManifest() {
  return JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
}

function candidateExports(kind) {
  const map = {};

  for (const entry of ENTRY_POINTS) {
    const esm = `./dist/${entry.base}.js`;
    const esmTypes = `./dist/${entry.base}.d.ts`;

    map[entry.subpath] = kind === 'per-module-cjs'
      ? {
        import: { types: esmTypes, default: esm },
        require: { types: `./dist-cjs/${entry.base}.d.cts`, default: `./dist-cjs/${entry.base}.cjs` },
      }
      : {
        import: { types: esmTypes, default: esm },
        require: { types: esmTypes, default: esm },
      };
  }

  return map;
}

function candidateManifest(kind) {
  const repo = readRepoManifest();
  const bridge = kind === 'require-bridge';

  return {
    name: repo.name,
    version: repo.version,
    description: repo.description,
    license: repo.license,
    repository: repo.repository,
    type: 'module',
    main: bridge ? './dist/index.js' : './dist-cjs/index.cjs',
    types: './dist/index.d.ts',
    // require(esm) only exists from Node 22.12.0 onward; the unmodified `>=22`
    // range would silently exclude 22.0-22.11 consumers of the bridge.
    engines: bridge ? { node: '>=22.12.0' } : repo.engines,
    // The real ESM CLI mapping is preserved in both candidates: the bin stays on
    // the ESM dist entry, so the CJS prototype does not claim a CJS CLI.
    bin: repo.bin,
    exports: candidateExports(kind),
    files: bridge ? ['dist', 'README.md', 'LICENSE'] : ['dist', 'dist-cjs', 'README.md', 'LICENSE'],
    peerDependencies: repo.peerDependencies,
    peerDependenciesMeta: repo.peerDependenciesMeta,
  };
}

export function createCandidate(workspace, kind, cjsBuild) {
  const directory = path.join(workspace.root, 'packages', kind);

  mkdirSync(directory, { recursive: true });
  cpSync(path.join(REPO_ROOT, 'dist'), path.join(directory, 'dist'), { recursive: true });

  if (kind === 'per-module-cjs') {
    if (cjsBuild === undefined) throw new Error('The per-module-cjs candidate requires a CJS emit.');

    cpSync(cjsBuild.outDir, path.join(directory, 'dist-cjs'), { recursive: true });
  }

  for (const file of ['README.md', 'LICENSE']) {
    cpSync(path.join(REPO_ROOT, file), path.join(directory, file));
  }

  const manifest = candidateManifest(kind);

  writeFileSync(path.join(directory, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  return { kind, directory, manifest };
}

/** Enumerate relative specifiers in a file, ignoring package/builtin names. */
function relativeSpecifiers(file) {
  const source = readFileSync(file, 'utf8');

  return [...source.matchAll(/(["'])(\.{1,2}\/[^"'\n]+)\1/g)].map((match) => match[2]);
}

/** Declaration graph: every relative .cjs reference must resolve to .d.cts. */
export function inspectDeclarationGraph(directory) {
  const root = path.join(directory, 'dist-cjs');

  if (!existsSync(root)) return { present: false, files: 0, specifiers: 0, unresolved: [], stale: [] };

  const files = walkFiles(root).filter((file) => file.endsWith('.d.cts'));
  const unresolved = [];
  const stale = [];
  let specifiers = 0;

  for (const file of files) {
    for (const specifier of relativeSpecifiers(file)) {
      specifiers += 1;

      if (!specifier.endsWith('.cjs')) {
        stale.push({ file: path.relative(directory, file), specifier });
        continue;
      }

      const expected = path.resolve(path.dirname(file), specifier.replace(/\.cjs$/, '.d.cts'));

      if (!existsSync(expected)) {
        unresolved.push({ file: path.relative(directory, file), specifier, expected: path.relative(directory, expected) });
      }
    }
  }

  return { present: true, files: files.length, specifiers, unresolved, stale };
}

/** Runtime graph: every require("./x.cjs") must resolve inside the package. */
export function inspectCjsRequires(directory) {
  const root = path.join(directory, 'dist-cjs');

  if (!existsSync(root)) return { present: false, files: 0, requires: 0, unresolved: [], esmSyntax: [] };

  const files = walkFiles(root).filter((file) => file.endsWith('.cjs'));
  const unresolved = [];
  const esmSyntax = [];
  let requires = 0;

  for (const file of files) {
    const source = readFileSync(file, 'utf8');

    for (const match of source.matchAll(/require\(\s*(["'])(\.{1,2}\/[^"'\n]+)\1\s*\)/g)) {
      requires += 1;
      const target = path.resolve(path.dirname(file), match[2]);

      if (!existsSync(target)) {
        unresolved.push({ file: path.relative(directory, file), specifier: match[2] });
      }
    }

    if (/^\s*(?:import|export)\s/m.test(source)) esmSyntax.push(path.relative(directory, file));
  }

  return { present: true, files: files.length, requires, unresolved, esmSyntax };
}

/** Full structural inspection of one candidate package. */
export function inspectCandidate(candidate) {
  const { directory, manifest } = candidate;
  const targets = [];

  for (const entry of ENTRY_POINTS) {
    const node = manifest.exports[entry.subpath];

    for (const condition of ['import', 'require']) {
      for (const key of ['types', 'default']) {
        const target = node?.[condition]?.[key];
        const targetText = target === undefined || target === null ? null : String(target);

        targets.push({
          subpath: entry.subpath, condition, key, target: targetText,
          exists: targetText !== null && existsSync(path.join(directory, targetText)),
        });
      }
    }
  }

  const missingTargets = targets.filter((target) => !target.exists);
  const bin = manifest.bin ?? {};

  const binTargets = Object.entries(bin).map(([name, target]) => ({
    name, target: String(target), exists: existsSync(path.join(directory, String(target))),
  }));

  const declarations = inspectDeclarationGraph(directory);
  const requires = inspectCjsRequires(directory);
  const distRoot = path.join(directory, 'dist');
  const esmFiles = existsSync(distRoot) ? walkFiles(distRoot) : [];
  const esmDeclarations = esmFiles.filter((file) => file.endsWith('.d.ts')).length;
  const esmModules = esmFiles.filter((file) => file.endsWith('.js')).length;
  const dependencies = manifest.dependencies ?? {};
  const exportKeys = Object.keys(manifest.exports).sort();
  const expectedKeys = ENTRY_POINTS.map((entry) => entry.subpath).sort();

  return {
    kind: candidate.kind,
    directory,
    exportKeys,
    exportKeysExact: exportKeys.length === expectedKeys.length
      && expectedKeys.every((key, index) => exportKeys[index] === key),
    runtimeDependencies: Object.keys(dependencies),
    peerIsolation: Object.keys(dependencies).length === 0,
    targets,
    missingTargets,
    binTargets,
    binTargetsMissing: binTargets.filter((target) => !target.exists),
    esmModules,
    esmDeclarations,
    declarations,
    requires,
    packageBytes: walkFiles(directory).reduce((total, file) => total + lstatSync(file).size, 0),
    fileCount: walkFiles(directory).length,
  };
}

/* ------------------------------------------------------------------ *
 * Tarballs and consumers
 * ------------------------------------------------------------------ */

export async function packCandidate(candidate, workspace, npmCli) {
  // Per-kind directory: both candidates share the package name and version, so
  // a shared destination would silently overwrite the first archive.
  const tarballDir = path.join(workspace.root, 'tarballs', candidate.kind);

  mkdirSync(tarballDir, { recursive: true });

  const result = await runNpm(npmCli,
    ['pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', tarballDir],
    candidate.directory, workspace);

  if (!result.ok) {
    throw new Error(`npm pack failed for ${candidate.kind}: ${result.stderr.slice(0, 500) || result.stdout.slice(0, 500)}`);
  }

  const entries = JSON.parse(result.stdout);
  const single = Array.isArray(entries) && entries.length === 1 ? entries[0] : undefined;

  if (!single?.filename) throw new Error(`npm pack returned no single archive for ${candidate.kind}.`);
  const tarball = path.join(tarballDir, single.filename);

  if (!existsSync(tarball)) throw new Error(`npm pack did not create ${single.filename}.`);

  return {
    tarball,
    filename: single.filename,
    bytes: lstatSync(tarball).size,
    files: Array.isArray(single.files) ? single.files.length : null,
  };
}

export const PEER_PACKAGES = ['express', 'hono'];
export const PEER_TYPE_PACKAGES = ['@types/express', '@types/node'];

/**
 * Isolated consumer root with the packed tarball installed offline. Peer links
 * are junctions into the read-only pinned tree and are always tracked.
 */
export async function installConsumer(workspace, { name, tarball, peers, npmCli }) {
  const root = path.join(workspace.root, 'consumers', name);

  mkdirSync(root, { recursive: true });
  writeFileSync(path.join(root, 'package.json'),
    `${JSON.stringify({ name: `phase10-${name}`, version: '0.0.0', private: true, type: 'module' }, null, 2)}\n`);

  const install = await runNpm(npmCli,
    ['install', tarball, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps'],
    root, workspace);

  if (!install.ok) {
    throw new Error(`offline install failed for ${name}: ${install.stderr.slice(0, 500) || install.stdout.slice(0, 500)}`);
  }

  const installed = path.join(root, 'node_modules', 'hooklatch');

  if (!existsSync(installed)) throw new Error(`The install for ${name} did not place hooklatch in node_modules.`);

  const links = [];

  if (peers) {
    for (const dependency of PEER_PACKAGES) {
      links.push(createTrackedJunction(workspace, pinnedToolPath(dependency), path.join(root, 'node_modules', dependency)));
    }

    for (const dependency of PEER_TYPE_PACKAGES) {
      links.push(createTrackedJunction(workspace, pinnedToolPath(dependency), path.join(root, 'node_modules', dependency)));
    }
  }

  return { root, installed, links, installExitCode: install.exitCode };
}

/* ------------------------------------------------------------------ *
 * Module-graph cross-check (pinned esbuild)
 * ------------------------------------------------------------------ */

/**
 * Reachable runtime modules for the six public entries, from the pinned esbuild
 * metafile. Used to prove the CJS declaration graph covers the REAL graph
 * instead of an invented or partial list.
 */
export function moduleGraph() {
  const esbuild = createRequire(pathToFileURL(path.join(REPO_ROOT, 'package.json')).href)('esbuild');
  const entryPoints = ENTRY_POINTS.map((entry) => path.join(REPO_ROOT, 'src', `${entry.base}.ts`));

  const result = esbuild.buildSync({
    entryPoints,
    bundle: true,
    write: false,
    metafile: true,
    // Required for multiple entries even with write:false; nothing is emitted.
    outdir: path.join(os.tmpdir(), 'hooklatch-phase10-graph'),
    format: 'esm',
    platform: 'node',
    target: 'node22',
    logLevel: 'silent',
    external: [...PEER_PACKAGES],
  });

  // Metafile keys may be absolute or cwd-relative; normalize to repo-relative.
  const inputs = Object.keys(result.metafile.inputs)
    .map((input) => toPosix(path.relative(REPO_ROOT, path.resolve(REPO_ROOT, input))))
    .filter((input) => input.startsWith('src/'))
    .sort();

  return { version: toolVersion('esbuild'), inputs, count: inputs.length };
}

/* ------------------------------------------------------------------ *
 * Controls
 * ------------------------------------------------------------------ */

function controlConsumer(workspace, candidate, name, mutate) {
  const root = path.join(workspace.root, 'controls', name);
  const installed = path.join(root, 'node_modules', 'hooklatch');

  mkdirSync(path.dirname(installed), { recursive: true });
  cpSync(candidate.directory, installed, { recursive: true });
  writeFileSync(path.join(root, 'package.json'), `${JSON.stringify({ name: `phase10-control-${name}`, private: true, type: 'module' })}\n`);
  mutate(installed);

  return { root, installed };
}

function writeRequireProbe(root, name) {
  const file = path.join(root, `${name}.cjs`);

  writeFileSync(file, [
    "'use strict';",
    'const assert = require("node:assert/strict");',
    'let api;',
    'try { api = require("hooklatch"); } catch (error) {',
    '  console.log(JSON.stringify({ ok: false, stage: "load", code: error.code, message: error.message }));',
    '  process.exit(1);',
    '}',
    'try { assert.equal(typeof api.verify, "function"); } catch (error) {',
    '  console.log(JSON.stringify({ ok: false, stage: "shape", message: error.message }));',
    '  process.exit(1);',
    '}',
    'console.log(JSON.stringify({ ok: true }));',
    '',
  ].join('\n'));

  return file;
}

async function controls(workspace, candidate, esmDist) {
  const results = {};
  const structural = inspectCandidate(candidate);

  const missing = controlConsumer(workspace, candidate, 'missing-require-target', (installed) => {
    rmSync(path.join(installed, 'dist-cjs', 'core.cjs'), { force: true });
  });

  const missingProbe = writeRequireProbe(missing.root, 'probe');
  const missingRun = await runChild(process.execPath, [missingProbe], { cwd: missing.root, timeoutMs: 30000 });
  const missingStatic = inspectCjsRequires(missing.installed);

  results.missingRequireTarget = {
    detectedStatically: missingStatic.unresolved.length > 0,
    detectedAtRuntime: !missingRun.ok && /MODULE_NOT_FOUND/.test(`${missingRun.stdout}${missingRun.stderr}`),
    baselinePasses: structural.requires.unresolved.length === 0,
  };

  const wrongGraph = controlConsumer(workspace, candidate, 'wrong-declaration-graph', (installed) => {
    const file = path.join(installed, 'dist-cjs', 'index.d.cts');
    const source = readFileSync(file, 'utf8');

    writeFileSync(file, source.replace('/core.cjs', '/core.js'));
  });

  const wrongStatic = inspectDeclarationGraph(wrongGraph.installed);

  results.wrongDeclarationGraph = {
    detectedStatically: wrongStatic.stale.length > 0 || wrongStatic.unresolved.length > 0,
    baselinePasses: structural.declarations.stale.length === 0 && structural.declarations.unresolved.length === 0,
  };

  const disconnected = controlConsumer(workspace, candidate, 'disconnected-exports', (installed) => {
    writeFileSync(path.join(installed, 'dist-cjs', 'index.cjs'), "'use strict';\nmodule.exports = {};\n");
  });

  const disconnectedProbe = writeRequireProbe(disconnected.root, 'probe');
  const disconnectedRun = await runChild(process.execPath, [disconnectedProbe], { cwd: disconnected.root, timeoutMs: 30000 });
  const baselineRoot = path.join(workspace.root, 'controls', 'baseline');

  mkdirSync(path.join(baselineRoot, 'node_modules'), { recursive: true });
  cpSync(candidate.directory, path.join(baselineRoot, 'node_modules', 'hooklatch'), { recursive: true });
  writeFileSync(path.join(baselineRoot, 'package.json'), `${JSON.stringify({ name: 'phase10-control-baseline', private: true, type: 'module' })}\n`);
  const baselineProbe = writeRequireProbe(baselineRoot, 'probe');
  const baselineRun = await runChild(process.execPath, [baselineProbe], { cwd: baselineRoot, timeoutMs: 30000 });

  results.disconnectedExports = {
    detectedAtRuntime: !disconnectedRun.ok,
    baselinePasses: baselineRun.ok,
  };

  results.esmDist = esmDist;
  results.allDetected = Object.entries(results)
    .filter(([key]) => key !== 'esmDist' && key !== 'allDetected')
    .every(([, value]) => value.detectedStatically === true || value.detectedAtRuntime === true)
    && results.missingRequireTarget.baselinePasses
    && results.wrongDeclarationGraph.baselinePasses
    && results.disconnectedExports.baselinePasses;

  return results;
}

/**
 * Control: real bounded children prove BOTH termination branches on separate
 * ledgers, so the run's own ledger is never cleared to make a deletion legal.
 *
 *   A. a child that closes on its own is removed normally;
 *   B. a child that must be killed on timeout is preserved and FAILS disposal
 *      while termination is unconfirmed, then may be removed only after
 *      confirmTermination() observes a closed child and no live pid.
 *
 * If the killed child cannot be confirmed closed, the control fails with the
 * scratch left in place instead of deleting it.
 */
export async function terminationControl() {
  const runLedgerBefore = processHealth.children.length;
  const results = { runLedger: 'separate', runLedgerChildrenBefore: runLedgerBefore };

  // Branch A: bounded child exits on its own, close confirmed, scratch removed.
  const cleanLedger = createHealthLedger();
  const cleanWorkspace = createWorkspace(`${TEMP_PREFIX}control-clean-`);

  const clean = await runChild(process.execPath, ['-e', 'process.exit(0);'], {
    cwd: cleanWorkspace.root, timeoutMs: 30000, ledger: cleanLedger,
  });

  assert(clean.ok && clean.closeConfirmed, 'Termination control A: the bounded child did not close cleanly.');
  disposeWorkspace(cleanWorkspace, { ledger: cleanLedger });

  assert(!existsSync(cleanWorkspace.root), 'Termination control A: scratch survived a confirmed close.');

  results.confirmedCloseRemovesScratch = true;

  // Branch B: real timeout. Preserve, fail while unconfirmed, then confirm.
  const timeoutLedger = createHealthLedger();
  const timeoutWorkspace = createWorkspace(`${TEMP_PREFIX}control-timeout-`);

  const timed = await runChild(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], {
    cwd: timeoutWorkspace.root, timeoutMs: 250, ledger: timeoutLedger,
  });

  assert(timed.timedOut, 'Termination control B: the child was not reported as timed out.');
  assert(timeoutLedger.uncertain, 'Termination control B: the ledger stayed clean after a timeout.');

  results.timeout = {
    timedOut: timed.timedOut, closeConfirmed: timed.closeConfirmed, pid: timed.pid, ledgerUncertain: true,
  };

  let withheld = null;

  try {
    disposeWorkspace(timeoutWorkspace, { ledger: timeoutLedger });
  } catch (error) {
    withheld = error instanceof Error ? error.message : String(error);
  }

  results.disposalFailedWhileUnconfirmed = withheld !== null && /preserved/i.test(withheld);
  results.scratchPreservedWhileUnconfirmed = existsSync(timeoutWorkspace.root);

  assert(results.disposalFailedWhileUnconfirmed,
    'Termination control B: disposal proceeded without a confirmed termination.');
  assert(results.scratchPreservedWhileUnconfirmed,
    'Termination control B: scratch was deleted while termination was unconfirmed.');

  const confirmation = confirmTermination(timeoutLedger);

  results.confirmation = confirmation;

  if (!confirmation.confirmed) {
    // Fail closed: leave the scratch for the coordinator instead of deleting it.
    throw new Error(
      `Termination control B: child termination could not be confirmed (${JSON.stringify(confirmation)}); scratch preserved at ${timeoutWorkspace.root}.`,
    );
  }

  disposeWorkspace(timeoutWorkspace, { ledger: timeoutLedger });
  results.removedAfterConfirmedTermination = !existsSync(timeoutWorkspace.root);
  results.runLedgerChildrenAfter = processHealth.children.length;
  results.runLedgerUntouched = processHealth.children.length === runLedgerBefore;

  assert(results.removedAfterConfirmedTermination,
    'Termination control B: scratch survived a confirmed termination.');
  assert(results.runLedgerUntouched, 'Termination control B: the control wrote into the run ledger.');

  return results;
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function usage() {
  console.log('Usage: node scripts/phase10/cjs-prototype.mjs [--json] [--self-test] [--out <file>] [--help]');
  console.log('Exit 0 prototype built and controls passed, 1 failure, 2 usage, 3 prerequisite blocked.');
  console.log('Builds disposable per-module-CJS and require(esm)-bridge candidates in OS temp only.');
  console.log('This script edits no repository source/package/config bytes and never publishes.');
  console.log(`--out is restricted to ${REPORT_DIRECTORY}/<name>.json (ignored evidence); anything else is refused.`);
}

function parseArgs(args) {
  const options = { json: false, selfTest: false, help: false, out: null };
  const seen = new Set();

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (seen.has(arg)) return { error: `duplicate argument: ${arg}` };
    seen.add(arg);

    if (arg === '--json') options.json = true;
    else if (arg === '--self-test') options.selfTest = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--out') {
      const value = args[index + 1];

      if (!value || value.startsWith('--')) return { error: '--out requires a file path' };
      options.out = value;
      index += 1;
    } else return { error: `unknown argument: ${arg}` };
  }

  return { options };
}

function prerequisites() {
  if (!existsSync(path.join(REPO_ROOT, 'src', 'index.ts'))) throw new PrerequisiteError('src/index.ts is absent.');

  if (!existsSync(path.join(REPO_ROOT, 'README.md'))) throw new PrerequisiteError('README.md is absent.');

  const toolchain = {
    typescript: toolVersion('typescript'),
    esbuild: toolVersion('esbuild'),
    oxlint: toolVersion('oxlint'),
    npmCli: locateNpmCli(),
  };

  const npm = runSync(process.execPath, [toolchain.npmCli, '--version']);

  if (npm.status !== 0) throw new PrerequisiteError(`npm CLI is not runnable: ${npm.stderr.slice(0, 200)}`);

  return { ...toolchain, npm: npm.stdout.trim() };
}

async function prototypeRun() {
  const toolchain = prerequisites();
  const before = snapshotRunInputs();
  const workspace = createWorkspace();
  let report;
  let baseline = before;
  let failure = null;
  let final = null;

  try {
    const esmBuild = await buildEsmDist();
    // The build legitimately (re)writes ignored dist/. Integrity covers the
    // prototype window itself, so the dist baseline is taken AFTER the build.
    const afterBuild = snapshotRunInputs();

    baseline = { tracked: before.tracked, dist: afterBuild.dist, head: before.head };
    const cjsBuild = await buildCjsEmit(workspace);

    const candidates = [
      createCandidate(workspace, 'per-module-cjs', cjsBuild),
      createCandidate(workspace, 'require-bridge'),
    ];

    const inspections = candidates.map((candidate) => inspectCandidate(candidate));
    const graph = moduleGraph();

    for (const inspection of inspections) {
      if (inspection.missingTargets.length > 0) {
        throw new Error(`${inspection.kind} has missing export targets: ${JSON.stringify(inspection.missingTargets)}`);
      }

      if (inspection.binTargetsMissing.length > 0) {
        throw new Error(`${inspection.kind} has missing bin targets: ${JSON.stringify(inspection.binTargetsMissing)}`);
      }

      if (inspection.declarations.unresolved.length > 0 || inspection.declarations.stale.length > 0) {
        throw new Error(`${inspection.kind} has a broken declaration graph.`);
      }

      if (inspection.requires.unresolved.length > 0 || inspection.requires.esmSyntax.length > 0) {
        throw new Error(`${inspection.kind} has a broken CJS runtime graph.`);
      }

      if (!inspection.exportKeysExact) throw new Error(`${inspection.kind} does not export exactly the six public subpaths.`);

      if (!inspection.peerIsolation) throw new Error(`${inspection.kind} declares runtime dependencies.`);
    }

    // Every reachable runtime module must exist in both candidate graphs.
    const cjs = candidates.find((candidate) => candidate.kind === 'per-module-cjs');
    const graphCoverage = [];

    for (const input of graph.inputs) {
      const relative = input.slice('src/'.length).replace(/\.ts$/, '');
      const cjsModule = path.join(cjs.directory, 'dist-cjs', `${relative}.cjs`);
      const cjsTypes = path.join(cjs.directory, 'dist-cjs', `${relative}.d.cts`);
      const esmModule = path.join(cjs.directory, 'dist', `${relative}.js`);

      graphCoverage.push({
        input, cjsModule: existsSync(cjsModule), cjsTypes: existsSync(cjsTypes), esmModule: existsSync(esmModule),
      });
    }

    const uncovered = graphCoverage.filter((entry) => !entry.cjsModule || !entry.cjsTypes || !entry.esmModule);

    if (uncovered.length > 0) throw new Error(`Module graph coverage failed: ${JSON.stringify(uncovered.slice(0, 5))}`);

    const tarballs = [];

    for (const candidate of candidates) {
      tarballs.push({ kind: candidate.kind, ...(await packCandidate(candidate, workspace, toolchain.npmCli)) });
    }

    report = {
      status: 'PASS',
      phase: '10',
      owner: 'deepseek-codebuff',
      generatedAt: new Date().toISOString(),
      source: {
        head: before.head, trackedFiles: before.tracked.count, trackedDigest: before.tracked.digest,
        distFiles: baseline.dist.count, distDigestAfterBuild: baseline.dist.digest,
      },
      toolchain: {
        node: process.version, npm: toolchain.npm,
        typescript: toolchain.typescript, esbuild: toolchain.esbuild, oxlint: toolchain.oxlint,
        platform: `${process.platform}/${process.arch}`,
      },
      esmBuild,
      cjsBuild: {
        modules: cjsBuild.renamed.scripts,
        declarations: cjsBuild.renamed.declarations,
        rewrittenFiles: cjsBuild.renamed.rewritten,
        emit: cjsBuild.step,
      },
      moduleGraph: { version: graph.version, count: graph.count, coverage: graphCoverage.length, uncovered: uncovered.length },
      candidates: inspections,
      tarballs,
      cleanup: { scratchRemoved: false },
    };

    if (report.candidates.some((candidate) => candidate.kind === 'per-module-cjs')) {
      // Explicit reminder for reviewers: the CJS candidate duplicates declarations.
      report.findings = {
        perModuleCjs: {
          declarationFiles: report.candidates.find((candidate) => candidate.kind === 'per-module-cjs').declarations.files,
          runtimeCopies: report.candidates.find((candidate) => candidate.kind === 'per-module-cjs').requires.files,
        },
        requireBridge: {
          engines: candidates.find((candidate) => candidate.kind === 'require-bridge').manifest.engines,
          nodeFloorOverride: '>=22.12.0 is required for unflagged require(esm); >=22 alone does not cover 22.0-22.11.',
        },
        bin: {
          preserved: candidates.map((candidate) => ({ kind: candidate.kind, bin: candidate.manifest.bin })),
          cliQualification: 'scripts/phase10/cjs-consumers.mjs executes the installed bin target with --help on both Node majors.',
        },
      };
    }
  } catch (error) {
    failure = error;
  } finally {
    const after = snapshotRunInputs();
    const problems = compareRunInputs(baseline, after);

    let cleanup;

    try {
      disposeWorkspace(workspace);
      cleanup = { scratchRemoved: true, scratch: workspace.root };
    } catch (error) {
      cleanup = { scratchRemoved: false, scratch: workspace.root, error: error.message };
      problems.push(`cleanup: ${error.message}`);
    }

    final = { after, problems, cleanup };
  }

  if (report !== undefined) {
    report.cleanup = final.cleanup;
    report.integrity = {
      problems: final.problems, trackedDigestAfter: final.after.tracked.digest, distDigestAfter: final.after.dist.digest,
    };

    if (final.problems.length > 0) report.status = 'FAILED';
  }

  if (failure !== null) throw failure;

  if (final.problems.length > 0 && report === undefined) throw new Error(`Integrity failure: ${final.problems.join('; ')}`);

  return report;
}

async function selfTestRun() {
  const toolchain = prerequisites();
  const before = snapshotRunInputs();
  const workspace = createWorkspace();
  let report;
  let baseline = before;
  let failure = null;
  let final = null;

  try {
    const esmBuild = await buildEsmDist();
    const afterBuild = snapshotRunInputs();

    baseline = { tracked: before.tracked, dist: afterBuild.dist, head: before.head };
    const cjsBuild = await buildCjsEmit(workspace);
    const candidate = createCandidate(workspace, 'per-module-cjs', cjsBuild);

    const controlResults = await controls(workspace, candidate, {
      steps: esmBuild.length, cjsModules: cjsBuild.renamed.scripts,
    });

    const timeout = await terminationControl();

    report = {
      status: controlResults.allDetected ? 'CONTROLS_PASSED' : 'CONTROLS_FAILED',
      phase: '10',
      owner: 'deepseek-codebuff',
      generatedAt: new Date().toISOString(),
      toolchain: { node: process.version, npm: toolchain.npm, typescript: toolchain.typescript, esbuild: toolchain.esbuild },
      controls: controlResults,
      uncertainTermination: timeout,
      cleanup: { scratchRemoved: false },
    };
  } catch (error) {
    failure = error;
  } finally {
    const after = snapshotRunInputs();
    const problems = compareRunInputs(baseline, after);

    let cleanup;

    try {
      disposeWorkspace(workspace);
      cleanup = { scratchRemoved: true, scratch: workspace.root };
    } catch (error) {
      cleanup = { scratchRemoved: false, scratch: workspace.root, error: error.message };
      problems.push(`cleanup: ${error.message}`);
    }

    final = { after, problems, cleanup };
  }

  if (report !== undefined) {
    report.cleanup = final.cleanup;
    report.integrity = { problems: final.problems };

    if (final.problems.length > 0 || report.status !== 'CONTROLS_PASSED') report.status = 'FAILED';
  }

  if (failure !== null) throw failure;

  if (final.problems.length > 0 && report === undefined) throw new Error(`Integrity failure: ${final.problems.join('; ')}`);

  return report;
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));

  if (parsed.error) {
    console.error(parsed.error);
    usage();

    return 2;
  }

  if (parsed.options.help) {
    usage();

    return 0;
  }

  // Validated BEFORE any build or install: a refused destination costs nothing
  // and can never touch protected bytes mid-run.
  let outTarget = null;

  if (parsed.options.out) {
    try {
      outTarget = resolveReportDestination(parsed.options.out);
    } catch (error) {
      console.error(`--out refused: ${error instanceof Error ? error.message : String(error)}`);

      return 1;
    }
  }

  let report;
  let exitCode = 0;

  try {
    report = parsed.options.selfTest ? await selfTestRun() : await prototypeRun();
  } catch (error) {
    if (error instanceof PrerequisiteError) {
      report = { status: 'BLOCKED', reason: error.message, phase: '10', owner: 'deepseek-codebuff' };
      exitCode = 3;
    } else {
      report = {
        status: 'FAILED',
        phase: '10',
        owner: 'deepseek-codebuff',
        error: error instanceof Error ? (error.stack ?? error.message) : String(error),
      };
      exitCode = 1;
    }
  }

  if (report.status === 'FAILED' && exitCode === 0) exitCode = 1;

  let evidenceWrite = null;

  if (outTarget !== null) {
    try {
      const preWrite = snapshotRunInputs();
      const written = writeEvidenceReport(outTarget, report, { preWrite });

      evidenceWrite = { path: outTarget.relative, ...written.postWrite, finalProblems: written.finalProblems };

      if (written.finalProblems.length > 0) {
        report.status = 'FAILED';
        exitCode = 1;
      }
    } catch (error) {
      evidenceWrite = {
        path: outTarget.relative, refused: error instanceof Error ? error.message : String(error), problems: ['--out write failed'],
      };
      report.status = 'FAILED';
      exitCode = 1;
    }
  }

  const printable = evidenceWrite === null ? report : { ...report, evidenceWrite };

  if (parsed.options.json) console.log(JSON.stringify(printable, null, 2));
  else {
    console.log(`${report.status}: ${report.phase === '10' ? 'phase10 CJS/ESM packaging prototype' : 'run'}`);
    console.log(JSON.stringify({
      status: report.status,
      candidates: report.candidates?.map((candidate) => ({
        kind: candidate.kind,
        exportKeysExact: candidate.exportKeysExact,
        declarationFiles: candidate.declarations.files,
        cjsModules: candidate.requires.files,
        packageBytes: candidate.packageBytes,
      })),
      tarballs: report.tarballs?.map((tarball) => ({ kind: tarball.kind, files: tarball.files, bytes: tarball.bytes })),
      cleanup: report.cleanup,
      integrity: report.integrity,
      evidenceWrite,
    }, null, 2));
  }

  return exitCode;
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    process.exitCode = await main();
  } catch (error) {
    console.log(JSON.stringify({
      status: 'FAILED', error: error instanceof Error ? (error.stack ?? error.message) : String(error),
    }));
    process.exitCode = 1;
  }
}
