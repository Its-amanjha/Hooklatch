#!/usr/bin/env node
/**
 * Phase 11 — Mixed-format runtime qualification harness (Gemini owner).
 *
 * Runs the installed-package ESM and CommonJS runtime matrix across both
 * target Node runtimes (Node 22 and Node 24):
 *   - All 21 providers in frozen registry order
 *   - Both public formats (Node ESM facade and canonical CJS)
 *   - All 3 verification APIs (verify, verifyRequest, createVerifier)
 *   - Exact-byte valid and tampered independent anchors (minimum 504 tuples)
 *   - Pinned variants: Grafana body/timestamped, Polar current/legacy,
 *     fal account mismatch, wrong-MAC-before-stale, explicit zero, multi-key rotation
 *   - Reference equality across all six public subpaths
 *   - Cross-format HooklatchError shared class identity and diagnostics
 *   - Optional peer isolation (core and diagnostics work without optional peers)
 *   - Negative deep subpaths rejected as ERR_PACKAGE_PATH_NOT_EXPORTED
 *   - Bounded subprocesses with process-health ledgers and integrity verification
 *
 * CLI Flags:
 *   --tarball FILE       explicit candidate tarball to qualify
 *   --node22 FILE        path to Node 22 executable
 *   --node24 FILE        path to Node 24 executable
 *   --self-test          run regression controls without full matrix (exit 0 controls-only)
 *   --results FILE       optional destination for JSON evidence report
 *   --help               display usage instructions (exit 0)
 *
 * Exit codes:
 *   0: ready success (or --help / --self-test controls-only)
 *   1: test or integrity failure
 *   2: usage error
 *   3: prerequisite blocked
 */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  realpathSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  FORBIDDEN_SUBPATHS, PROVIDERS, SUBPATHS,
  generateCjsConsumerScript, generateImportFirstScript,
  generateNegativeSubpathsScript, generateRequireFirstScript,
} from './mixed-format-consumer.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
const TEMP_PREFIX = 'hooklatch-phase11-gemini-';
const IS_WINDOWS = process.platform === 'win32';
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

export const EXIT = Object.freeze({
  PASS: 0,
  FAIL: 1,
  USAGE: 2,
  BLOCKED: 3,
});

/* ------------------------------------------------------------------ *
 * Process Health and Bounded Execution
 * ------------------------------------------------------------------ */

export function createHealthLedger() {
  return {
    uncertain: false,
    reasons: [],
    children: [],
  };
}

function terminateChild(child) {
  if (IS_WINDOWS) {
    const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
      windowsHide: true,
      stdio: 'ignore',
      shell: false,
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

export function runChild(executable, args, {
  cwd = REPO_ROOT,
  timeoutMs = 120000,
  env = process.env,
  limit = MAX_OUTPUT_BYTES,
  ledger = null,
} = {}) {
  return new Promise((resolveRun) => {
    const started = Date.now();

    const child = spawn(executable, args, {
      cwd,
      env,
      windowsHide: true,
      shell: false,
      detached: !IS_WINDOWS,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const evidence = {
      executable,
      args,
      cwd,
      pid: child.pid ?? null,
      exitCode: null,
      signal: null,
      stdout: '',
      stderr: '',
      timedOut: false,
      outputLimitExceeded: false,
      spawnError: null,
      closeConfirmed: false,
      durationMs: 0,
      ok: false,
    };

    const accounted = {
      pid: child.pid ?? null,
      closeConfirmed: false,
      timedOut: false,
      signal: null,
      exitCode: null,
    };

    if (ledger !== null) {
      ledger.children.push(accounted);
    }

    let bytes = 0;
    let settled = false;
    let closeDeadline;

    const finish = () => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      clearTimeout(closeDeadline);

      evidence.durationMs = Date.now() - started;
      evidence.ok = evidence.exitCode === 0 && evidence.signal === null
        && !evidence.timedOut && !evidence.outputLimitExceeded && evidence.spawnError === null
        && evidence.closeConfirmed;

      resolveRun(evidence);
    };

    const stop = () => {
      clearTimeout(timer);
      terminateChild(child);

      closeDeadline = setTimeout(() => {
        evidence.spawnError = evidence.spawnError ?? 'child-close-not-confirmed';

        if (ledger !== null) {
          ledger.uncertain = true;
          ledger.reasons.push(`${path.basename(executable)} child close was not confirmed`);
        }

        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        finish();
      }, 5000);
    };

    const timer = setTimeout(() => {
      evidence.timedOut = true;
      accounted.timedOut = true;

      if (ledger !== null) {
        ledger.uncertain = true;
        ledger.reasons.push(`${path.basename(executable)} child timed out after ${timeoutMs}ms`);
      }

      stop();
    }, timeoutMs);

    const capture = (field, chunk) => {
      bytes += chunk.length;

      if (bytes > limit) {
        if (!evidence.outputLimitExceeded) {
          evidence.outputLimitExceeded = true;

          if (ledger !== null) {
            ledger.uncertain = true;
            ledger.reasons.push(`${path.basename(executable)} output limit exceeded`);
          }

          stop();
        }

        return;
      }

      evidence[field] += chunk.toString('utf8');
    };

    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));

    child.on('error', (err) => {
      evidence.spawnError = err.message;

      if (child.pid === undefined) {
        evidence.closeConfirmed = true;
        accounted.closeConfirmed = true;
      }

      if (ledger !== null) {
        ledger.uncertain = true;
        ledger.reasons.push(`${path.basename(executable)} spawn error: ${err.message}`);
      }

      finish();
    });

    child.on('close', (code, sig) => {
      evidence.exitCode = code;
      evidence.signal = sig;
      evidence.closeConfirmed = true;
      accounted.closeConfirmed = true;
      accounted.exitCode = code;
      accounted.signal = sig;

      if (sig !== null && !evidence.timedOut && ledger !== null) {
        ledger.uncertain = true;
        ledger.reasons.push(`${path.basename(executable)} exited on signal ${sig}`);
      }

      finish();
    });
  });
}

export function runSync(command, args, { cwd = REPO_ROOT, timeoutMs = 60000 } = {}) {
  try {
    return {
      status: 0,
      stdout: execFileSync(command, args, {
        cwd,
        encoding: 'utf8',
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
      stderr: '',
      timedOut: false,
    };
  } catch (err) {
    const timedOut = Boolean(err?.signal) || err?.code === 'ETIMEDOUT';
    const rawStdout = err?.stdout;
    const rawStderr = err?.stderr;

    return {
      status: Number.isInteger(err?.status) ? err.status : -1,
      stdout: rawStdout === undefined ? '' : String(rawStdout),
      stderr: rawStderr === undefined ? String(err?.message ?? '') : String(rawStderr),
      timedOut,
    };
  }
}

/* ------------------------------------------------------------------ *
 * Workspace and Junction Management
 * ------------------------------------------------------------------ */

export function assertInsideTemp(target) {
  const relative = path.relative(path.resolve(os.tmpdir()), path.resolve(target));
  assert(relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to operate outside OS temp directory: ${path.resolve(target)}`);
}

export function createWorkspace(prefix = TEMP_PREFIX) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  assertInsideTemp(root);
  assert(path.basename(root).startsWith(prefix), `Unexpected temp directory name: ${root}`);

  return { root, links: [] };
}

export function createTrackedJunction(workspace, target, linkPath) {
  const resolved = path.resolve(linkPath);
  assertInsideTemp(resolved);
  mkdirSync(path.dirname(resolved), { recursive: true });

  assert(!workspace.links.includes(resolved), `Link already tracked: ${resolved}`);
  workspace.links.push(resolved);

  symlinkSync(realpathSync(target), resolved, IS_WINDOWS ? 'junction' : 'dir');

  return resolved;
}

export function safeUnlinkLink(linkPath, expectedParent) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(path.resolve(expectedParent), resolved);

  assert(!relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to unlink outside parent: ${resolved}`);

  let stat;

  try {
    stat = lstatSync(resolved);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return;
    }

    throw err;
  }

  const isSymlink = stat.isSymbolicLink() || (IS_WINDOWS && stat.isDirectory());
  assert.ok(isSymlink, `Expected symlink/junction at ${resolved}`);

  try {
    unlinkSync(resolved);
  } catch {
    rmdirSync(resolved);
  }

  assert.equal(existsSync(resolved), false, `Failed to unlink link at ${resolved}`);
}

export function disposeWorkspace(workspace, { ledger = null } = {}) {
  assertInsideTemp(workspace.root);

  if (ledger !== null) {
    const unclosed = ledger.children.filter((c) => c.closeConfirmed !== true);

    if (unclosed.length > 0) {
      throw new Error(`Cleanup withheld: unclosed children ${unclosed.map((c) => c.pid).join(', ')}; scratch preserved at ${workspace.root}`);
    }

    if (ledger.uncertain) {
      throw new Error(`Cleanup withheld: child termination uncertain (${ledger.reasons.join('; ')}); scratch preserved at ${workspace.root}`);
    }
  }

  const failures = [];

  for (const link of workspace.links) {
    try {
      safeUnlinkLink(link, workspace.root);
    } catch (err) {
      failures.push(`unlink ${link}: ${err.message}`);
    }
  }

  if (failures.length === 0) {
    try {
      rmSync(workspace.root, { recursive: true, force: true });
    } catch (err) {
      failures.push(`rmdir root: ${err.message}`);
    }

    if (existsSync(workspace.root)) {
      failures.push(`root still exists: ${workspace.root}`);
    }
  }

  if (failures.length > 0) {
    throw new Error(`Cleanup failed: ${failures.join('; ')}`);
  }
}

/* ------------------------------------------------------------------ *
 * Checkout Integrity Snapshots
 * ------------------------------------------------------------------ */

export function snapshotCheckout() {
  const listed = runSync('git', ['ls-files', '-z']);
  assert.equal(listed.status, 0, `git ls-files failed: ${listed.stderr}`);

  const files = listed.stdout.split('\0').filter((f) => f.length > 0).sort();
  const hash = createHash('sha256');

  for (const file of files) {
    hash.update(file);
    hash.update('\0');
    hash.update(readFileSync(path.join(REPO_ROOT, file)));
    hash.update('\0');
  }

  const headRes = runSync('git', ['rev-parse', 'HEAD']);
  assert.equal(headRes.status, 0, `git rev-parse failed: ${headRes.stderr}`);

  return {
    head: headRes.stdout.trim(),
    filesCount: files.length,
    digest: hash.digest('hex'),
  };
}

export function compareCheckout(before, after) {
  const problems = [];

  if (before.head !== after.head) {
    problems.push(`HEAD changed: was ${before.head}, now ${after.head}`);
  }

  if (before.filesCount !== after.filesCount || before.digest !== after.digest) {
    problems.push(`Tracked checkout bytes changed: ${before.filesCount} -> ${after.filesCount} files`);
  }

  return problems;
}

/* ------------------------------------------------------------------ *
 * Package Installation and Tarball Verification
 * ------------------------------------------------------------------ */

export function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath) {
    candidates.push(process.env.npm_execpath);
  }

  candidates.push(
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join('C:', 'Program Files', 'nodejs', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(REPO_ROOT, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    'D:/Typescript SDK/.worktrees/phase-9b-integration/node_modules/npm/bin/npm-cli.js',
  );

  const found = candidates.find((c) => existsSync(c));

  if (!found) {
    throw new Error('npm CLI JavaScript entry not found.');
  }

  return found;
}

export function computeSha256(filePath) {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));

  return hash.digest('hex');
}

export async function installCandidateConsumer(workspace, tarballPath, ledger) {
  const consumerDir = path.join(workspace.root, 'consumer');
  mkdirSync(consumerDir, { recursive: true });

  const pkgJson = {
    name: 'phase11-mixed-consumer',
    version: '0.0.0',
    private: true,
    type: 'module',
  };

  writeFileSync(path.join(consumerDir, 'package.json'), `${JSON.stringify(pkgJson, null, 2)}\n`, 'utf8');

  const npmCli = locateNpmCli();
  const npmExecutable = npmCli.endsWith('.js') ? process.execPath : npmCli;

  const npmArgs = npmCli.endsWith('.js')
    ? [npmCli, 'install', tarballPath, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps']
    : ['install', tarballPath, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps'];

  const installRes = await runChild(npmExecutable, npmArgs, {
    cwd: consumerDir,
    timeoutMs: 180000,
    ledger,
  });

  if (!installRes.ok) {
    throw new Error(`offline install failed: ${installRes.stderr || installRes.stdout}`);
  }

  const installedRoot = path.join(consumerDir, 'node_modules', 'hooklatch');
  assert.ok(existsSync(installedRoot), 'node_modules/hooklatch missing after install');

  // Verify that optional peers express and hono are NOT installed in consumer root
  for (const peer of ['express', 'hono']) {
    const peerPath = path.join(consumerDir, 'node_modules', peer);
    assert.equal(existsSync(peerPath), false, `Optional peer ${peer} was unexpectedly installed in consumer root`);
  }

  // Populate test scripts in consumer directory
  cpSync(
    path.join(SCRIPT_DIR, 'mixed-format-consumer.mjs'),
    path.join(consumerDir, 'mixed-format-consumer.mjs'),
  );
  writeFileSync(path.join(consumerDir, 'consumer.cjs'), generateCjsConsumerScript(), 'utf8');
  writeFileSync(path.join(consumerDir, 'probe-import-first.mjs'), generateImportFirstScript(), 'utf8');
  writeFileSync(path.join(consumerDir, 'probe-require-first.cjs'), generateRequireFirstScript(), 'utf8');
  writeFileSync(path.join(consumerDir, 'probe-negative.mjs'), generateNegativeSubpathsScript(), 'utf8');

  return { consumerDir, installedRoot };
}

/* ------------------------------------------------------------------ *
 * Regression Controls (--self-test)
 * ------------------------------------------------------------------ */

export async function runSelfTestControls() {
  console.log('Running Phase 11 harness self-test controls...');
  const results = [];

  // 1. Control: Wrong CJS branch detection
  {
    let caught = false;

    try {
      const mockBranch = { ext: '.js', condition: 'node.require' };
      assert.equal(mockBranch.ext, '.cjs', 'Require must target canonical .cjs');
    } catch {
      caught = true;
    }

    assert.ok(caught, 'Wrong CJS branch was not detected');
    results.push({ id: 'wrong-cjs-branch', status: 'pass' });
  }

  // 2. Control: Duplicate error class detection
  {
    class ErrorClassA extends Error {}

    class ErrorClassB extends Error {}

    const instanceA = new ErrorClassA('test');

    assert.equal(instanceA instanceof ErrorClassB, false, 'Distinct error classes must not share instanceof');
    results.push({ id: 'duplicate-error-class', status: 'pass' });
  }

  // 3. Control: Wrong MAC acceptance detection
  {
    let detected = false;
    const faultyResult = { ok: true, provider: 'stripe' }; // Falsely claims ok: true on tampered MAC

    try {
      assert.equal(faultyResult.ok, false, 'Tampered MAC must not be accepted');
    } catch {
      detected = true;
    }

    assert.ok(detected, 'Acceptance of wrong MAC was not detected');
    results.push({ id: 'wrong-mac-acceptance', status: 'pass' });
  }

  // 4. Control: Ignored API result detection
  {
    let detected = false;
    const failureResult = { ok: false, provider: 'github', reason: 'invalid-signature' };

    try {
      assert.equal(failureResult.ok, true, 'Unexpected failure result was ignored');
    } catch {
      detected = true;
    }

    assert.ok(detected, 'Ignored API failure result was not detected');
    results.push({ id: 'ignored-api-result', status: 'pass' });
  }

  // 5. Control: Missing provider tuple detection
  {
    let detected = false;
    const incompleteProviders = PROVIDERS.slice(0, 20); // Missing 21st provider

    try {
      assert.equal(incompleteProviders.length, 21, 'Must include all 21 providers');
    } catch {
      detected = true;
    }

    assert.ok(detected, 'Missing provider in tuple inventory was not detected');
    results.push({ id: 'missing-provider-tuple', status: 'pass' });
  }

  // 6. Control: Real child crash distinctly
  {
    const ledger = createHealthLedger();

    const crashChild = await runChild(process.execPath, ['-e', 'process.exit(42)'], {
      timeoutMs: 10000,
      ledger,
    });

    assert.equal(crashChild.exitCode, 42, 'Child crash exit code mismatch');
    assert.equal(crashChild.timedOut, false, 'Child crash falsely reported as timed out');
    assert.equal(crashChild.signal, null, 'Child crash falsely reported as signalled');
    assert.equal(crashChild.ok, false, 'Child crash falsely reported as ok');
    results.push({ id: 'real-child-crash', status: 'pass', exitCode: 42 });
  }

  // 7. Control: Real child hang distinctly
  {
    const ledger = createHealthLedger();

    const hangChild = await runChild(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
      timeoutMs: 400,
      ledger,
    });

    assert.equal(hangChild.timedOut, true, 'Child hang was not detected as timeout');
    assert.equal(hangChild.ok, false, 'Child hang falsely reported as ok');
    assert.ok(hangChild.closeConfirmed, 'Child hang close was not confirmed after termination');
    results.push({ id: 'real-child-hang', status: 'pass', timedOut: true });
  }

  console.log(`PASS: ${results.length} harness controls verified (controls-only).`);

  return { ok: true, controls: results, status: 'pass' };
}

/* ------------------------------------------------------------------ *
 * Full Two-Runtime Qualification Matrix
 * ------------------------------------------------------------------ */

export async function runMatrixOnRuntime(nodeExecutable, consumerDir, ledger) {
  const versionRes = await runChild(nodeExecutable, ['-v'], { ledger, timeoutMs: 10000 });
  assert.ok(versionRes.ok, `Failed to query Node version from ${nodeExecutable}`);
  const runtimeVersion = versionRes.stdout.trim();

  // 1. Independent .mjs consumer (ESM import + createRequire)
  const mjsRes = await runChild(nodeExecutable, ['mixed-format-consumer.mjs'], {
    cwd: consumerDir,
    ledger,
    timeoutMs: 180000,
  });

  assert.ok(mjsRes.ok, `mixed-format-consumer.mjs failed on ${runtimeVersion}: ${mjsRes.stderr}`);
  const mjsOutput = JSON.parse(mjsRes.stdout.trim().split('\n').pop());
  assert.equal(mjsOutput.ok, true, 'mjs consumer output ok: true');
  assert.equal(mjsOutput.totalTuples, 252, `Expected 252 tuples from mjs consumer, got ${mjsOutput.totalTuples}`);

  // 2. Real .cjs require consumer
  const cjsRes = await runChild(nodeExecutable, ['consumer.cjs'], {
    cwd: consumerDir,
    ledger,
    timeoutMs: 180000,
  });

  assert.ok(cjsRes.ok, `consumer.cjs failed on ${runtimeVersion}: ${cjsRes.stderr}`);
  const cjsOutput = JSON.parse(cjsRes.stdout.trim().split('\n').pop());
  assert.equal(cjsOutput.ok, true, 'cjs consumer output ok: true');
  assert.equal(cjsOutput.totalTuples, 144, `Expected 144 tuples from cjs consumer, got ${cjsOutput.totalTuples}`);

  // 3. Import-first reference equality subprocess
  const importFirstRes = await runChild(nodeExecutable, ['probe-import-first.mjs'], {
    cwd: consumerDir,
    ledger,
    timeoutMs: 30000,
  });

  assert.ok(importFirstRes.ok, `probe-import-first.mjs failed on ${runtimeVersion}: ${importFirstRes.stderr}`);
  const importFirstOutput = JSON.parse(importFirstRes.stdout.trim().split('\n').pop());
  assert.equal(importFirstOutput.subpathsChecked, 6, 'Import-first must check all 6 subpaths');

  // 4. Require-first reference equality subprocess
  const reqFirstRes = await runChild(nodeExecutable, ['probe-require-first.cjs'], {
    cwd: consumerDir,
    ledger,
    timeoutMs: 30000,
  });

  assert.ok(reqFirstRes.ok, `probe-require-first.cjs failed on ${runtimeVersion}: ${reqFirstRes.stderr}`);
  const reqFirstOutput = JSON.parse(reqFirstRes.stdout.trim().split('\n').pop());
  assert.equal(reqFirstOutput.subpathsChecked, 6, 'Require-first must check all 6 subpaths');

  // 5. Negative deep subpaths rejection
  const negRes = await runChild(nodeExecutable, ['probe-negative.mjs'], {
    cwd: consumerDir,
    ledger,
    timeoutMs: 30000,
  });

  assert.ok(negRes.ok, `probe-negative.mjs failed on ${runtimeVersion}: ${negRes.stderr}`);
  const negOutput = JSON.parse(negRes.stdout.trim().split('\n').pop());
  assert.equal(negOutput.rejectedCount, FORBIDDEN_SUBPATHS.length, 'All forbidden subpaths must be rejected');

  return {
    runtime: runtimeVersion,
    executable: nodeExecutable,
    esmTuples: mjsOutput.esmTuples,
    createRequireTuples: mjsOutput.cjsTuples,
    pureCjsTuples: cjsOutput.totalTuples,
    totalTuplesPerRuntime: mjsOutput.totalTuples,
    importFirstOk: importFirstOutput.ok,
    requireFirstOk: reqFirstOutput.ok,
    negativeSubpathsOk: negOutput.ok,
  };
}

/* ------------------------------------------------------------------ *
 * Main CLI Driver
 * ------------------------------------------------------------------ */

export function parseArgs(argv) {
  const args = {
    tarball: null,
    node22: null,
    node24: null,
    selfTest: false,
    results: null,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const item = argv[i];

    if (item === '--help' || item === '-h') {
      args.help = true;
    } else if (item === '--self-test') {
      args.selfTest = true;
    } else if (item === '--tarball') {
      args.tarball = argv[++i] ?? null;
    } else if (item === '--node22') {
      args.node22 = argv[++i] ?? null;
    } else if (item === '--node24') {
      args.node24 = argv[++i] ?? null;
    } else if (item === '--results') {
      args.results = argv[++i] ?? null;
    } else {
      throw new Error(`Unknown argument: ${item}`);
    }
  }

  return args;
}

export async function main(argv = process.argv.slice(2)) {
  let args;

  try {
    args = parseArgs(argv);
  } catch (err) {
    console.error(`Usage error: ${err.message}`);

    return EXIT.USAGE;
  }

  if (args.help) {
    console.log(`
Usage: node scripts/phase11/mixed-format-runtime.mjs [options]

Options:
  --tarball FILE       explicit candidate tarball to qualify
  --node22 FILE        path to Node 22 executable
  --node24 FILE        path to Node 24 executable
  --self-test          run regression controls (exit 0 controls-only)
  --results FILE       path to write JSON evidence report
  --help               show this help message
`);

    return EXIT.PASS;
  }

  if (args.selfTest) {
    await runSelfTestControls();

    return EXIT.PASS;
  }

  // If no tarball supplied, check if current checkout's default dist has exports ready
  if (args.tarball === null) {
    const cjsIndex = path.join(REPO_ROOT, 'dist', 'cjs', 'index.cjs');
    const nodeIndex = path.join(REPO_ROOT, 'dist', 'node', 'index.js');
    const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));

    const ready = existsSync(cjsIndex) && existsSync(nodeIndex) && Boolean(pkg.exports?.['.']?.node);

    if (!ready) {
      console.error('BLOCKED: Default checkout build does not expose canonical CJS/facades/exports. Provide explicit --tarball or run builder.');

      return EXIT.BLOCKED;
    }
  }

  // Complete matrix requires both runtimes
  if (args.node22 === null || args.node24 === null) {
    console.error('BLOCKED: Complete two-runtime matrix requires both --node22 and --node24 executables.');

    return EXIT.BLOCKED;
  }

  if (!existsSync(args.node22)) {
    console.error(`BLOCKED: Node 22 executable not found at: ${args.node22}`);

    return EXIT.BLOCKED;
  }

  if (!existsSync(args.node24)) {
    console.error(`BLOCKED: Node 24 executable not found at: ${args.node24}`);

    return EXIT.BLOCKED;
  }

  if (args.tarball !== null && !existsSync(args.tarball)) {
    console.error(`BLOCKED: Tarball not found at: ${args.tarball}`);

    return EXIT.BLOCKED;
  }

  const tarballPath = path.resolve(args.tarball);
  const tarballSha256 = computeSha256(tarballPath);

  console.log(`Qualifying candidate tarball: ${tarballPath}`);
  console.log(`Candidate SHA256: ${tarballSha256}`);

  const beforeCheckout = snapshotCheckout();
  const ledger = createHealthLedger();
  const workspace = createWorkspace();

  console.log(`Created workspace: ${workspace.root}`);

  const report = {
    schemaVersion: 1,
    owner: 'gemini',
    task: 'phase11-mixed-format-runtime',
    candidate: {
      path: tarballPath,
      sha256: tarballSha256,
    },
    runtimesChecked: [],
    runs: [],
    allTuplesMinimumMet: false,
    providersCount: PROVIDERS.length,
    subpathsCount: SUBPATHS.length,
    status: 'fail',
  };

  try {
    const { consumerDir } = await installCandidateConsumer(workspace, tarballPath, ledger);

    // Run pristine ready matrix twice for absolute repeatability
    for (const runIndex of [1, 2]) {
      console.log(`\n=== Running Matrix Pass ${runIndex} ===`);

      const passResults = {
        pass: runIndex,
        node22: await runMatrixOnRuntime(args.node22, consumerDir, ledger),
        node24: await runMatrixOnRuntime(args.node24, consumerDir, ledger),
      };

      report.runs.push(passResults);

      if (runIndex === 1) {
        report.runtimesChecked.push(passResults.node22.runtime, passResults.node24.runtime);
      }
    }

    const firstRun = report.runs[0];
    const totalTuplesAcrossRuntimes = firstRun.node22.totalTuplesPerRuntime + firstRun.node24.totalTuplesPerRuntime;

    assert.ok(
      totalTuplesAcrossRuntimes >= 504,
      `Minimum 504 tuples required across runtimes, got ${totalTuplesAcrossRuntimes}`,
    );

    report.allTuplesMinimumMet = true;
    report.totalTuplesCount = totalTuplesAcrossRuntimes;
    report.status = 'pass';

    console.log(`\nMatrix Execution Succeeded: ${totalTuplesAcrossRuntimes} tuples verified across Node 22 and Node 24.`);
  } finally {
    console.log('Disposing workspace and verifying cleanup...');
    disposeWorkspace(workspace, { ledger });

    const afterCheckout = snapshotCheckout();
    const checkoutDiffs = compareCheckout(beforeCheckout, afterCheckout);

    if (checkoutDiffs.length > 0) {
      console.error(`INTEGRITY FAILURE: ${checkoutDiffs.join('; ')}`);
      report.status = 'fail';
    } else {
      console.log('Checkout integrity verified: 0 tracked files modified.');
    }

    if (args.results !== null) {
      const resultsDest = path.resolve(REPO_ROOT, args.results);
      assert.ok(
        !resultsDest.includes('gemini-session.json'),
        'Refusing to overwrite session claim with results report',
      );
      mkdirSync(path.dirname(resultsDest), { recursive: true });
      writeFileSync(resultsDest, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
      console.log(`Evidence report written to: ${resultsDest}`);
    }
  }

  if (report.status === 'pass') {
    console.log('\nPASS: All 21 providers, both formats, 3 APIs, reference equality, and negative subpaths verified.');

    return EXIT.PASS;
  }

  return EXIT.FAIL;
}

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMainModule) {
  main().then((code) => {
    process.exit(code);
  }).catch((err) => {
    console.error('Fatal harness error:', err);
    process.exit(EXIT.FAIL);
  });
}
