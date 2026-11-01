#!/usr/bin/env node
/**
 * Phase 13 release-candidate controls (Claude owner). HARNESS-ONLY: nothing
 * here qualifies a product artifact.
 *
 * Two families, both against the real scripts/phase13/release-candidate.mjs:
 *
 *   cli/*      bounded subprocesses of the real CLI: help/usage/duplicate/
 *              unknown/incompatible arguments (2), default and partial input
 *              BLOCKED (3) with no stage directory or temp entry created,
 *              wrong artifact and wrong runtime (1) before any gate runs, and
 *              --results overwrite/tracked/claim/outside/linked-ancestor guards.
 *   harness/*  runQualification() with the exported command seam pointing
 *              every stage at an isolated fake gate child in an OS-temp
 *              workspace. The production validators, classification,
 *              aggregation, archive hashing, integrity and temp-leftover
 *              checks run unchanged; only the child script differs, and every
 *              such result is labelled `harness-*` / controlsOnly.
 *
 * Fake children write production-shaped reports from syntheticReport(). The
 * control workspace is created with the reviewed Phase 11 workspace helper and
 * disposed through it; uncertain child termination preserves it.
 *
 * Usage: node scripts/phase13/release-candidate-controls.mjs [--help]
 * Exit: 0 every control passed, 1 a control failed, 2 usage.
 */
import { randomUUID } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, readdirSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { gzipSync } from 'node:zlib';
import {
  assertInsideTemp, createHealthLedger, createWorkspace, disposeWorkspace, runChild, runSync,
} from '../phase11/mixed-format-runtime.mjs';
import {
  EXIT, REPO_ROOT, STAGE_IDS, hooklatchTempEntries, runQualification, sha256File, syntheticReport,
} from './release-candidate.mjs';

const CLI = path.join(REPO_ROOT, 'scripts', 'phase13', 'release-candidate.mjs');
const LEAK_PREFIX = 'hooklatch-phase13-rc-leak-';
const CONTROL_PREFIX = 'hooklatch-phase13-rc-controls-';
const HANG_TIMEOUT_MS = 3000;

const FAKE_GATE = `import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const [behaviorFile, ...args] = process.argv.slice(2);
const behavior = JSON.parse(readFileSync(behaviorFile, 'utf8'));
const out = args[args.indexOf('--results') + 1];
const tarball = args[args.indexOf('--tarball') + 1];
if (behavior.mutateArtifact) appendFileSync(tarball, 'x');
if (behavior.leakTemp) mkdtempSync(path.join(os.tmpdir(), ${JSON.stringify(LEAK_PREFIX)}));
if (behavior.report !== null) writeFileSync(out, JSON.stringify(behavior.report));
if (behavior.hang) setInterval(() => {}, 1000);
else process.exit(behavior.exit);
`;

function usage() {
  return 'Usage: node scripts/phase13/release-candidate-controls.mjs [--help]\nHarness-only controls for scripts/phase13/release-candidate.mjs. Exit: 0 all pass, 1 failure, 2 usage.';
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function assertThat(condition, message) {
  if (!condition) throw new Error(message);
}

function processGone(pid) {
  try {
    process.kill(pid, 0);

    return false;
  } catch (error) {
    return error.code === 'ESRCH';
  }
}

/* ------------------------------------------------------------------ *
 * CLI controls (real script, bounded subprocesses)
 * ------------------------------------------------------------------ */

async function cli(args, ledger) {
  const run = await runChild(process.execPath, [CLI, ...args], { cwd: REPO_ROOT, timeoutMs: 120000, ledger });

  assertThat(run.closeConfirmed && !run.timedOut && run.signal === null, `cli child not cleanly closed: ${JSON.stringify(args)}`);

  return run;
}

function scratchDirs() {
  const notes = path.join(REPO_ROOT, 'notes');

  return existsSync(notes) ? readdirSync(notes).filter((name) => name.startsWith('.release-candidate-')) : [];
}

async function cliControls(workspace, ledger, control) {
  const host = process.execPath;
  const textFile = path.join(workspace.root, 'not-an-archive.tgz');
  const gzipFile = path.join(workspace.root, 'synthetic.tgz');
  const runsDir = path.join(REPO_ROOT, 'notes', `.rc-controls-${randomUUID()}`);

  writeFileSync(textFile, 'plain text, not gzip');
  writeFileSync(gzipFile, gzipSync(Buffer.from('synthetic')));
  mkdirSync(runsDir, { recursive: true });

  const expectNoSideEffects = async (args, expectedExit, pattern) => {
    const tempBefore = hooklatchTempEntries();
    const scratchBefore = scratchDirs();
    const run = await cli(args, ledger);

    assertThat(run.exitCode === expectedExit, `expected exit ${expectedExit}, observed ${String(run.exitCode)}: ${run.stdout.slice(-400)}${run.stderr.slice(-400)}`);
    assertThat(pattern.test(run.stdout + run.stderr), `output did not match ${String(pattern)}`);
    assertThat(hooklatchTempEntries().join('|') === tempBefore.join('|'), 'temp entries changed');
    assertThat(scratchDirs().join('|') === scratchBefore.join('|'), 'scratch stage directory created');

    return run;
  };

  await control('cli/help', () => expectNoSideEffects(['--help'], EXIT.READY, /Usage:/));
  await control('cli/default-no-arguments-blocked-before-temp', () => expectNoSideEffects([], EXIT.BLOCKED, /"result":"blocked".*not supplied/));
  await control('cli/partial-inputs-blocked', () => expectNoSideEffects(['--tarball', gzipFile], EXIT.BLOCKED, /--node22-floor not supplied/));
  await control('cli/missing-tarball-file-blocked', () => expectNoSideEffects(
    ['--tarball', path.join(workspace.root, 'absent.tgz'), '--node22-floor', host, '--node22', host, '--node24', host], EXIT.BLOCKED, /input file missing: tarball/));
  await control('cli/duplicate-argument', () => expectNoSideEffects(['--node24', host, '--node24', host], EXIT.USAGE, /duplicate argument/));
  await control('cli/unknown-argument', () => expectNoSideEffects(['--node20', host], EXIT.USAGE, /unknown argument/));
  await control('cli/missing-value', () => expectNoSideEffects(['--tarball'], EXIT.USAGE, /missing value/));
  await control('cli/self-test-incompatible', () => expectNoSideEffects(['--self-test', '--tarball', gzipFile], EXIT.USAGE, /standalone/));
  await control('cli/wrong-artifact-before-gates', () => expectNoSideEffects(
    ['--tarball', textFile, '--node22-floor', host, '--node22', host, '--node24', host], EXIT.FAILED, /wrong-artifact/));
  // The one host executable is passed for every role: the floor role and the
  // role for the other Node line must both be rejected before any gate runs.
  const otherLine = process.versions.node.startsWith('22.') ? '--node24' : '--node22';
  const hostVersion = process.version.split('.').join('\\.');

  await control('cli/wrong-floor-runtime-before-gates', () => expectNoSideEffects(
    ['--tarball', gzipFile, '--node22-floor', host, '--node22', host, '--node24', host], EXIT.FAILED,
    new RegExp(`--node22-floor reports ${hostVersion}, expected exactly v22\\.0\\.0`)));
  await control('cli/host-substituted-for-other-line', () => expectNoSideEffects(
    ['--tarball', gzipFile, '--node22-floor', host, '--node22', host, '--node24', host], EXIT.FAILED, new RegExp(`${otherLine} reports ${hostVersion}`)));

  const resultsGuard = (id, target, pattern) => control(`cli/results-guard/${id}`, async () => {
    const existedBefore = existsSync(target);

    await expectNoSideEffects(['--tarball', gzipFile, '--results', target], EXIT.USAGE, pattern);
    assertThat(existsSync(target) === existedBefore, 'results destination state changed');
  });

  const existing = path.join(runsDir, `existing-${randomUUID()}.json`);

  writeFileSync(existing, '{"keep":true}\n', { flag: 'wx' });

  await resultsGuard('existing-file-not-overwritten', existing, /already exists/);
  await resultsGuard('tracked-file', path.join(REPO_ROOT, 'package.json'), /already exists|tracked/);
  await resultsGuard('claim-file', path.join(REPO_ROOT, 'notes', 'phase-13', 'claude', 'session.json'), /already exists|claim/);
  await resultsGuard('fresh-claim-name', path.join(runsDir, `phase13-${randomUUID()}-session.json`), /claim|session/);
  await resultsGuard('outside-checkout', path.join(workspace.root, 'results.json'), /inside this checkout/);
  await resultsGuard('not-json', path.join(runsDir, `report-${randomUUID()}.txt`), /\.json/);
  await resultsGuard('equals-tarball', gzipFile, /already exists|inside this checkout|tarball/);

  const stageCollision = path.join(runsDir, `collision-${randomUUID()}`);

  mkdirSync(`${stageCollision}.stages`);
  await resultsGuard('stage-directory-exists', `${stageCollision}.json`, /stage report directory already exists/);
  rmdirSync(`${stageCollision}.stages`);

  const link = path.join(runsDir, `link-${randomUUID()}`);
  const linkTarget = path.join(workspace.root, 'link-target');

  mkdirSync(linkTarget);
  symlinkSync(linkTarget, link, process.platform === 'win32' ? 'junction' : 'dir');

  try {
    await resultsGuard('linked-ancestor', path.join(link, 'results.json'), /symbolic link/);
    assertThat(readdirSync(linkTarget).length === 0, 'write through linked ancestor');
  } finally {
    assertThat(lstatSync(link).isSymbolicLink() || process.platform === 'win32', 'control link replaced');

    try {
      unlinkSync(link);
    } catch {
      rmdirSync(link);
    }
  }

  assertThat(!existsSync(link), 'control link not removed');
  rmSync(existing);
  assertThat(readdirSync(runsDir).length === 0, 'control results directory not empty');
  rmdirSync(runsDir);
}

/* ------------------------------------------------------------------ *
 * Harness controls (production pipeline, fake gate children)
 * ------------------------------------------------------------------ */

function harnessContext(workspace, label) {
  const root = path.join(workspace.root, label);
  const tarball = path.join(root, 'candidate.tgz');
  const stageDir = path.join(root, 'stages');

  mkdirSync(stageDir, { recursive: true });
  writeFileSync(tarball, gzipSync(Buffer.from(`synthetic candidate ${label}`)));

  const head = runSync('git', ['rev-parse', 'HEAD']).stdout.trim();
  const fakeRuntime = (name, version) => ({ path: path.join(root, `${name}.exe`), version, sha256: '0'.repeat(64) });

  return {
    root,
    stageDir,
    stageDirScratch: true,
    head,
    host: { version: process.version },
    tarball: { path: tarball, sha256: sha256File(tarball), bytes: 0 },
    runtimes: { node22Floor: fakeRuntime('floor', 'v22.0.0'), node22: fakeRuntime('n22', 'v22.99.1'), node24: fakeRuntime('n24', 'v24.99.1') },
  };
}

async function harnessRun(workspace, label, overrides) {
  const context = harnessContext(workspace, label);
  const fakeGate = path.join(workspace.root, 'fake-gate.mjs');
  const pids = [];

  context.tarball.bytes = lstatSync(context.tarball.path).size;

  if (!existsSync(fakeGate)) writeFileSync(fakeGate, FAKE_GATE);

  for (const id of STAGE_IDS) {
    const behavior = { exit: 0, report: syntheticReport(id, context), hang: false, leakTemp: false, mutateArtifact: false, ...overrides[id] };

    writeFileSync(path.join(context.root, `${id}.behavior.json`), JSON.stringify(behavior));
  }

  for (const [id, report] of Object.entries(overrides.preexisting ?? {})) {
    writeFileSync(path.join(context.stageDir, `${STAGE_IDS.indexOf(id) + 1}-${id}.json`), JSON.stringify(report));
  }

  const report = await runQualification(context, {
    timeoutMs: HANG_TIMEOUT_MS,
    command: (stage, args) => ({ script: fakeGate, args: [path.join(context.root, `${stage.id}.behavior.json`), ...args] }),
  });

  for (const stage of report.stages) {
    if (Number.isInteger(stage.execution?.pid)) pids.push(stage.execution.pid);
  }

  return { report, context, pids };
}

function statuses(report) {
  return report.stages.map((stage) => stage.status).join(',');
}

async function harnessControls(workspace, control) {
  await control('harness/all-six-stages-ready-is-labelled-harness', async () => {
    const { report, context } = await harnessRun(workspace, 'ready', {});

    assertThat(report.exitCode === EXIT.READY && report.result === 'harness-ready' && report.controlsOnly === true, `${report.result} ${JSON.stringify(report.problems)}`);
    assertThat(report.stages.length === 6 && report.stages.every((stage) => stage.status === 'ready' && Number.isInteger(stage.execution?.pid)), statuses(report));
    assertThat(report.stages.every((stage) => stage.argv.includes(context.tarball.path) && stage.artifactBefore === context.tarball.sha256 && stage.artifactAfter === context.tarball.sha256), 'artifact binding');
    assertThat(report.cleanup.stageDirRemoved === true && report.cleanup.tempLeftovers.length === 0, 'scratch cleanup');
  });

  await control('harness/child-exit-9-is-crash-not-rejection', async () => {
    const { report } = await harnessRun(workspace, 'exit9', { 'runtime-floor': { exit: 9, report: null } });

    assertThat(report.exitCode === EXIT.FAILED, String(report.exitCode));
    assertThat(statuses(report) === 'ready,ready,crashed,not-run,not-run,not-run', statuses(report));
    assertThat(report.stages[2].classification === 'crashed' && report.stages[2].execution.exitCode === 9, 'classification');
  });

  await control('harness/genuine-rejection-is-failed', async () => {
    const { report } = await harnessRun(workspace, 'reject', { 'package-contract': { exit: 1, report: { status: 'fail' } } });

    assertThat(report.exitCode === EXIT.FAILED && report.stages[0].classification === 'rejected' && report.stages[0].status === 'failed', statuses(report));
    assertThat(report.stages.slice(1).every((stage) => stage.status === 'not-run'), statuses(report));
  });

  await control('harness/hang-terminated-confirmed-scratch-preserved', async () => {
    const { report, pids } = await harnessRun(workspace, 'hang', { 'types-compatibility': { hang: true } });
    const hung = report.stages[1];

    assertThat(report.exitCode === EXIT.FAILED && hung.status === 'timeout' && hung.classification === 'timeout', statuses(report));
    assertThat(hung.execution.timedOut === true && hung.execution.closeConfirmed === true, 'termination not confirmed');
    assertThat(processGone(pids[1]), `hung child ${pids[1]} still alive`);
    assertThat(report.cleanup.uncertain === true && report.cleanup.preserved !== null && existsSync(report.cleanup.preserved), 'scratch not preserved after timeout');
    assertThat(report.stages.slice(2).every((stage) => stage.status === 'not-run'), statuses(report));
  });

  await control('harness/blocked-stage-propagates-3', async () => {
    const { report } = await harnessRun(workspace, 'blocked', { 'mixed-format-runtime': { exit: 3, report: null } });

    assertThat(report.exitCode === EXIT.BLOCKED && report.result === 'harness-blocked', `${report.result}`);
    assertThat(statuses(report) === 'ready,ready,ready,blocked,not-run,not-run', statuses(report));
  });

  await control('harness/missing-report-with-exit-0', async () => {
    const { report } = await harnessRun(workspace, 'noreport', { 'types-compatibility': { report: null } });

    assertThat(report.exitCode === EXIT.FAILED && report.stages[1].problems.some((problem) => /no structured report/.test(problem)), JSON.stringify(report.stages[1].problems));
  });

  await control('harness/wrong-artifact-hash-in-report', async () => {
    const { report } = await harnessRun(workspace, 'wrongsha', { 'framework-node22': { report: { ...syntheticReport('framework-node22', harnessContext(workspace, 'wrongsha-src')), artifact: { sha256: 'f'.repeat(64) } } } });

    assertThat(report.exitCode === EXIT.FAILED && report.stages[4].problems.some((problem) => /artifact sha256/.test(problem)), JSON.stringify(report.stages[4].problems));
  });

  await control('harness/wrong-runtime-report', async () => {
    const first = await harnessRun(workspace, 'wrongrt', {});
    const node22Report = syntheticReport('framework-node22', first.context);
    const { report } = await harnessRun(workspace, 'wrongrt2', { 'framework-node24': { report: { ...node22Report, artifact: { sha256: '' } } } });
    const stage = report.stages[5];

    assertThat(report.exitCode === EXIT.FAILED && stage.problems.some((problem) => /target runtime v22\./.test(problem)), JSON.stringify(stage.problems));
  });

  await control('harness/artifact-mutated-during-stage', async () => {
    const { report } = await harnessRun(workspace, 'mutate', { 'runtime-floor': { mutateArtifact: true } });

    assertThat(report.exitCode === EXIT.FAILED && report.stages[2].problems.some((problem) => /artifact changed during stage/.test(problem)), JSON.stringify(report.stages[2].problems));
    assertThat(report.artifact.sha256After !== report.artifact.sha256, 'post-run hash');
  });

  await control('harness/historical-report-cannot-replace-execution', async () => {
    const source = harnessContext(workspace, 'historical-src');
    const { report } = await harnessRun(workspace, 'historical', { preexisting: { 'package-contract': syntheticReport('package-contract', source) } });

    assertThat(report.exitCode === EXIT.FAILED && report.stages[0].execution === null, statuses(report));
    assertThat(report.stages[0].problems.some((problem) => /already exists before execution/.test(problem)), JSON.stringify(report.stages[0].problems));
  });

  await control('harness/temp-leftover-prevents-ready', async () => {
    let leaked = [];

    try {
      const { report } = await harnessRun(workspace, 'leak', { 'framework-node24': { leakTemp: true } });

      leaked = report.cleanup.tempLeftovers;
      assertThat(report.stages.every((stage) => stage.status === 'ready'), statuses(report));
      assertThat(report.exitCode === EXIT.FAILED && leaked.length === 1 && leaked[0].startsWith(LEAK_PREFIX), JSON.stringify(report.cleanup));
    } finally {
      for (const name of hooklatchTempEntries().filter((entry) => entry.startsWith(LEAK_PREFIX))) {
        const target = path.join(os.tmpdir(), name);

        assertInsideTemp(target);
        rmSync(target, { recursive: true, force: true });
      }
    }
  });
}

/* ------------------------------------------------------------------ *
 * Driver
 * ------------------------------------------------------------------ */

async function main(argv) {
  if (argv.length === 1 && argv[0] === '--help') {
    process.stdout.write(`${usage()}\n`);

    return EXIT.READY;
  }

  if (argv.length > 0) {
    process.stderr.write(`release-candidate-controls: unknown or extra arguments\n${usage()}\n`);

    return EXIT.USAGE;
  }

  const results = [];
  const ledger = createHealthLedger();
  const workspace = createWorkspace(CONTROL_PREFIX);

  const control = async (id, fn) => {
    const started = Date.now();

    try {
      await fn();
      results.push({ id, status: 'pass', ms: Date.now() - started });
    } catch (error) {
      results.push({ id, status: 'fail', ms: Date.now() - started, detail: messageOf(error).slice(0, 1500) });
    }
  };

  let cleanup;

  try {
    await cliControls(workspace, ledger, control);
    await harnessControls(workspace, control);
  } finally {
    try {
      disposeWorkspace(workspace, { ledger });
      cleanup = { removed: !existsSync(workspace.root), root: workspace.root };
    } catch (error) {
      cleanup = { removed: false, root: workspace.root, detail: messageOf(error) };
    }
  }

  const failed = results.filter((entry) => entry.status !== 'pass');
  const ok = failed.length === 0 && cleanup.removed;

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    kind: 'phase13-release-candidate-controls',
    controlsOnly: true,
    result: ok ? 'controls-passed' : 'controls-failed',
    passed: results.length - failed.length,
    total: results.length,
    controls: results,
    cleanup,
    note: 'harness-only; fake gate children never qualify a product artifact',
  }, null, 2)}\n`);

  return ok ? EXIT.READY : EXIT.FAILED;
}

process.exitCode = await main(process.argv.slice(2));
