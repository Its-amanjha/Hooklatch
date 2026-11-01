#!/usr/bin/env node
/**
 * Phase 13 exact-artifact release-candidate qualification (Claude owner).
 *
 * Serially drives the six existing, reviewed Phase 11 gates against ONE
 * caller-supplied tarball and three caller-supplied Node executables:
 *
 *   1. package-contract       scripts/phase11/package-contract.mjs
 *   2. types-compatibility    scripts/phase11/types-compatibility.mjs
 *   3. runtime-floor          scripts/phase11/runtime-floor.mjs (exact 22.0.0 + later 22)
 *   4. mixed-format-runtime   scripts/phase11/mixed-format-runtime.mjs (later 22 + 24)
 *   5. framework-node22       scripts/phase11/workers-compatibility.mjs --node <later 22>
 *   6. framework-node24       scripts/phase11/workers-compatibility.mjs --node <24>
 *
 * This script is an orchestrator, not a gate: it never extracts, installs or
 * imports the candidate itself. Each gate runs as a bounded child on the host
 * Node 24 toolchain (the gates dispatch the target runtimes themselves). A
 * stage is accepted only when the child closed cleanly with exit 0 AND wrote a
 * fresh structured report in this run whose status, exact inventory, artifact
 * SHA-256, target runtime versions/hashes, cleanup and integrity fields match.
 * The archive hash is re-measured around every stage, and the checkout
 * (tracked files + full dist/ tree, git status) and OS-temp `hooklatch-*`
 * entries are compared before and after the whole run.
 *
 * Usage:
 *   node scripts/phase13/release-candidate.mjs --tarball FILE --node22-floor FILE
 *        --node22 FILE --node24 FILE [--results FILE]
 *   node scripts/phase13/release-candidate.mjs --self-test
 *   node scripts/phase13/release-candidate.mjs --help
 *
 * Exit: 0 ready (all six stages + integrity + cleanup), 1 failed, 2 usage,
 * 3 BLOCKED (missing prerequisite or a stage reported BLOCKED; remaining
 * stages not-run). --self-test is harness-only and never a qualification.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  compareCheckout, createHealthLedger, runChild, runSync, snapshotCheckout,
} from '../phase11/mixed-format-runtime.mjs';
import { PROVIDERS, SUBPATHS } from '../phase11/mixed-format-consumer.mjs';
import { UsageError, isPlainRecord, validateResultsDestination } from '../phase11/package-contract.mjs';
import { FRAMEWORKS, STATES } from '../../tests/compatibility/phase11-framework-consumer.mjs';

export const EXIT = Object.freeze({ READY: 0, FAILED: 1, USAGE: 2, BLOCKED: 3 });

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export const FLOOR_VERSION = 'v22.0.0';

export const STAGE_TIMEOUT_MS = 45 * 60 * 1000;

const PROBE_TIMEOUT_MS = 30_000;
const TAIL_CHARS = 1500;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const TEMP_MARKER = 'hooklatch-';

export const EXPECTED = Object.freeze({
  packageChecks: 23,
  typeCases: 142,
  compilerControls: 9,
  floorChecks: 44,
  providers: 21,
  subpaths: 6,
  tuplesPerRuntime: 252,
  pureCjsTuples: 150,
  matrixPasses: 2,
  workerdMatrices: 2,
  frameworkProviders: Object.freeze(['github', 'grafana', 'fal']),
});

const USAGE = `Usage:
  node scripts/phase13/release-candidate.mjs --tarball FILE --node22-floor FILE --node22 FILE --node24 FILE [--results FILE]
  node scripts/phase13/release-candidate.mjs --self-test
  node scripts/phase13/release-candidate.mjs --help

Qualifies ONE explicit tarball through the six existing Phase 11 gates, serially:
package-contract, types-compatibility, runtime-floor, mixed-format-runtime,
framework (later Node 22) and framework (Node 24).

  --tarball FILE       candidate .tgz (required; hashed before and after every stage)
  --node22-floor FILE  executable reporting exactly ${FLOOR_VERSION}
  --node22 FILE        a later Node 22 executable (not ${FLOOR_VERSION})
  --node24 FILE        a Node 24 executable
  --results FILE       new git-ignored .json inside this checkout; written exclusively
                       after cleanup/integrity checks. Per-stage gate reports are kept
                       in the sibling directory FILE-without-.json + ".stages".
  --self-test          in-process harness controls only (never a qualification)

Nothing is downloaded; runtimes are never substituted by the host. Missing inputs
are BLOCKED (3) before any directory is created.
Exit: 0 ready, 1 failed, 2 usage, 3 blocked.`;

/* ------------------------------------------------------------------ *
 * Arguments
 * ------------------------------------------------------------------ */

const VALUE_FLAGS = Object.freeze({
  '--tarball': 'tarball',
  '--node22-floor': 'node22Floor',
  '--node22': 'node22',
  '--node24': 'node24',
  '--results': 'results',
});

export function parseArguments(argv) {
  const options = { help: false, selfTest: false, tarball: null, node22Floor: null, node22: null, node24: null, results: null };
  const seen = new Set();

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];

    if (seen.has(flag)) throw new UsageError(`duplicate argument: ${flag}`);

    seen.add(flag);

    if (flag === '--help') {
      options.help = true;
      continue;
    }

    if (flag === '--self-test') {
      options.selfTest = true;
      continue;
    }

    const key = VALUE_FLAGS[flag];

    if (key === undefined) throw new UsageError(`unknown argument: ${flag}`);

    const value = argv[index + 1];

    if (value === undefined || value === '' || value.startsWith('--')) throw new UsageError(`missing value for ${flag}`);

    options[key] = value;
    index += 1;
  }

  const valued = Object.values(VALUE_FLAGS).some((key) => options[key] !== null);

  if (options.help && (options.selfTest || valued)) throw new UsageError('--help is standalone');

  if (options.selfTest && valued) throw new UsageError('--self-test is standalone and takes no inputs');

  return options;
}

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */

export function sha256File(file) {
  const hash = createHash('sha256');
  const handle = openSync(file, 'r');
  const buffer = Buffer.alloc(1024 * 1024);

  try {
    let read = readSync(handle, buffer, 0, buffer.length, null);

    while (read > 0) {
      hash.update(buffer.subarray(0, read));
      read = readSync(handle, buffer, 0, buffer.length, null);
    }
  } finally {
    closeSync(handle);
  }

  return hash.digest('hex');
}

function tail(text) {
  return text.length > TAIL_CHARS ? text.slice(-TAIL_CHARS) : text;
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/** JSON boundary kind check without typeof (same approach as the Phase 11 gates). */
function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

function samePath(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);

  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function isInside(parent, child) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));

  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function check(problems, condition, message) {
  if (!condition) problems.push(message);
}

function uniqueCount(values) {
  return new Set(values).size;
}

export function hooklatchTempEntries() {
  return readdirSync(os.tmpdir()).filter((name) => name.startsWith(TEMP_MARKER)).sort();
}

function gitStatus() {
  const run = runSync('git', ['status', '--porcelain=v1', '--untracked-files=all']);

  return { status: run.status, stdout: run.stdout };
}

function gitIgnored(target) {
  return runSync('git', ['check-ignore', '-q', '--no-index', path.relative(REPO_ROOT, target).split(path.sep).join('/')]).status === 0;
}

/* ------------------------------------------------------------------ *
 * Stage table (production gates only)
 * ------------------------------------------------------------------ */

function frameworkTuples() {
  return ['import', 'require'].flatMap((format) => FRAMEWORKS.flatMap((framework) => EXPECTED.frameworkProviders
    .flatMap((provider) => STATES.map((state) => `${framework}:${format}:${provider}:${state}`))));
}

function validatePackageContract(report, context) {
  const problems = [];
  const checks = Array.isArray(report.checks) ? report.checks : [];
  const ids = checks.map((entry) => String(entry?.id));

  check(problems, report.gate === 'phase11-package-contract', `gate id ${String(report.gate)}`);
  check(problems, report.mode === 'tarball' && report.controlsOnly === false, `mode ${String(report.mode)}/controlsOnly ${String(report.controlsOnly)}`);
  check(problems, report.status === 'pass' && report.exit === EXIT.READY, `status ${String(report.status)} exit ${String(report.exit)}`);
  check(problems, report.environment?.tarball?.sha256 === context.tarball.sha256, `artifact sha256 ${String(report.environment?.tarball?.sha256)}`);
  check(problems, report.environment?.tarball?.bytes === context.tarball.bytes, `artifact bytes ${String(report.environment?.tarball?.bytes)}`);
  check(problems, report.environment?.node === context.host.version, `probe runtime ${String(report.environment?.node)} (host ${context.host.version})`);
  check(problems, report.summary?.checks === EXPECTED.packageChecks && report.summary?.passed === EXPECTED.packageChecks,
    `checks ${String(report.summary?.passed)}/${String(report.summary?.checks)} (expected ${EXPECTED.packageChecks})`);
  check(problems, report.summary?.failed === 0 && report.summary?.notRun === 0, 'failed or not-run checks present');
  check(problems, checks.length === EXPECTED.packageChecks && uniqueCount(ids) === ids.length, `check inventory ${checks.length} (unique ${uniqueCount(ids)})`);
  check(problems, checks.every((entry) => entry?.verdict === 'pass'), 'non-pass check verdict');
  check(problems, Array.isArray(report.findings) && report.findings.length === 0, 'findings present');
  check(problems, report.cleanup?.attempted === true && report.cleanup?.verified === true && report.cleanup?.cleanupSafe === true, 'cleanup not verified');
  check(problems, report.integrity?.sampled === true && Array.isArray(report.integrity?.changed) && report.integrity.changed.length === 0, 'integrity not verified');

  return { problems, observed: { checkIds: ids, runtime: report.environment?.node ?? null } };
}

function validateTypes(report, context) {
  const problems = [];
  const cases = Array.isArray(report.cases) ? report.cases : [];
  const controls = Array.isArray(report.controls) ? report.controls : [];
  const caseIds = cases.map((entry) => String(entry?.id));
  const controlIds = controls.map((entry) => String(entry?.id));
  const summary = report.summary ?? {};

  check(problems, report.status === 'ready' && summary.ready === true, `status ${String(report.status)}`);
  check(problems, report.mode === 'candidate-tarball', `mode ${String(report.mode)}`);
  check(problems, report.artifact?.sha256 === context.tarball.sha256, `artifact sha256 ${String(report.artifact?.sha256)}`);
  check(problems, report.toolchain?.node === context.host.version, `compiler host ${String(report.toolchain?.node)}`);
  check(problems, summary.cases === EXPECTED.typeCases && summary.passed === EXPECTED.typeCases, `cases ${String(summary.passed)}/${String(summary.cases)} (expected ${EXPECTED.typeCases})`);
  check(problems, summary.failed === 0 && summary.infrastructure === 0, 'failed or infrastructure cases');
  check(problems, cases.length === EXPECTED.typeCases && uniqueCount(caseIds) === caseIds.length, `case inventory ${cases.length} (unique ${uniqueCount(caseIds)})`);
  check(problems, cases.every((entry) => entry?.status === 'pass'), 'non-pass case');
  check(problems, summary.controls === EXPECTED.compilerControls && summary.controlsDetected === EXPECTED.compilerControls,
    `compiler controls ${String(summary.controlsDetected)}/${String(summary.controls)} (expected ${EXPECTED.compilerControls})`);
  check(problems, controls.length === EXPECTED.compilerControls && controls.every((entry) => entry?.detected === true) && uniqueCount(controlIds) === controlIds.length, 'control inventory');
  check(problems, summary.graphProblems === 0 && summary.integrityFailures === 0, 'graph or integrity problems');
  check(problems, summary.tempRemoved === true && report.integrity?.cleanup?.removed === true, 'temp not removed');
  check(problems, report.integrity?.head === context.head, `integrity head ${String(report.integrity?.head)}`);

  return { problems, observed: { caseIds, controlIds, compilerHost: report.toolchain?.node ?? null, typescript: report.toolchain?.typescript ?? null } };
}

function validateFloor(wrapper, context) {
  const problems = [];
  const summary = wrapper.summary ?? {};
  const evidence = wrapper.evidence ?? {};
  const inventories = Array.isArray(summary.checkInventories) ? summary.checkInventories : [];
  const tuples = Array.isArray(evidence.tuples) ? evidence.tuples : [];
  const tupleIds = tuples.map((tuple) => (Array.isArray(tuple?.validation?.checkIds) ? tuple.validation.checkIds.map(String) : []));

  check(problems, summary.result === 'ready' && summary.exitCode === EXIT.READY, `result ${String(summary.result)}`);
  check(problems, summary.floor?.version === FLOOR_VERSION && summary.floor?.sha256 === context.runtimes.node22Floor.sha256, `floor ${String(summary.floor?.version)} sha ${String(summary.floor?.sha256)}`);
  check(problems, isString(summary.floor?.executable) && samePath(summary.floor.executable, context.runtimes.node22Floor.path), 'floor executable path');
  check(problems, summary.repeat?.version === context.runtimes.node22.version && summary.repeat?.sha256 === context.runtimes.node22.sha256, `repeat ${String(summary.repeat?.version)}`);
  check(problems, isString(summary.repeat?.executable) && samePath(summary.repeat.executable, context.runtimes.node22.path), 'repeat executable path');
  check(problems, summary.tarball?.sha256 === context.tarball.sha256, `artifact sha256 ${String(summary.tarball?.sha256)}`);
  check(problems, inventories.length === 2 && inventories.every((entry) => entry?.checks === EXPECTED.floorChecks && entry?.passed === EXPECTED.floorChecks),
    `check inventories ${JSON.stringify(inventories)}`);
  check(problems, inventories[0]?.label === 'node22.0.0-floor', `first tuple ${String(inventories[0]?.label)}`);
  check(problems, tuples.length === 2 && tuples.every((tuple) => tuple?.validation?.ok === true), 'tuple validation');
  check(problems, tupleIds.every((ids) => ids.length === EXPECTED.floorChecks && uniqueCount(ids) === ids.length), 'tuple check ids');
  check(problems, tupleIds.length === 2 && tupleIds[0].join('|') === tupleIds[1].join('|'), 'floor and repeat inventories differ');
  check(problems, summary.cleanup?.confirmed === true && summary.integrityUnchanged === true, 'cleanup/integrity not confirmed');
  check(problems, evidence.host?.node === context.host.version, `install host ${String(evidence.host?.node)}`);

  return { problems, observed: { checkIds: tupleIds[0] ?? [], tuples: inventories, runtimes: [summary.floor?.version ?? null, summary.repeat?.version ?? null] } };
}

function validateMixed(report, context) {
  const problems = [];
  const runs = Array.isArray(report.runs) ? report.runs : [];
  const expectedRuntimes = [context.runtimes.node22.version, context.runtimes.node24.version];

  check(problems, report.status === 'pass' && report.allTuplesMinimumMet === true, `status ${String(report.status)}`);
  check(problems, report.candidate?.sha256 === context.tarball.sha256, `artifact sha256 ${String(report.candidate?.sha256)}`);
  check(problems, report.candidate?.path !== undefined && samePath(String(report.candidate.path), context.tarball.path), 'artifact path');
  check(problems, JSON.stringify(report.runtimesChecked) === JSON.stringify(expectedRuntimes), `runtimes ${JSON.stringify(report.runtimesChecked)}`);
  check(problems, report.providersCount === EXPECTED.providers && PROVIDERS.length === EXPECTED.providers, `providers ${String(report.providersCount)}`);
  check(problems, report.subpathsCount === EXPECTED.subpaths && SUBPATHS.length === EXPECTED.subpaths, `subpaths ${String(report.subpathsCount)}`);
  check(problems, report.totalTuplesCount === EXPECTED.tuplesPerRuntime * 2, `total tuples ${String(report.totalTuplesCount)}`);
  check(problems, runs.length === EXPECTED.matrixPasses, `matrix passes ${runs.length}`);

  for (const run of runs) {
    for (const [label, runtime] of [['node22', context.runtimes.node22], ['node24', context.runtimes.node24]]) {
      const entry = run?.[label];

      check(problems, entry?.runtime === runtime.version, `pass ${String(run?.pass)} ${label} runtime ${String(entry?.runtime)}`);
      check(problems, isString(entry?.executable) && samePath(entry.executable, runtime.path), `pass ${String(run?.pass)} ${label} executable`);
      check(problems, entry?.totalTuplesPerRuntime === EXPECTED.tuplesPerRuntime && entry?.pureCjsTuples === EXPECTED.pureCjsTuples,
        `pass ${String(run?.pass)} ${label} tuples ${String(entry?.totalTuplesPerRuntime)}/${String(entry?.pureCjsTuples)}`);
      check(problems, entry?.importFirstOk === true && entry?.requireFirstOk === true && entry?.negativeSubpathsOk === true, `pass ${String(run?.pass)} ${label} identity/negative probes`);
    }
  }

  return { problems, observed: { runtimes: report.runtimesChecked ?? null, totalTuples: report.totalTuplesCount ?? null } };
}

function validateFramework(runtimeKey) {
  return (report, context) => {
    const problems = [];
    const runtime = context.runtimes[runtimeKey];
    const tuples = Array.isArray(report.nodeTuples) ? report.nodeTuples : [];
    const observed = tuples.map((tuple) => `${String(tuple?.framework)}:${String(tuple?.format)}:${String(tuple?.provider)}:${String(tuple?.state)}`);
    const expected = frameworkTuples();
    const workers = Array.isArray(report.workers) ? report.workers : [];

    check(problems, report.artifact?.sha256 === context.tarball.sha256, `artifact sha256 ${String(report.artifact?.sha256)}`);
    check(problems, report.runtime === runtime.version, `target runtime ${String(report.runtime)} (expected ${runtime.version})`);
    check(problems, observed.join('|') === expected.join('|'), `node request inventory ${observed.length}/${expected.length}`);
    check(problems, workers.length === EXPECTED.workerdMatrices, `workerd matrices ${workers.length}`);
    check(problems, workers.every((worker) => worker?.userAgent === 'Cloudflare-Workers' && worker?.wrongAccount === true
      && Array.isArray(worker?.tuples) && worker.tuples.length === EXPECTED.frameworkProviders.length * STATES.length), 'workerd matrix content');
    check(problems, Array.isArray(report.controls) && report.controls.length === 0, 'unexpected self-test controls in a ready run');
    check(problems, Array.isArray(report.bundleInputs) && report.bundleInputs.length > 0, 'bundle inputs missing');
    check(problems, report.cleanupVerified === true, 'cleanup not verified');

    return { problems, observed: { runtime: report.runtime ?? null, nodeRequests: observed.length, workerdMatrices: workers.length } };
  };
}

export const STAGES = Object.freeze([
  Object.freeze({
    id: 'package-contract',
    script: 'scripts/phase11/package-contract.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--results', out],
    stdoutReport: true,
    validate: validatePackageContract,
  }),
  Object.freeze({
    id: 'types-compatibility',
    script: 'scripts/phase11/types-compatibility.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--results', out],
    stdoutReport: false,
    validate: validateTypes,
  }),
  Object.freeze({
    id: 'runtime-floor',
    script: 'scripts/phase11/runtime-floor.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--node22-floor', context.runtimes.node22Floor.path, '--node22', context.runtimes.node22.path, '--results', out],
    stdoutReport: false,
    validate: validateFloor,
  }),
  Object.freeze({
    id: 'mixed-format-runtime',
    script: 'scripts/phase11/mixed-format-runtime.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--node22', context.runtimes.node22.path, '--node24', context.runtimes.node24.path, '--results', out],
    stdoutReport: false,
    validate: validateMixed,
  }),
  Object.freeze({
    id: 'framework-node22',
    script: 'scripts/phase11/workers-compatibility.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--node', context.runtimes.node22.path, '--results', out],
    stdoutReport: false,
    validate: validateFramework('node22'),
  }),
  Object.freeze({
    id: 'framework-node24',
    script: 'scripts/phase11/workers-compatibility.mjs',
    args: (context, out) => ['--tarball', context.tarball.path, '--node', context.runtimes.node24.path, '--results', out],
    stdoutReport: false,
    validate: validateFramework('node24'),
  }),
]);

export const STAGE_IDS = Object.freeze(STAGES.map((stage) => stage.id));

/* ------------------------------------------------------------------ *
 * Stage execution and classification
 * ------------------------------------------------------------------ */

export function classifyChild(run) {
  if (run.spawnError !== null && run.pid === null) return 'infrastructure';

  if (!run.closeConfirmed) return 'termination-unconfirmed';

  if (run.timedOut) return 'timeout';

  if (run.outputLimitExceeded) return 'output-overflow';

  if (run.signal !== null) return 'crashed';

  if (run.exitCode === EXIT.READY) return 'exited-0';

  if (run.exitCode === EXIT.FAILED) return 'rejected';

  if (run.exitCode === EXIT.BLOCKED) return 'blocked';

  if (run.exitCode === EXIT.USAGE) return 'usage';

  return 'crashed';
}

function childEvidence(run) {
  return {
    pid: run.pid,
    exitCode: run.exitCode,
    signal: run.signal,
    timedOut: run.timedOut,
    outputLimitExceeded: run.outputLimitExceeded,
    spawnError: run.spawnError,
    closeConfirmed: run.closeConfirmed,
    durationMs: run.durationMs,
    stdoutTail: tail(run.stdout),
    stderrTail: tail(run.stderr),
  };
}

function readStageReport(stage, reportPath, run) {
  if (existsSync(reportPath)) {
    const size = statSync(reportPath).size;

    if (size > MAX_REPORT_BYTES) return { report: null, source: 'results-file', problem: `report exceeds ${MAX_REPORT_BYTES} bytes` };

    try {
      return { report: JSON.parse(readFileSync(reportPath, 'utf8')), source: 'results-file', problem: null };
    } catch (error) {
      return { report: null, source: 'results-file', problem: `report does not parse: ${messageOf(error)}` };
    }
  }

  if (stage.stdoutReport && run.stdout.trim() !== '') {
    try {
      return { report: JSON.parse(run.stdout), source: 'stdout', problem: null };
    } catch {
      return { report: null, source: 'stdout', problem: 'stdout report does not parse' };
    }
  }

  return { report: null, source: null, problem: 'no structured report produced by this run' };
}

/** Bounded copy of a non-ready gate's own verdict fields, for diagnosis only. */
function gateDiagnostic(report) {
  const text = JSON.stringify({ status: report.status ?? report.summary?.result ?? null, summary: report.summary ?? null, error: report.error ?? null });

  return text.length > 4000 ? `${text.slice(0, 4000)}...` : text;
}

const STATUS_BY_CLASS = Object.freeze({
  'exited-0': 'ready',
  rejected: 'failed',
  blocked: 'blocked',
  usage: 'infrastructure',
  crashed: 'crashed',
  timeout: 'timeout',
  'output-overflow': 'infrastructure',
  'termination-unconfirmed': 'infrastructure',
  infrastructure: 'infrastructure',
});

export async function runStage(stage, context, command, timeoutMs, ledger) {
  const reportPath = path.join(context.stageDir, `${STAGE_IDS.indexOf(stage.id) + 1}-${stage.id}.json`);

  const outcome = {
    id: stage.id,
    script: stage.script,
    status: 'failed',
    classification: null,
    argv: null,
    reportPath,
    reportSource: null,
    artifactBefore: null,
    artifactAfter: null,
    execution: null,
    problems: [],
    observed: null,
  };

  if (existsSync(reportPath)) {
    outcome.problems.push('stage report already exists before execution; historical reports never substitute for a run');

    return outcome;
  }

  outcome.artifactBefore = sha256File(context.tarball.path);

  if (outcome.artifactBefore !== context.tarball.sha256) {
    outcome.problems.push(`artifact changed before stage: ${outcome.artifactBefore}`);

    return outcome;
  }

  const productionArgs = stage.args(context, reportPath);
  const invocation = command(stage, productionArgs);

  outcome.argv = [invocation.script, ...invocation.args];

  const run = await runChild(process.execPath, outcome.argv, { cwd: REPO_ROOT, timeoutMs, ledger });

  outcome.execution = childEvidence(run);
  outcome.classification = classifyChild(run);
  outcome.status = STATUS_BY_CLASS[outcome.classification];
  outcome.artifactAfter = existsSync(context.tarball.path) ? sha256File(context.tarball.path) : null;

  if (outcome.artifactAfter !== context.tarball.sha256) {
    outcome.status = 'failed';
    outcome.problems.push(`artifact changed during stage: ${String(outcome.artifactAfter)}`);
  }

  const read = readStageReport(stage, reportPath, run);

  if (outcome.status !== 'ready') {
    if (isPlainRecord(read.report)) outcome.diagnostic = gateDiagnostic(read.report);

    return outcome;
  }

  outcome.reportSource = read.source;

  if (read.report === null || !isPlainRecord(read.report)) {
    outcome.status = 'failed';
    outcome.problems.push(read.problem ?? 'report is not an object');

    return outcome;
  }

  const validation = stage.validate(read.report, context);

  outcome.observed = validation.observed;
  outcome.problems.push(...validation.problems);

  if (validation.problems.length > 0) outcome.status = 'failed';

  return outcome;
}

/* ------------------------------------------------------------------ *
 * Aggregation
 * ------------------------------------------------------------------ */

const FAILURE_STATUSES = new Set(['failed', 'crashed', 'timeout', 'infrastructure']);

export function aggregate(outcomes, checks) {
  const problems = [];
  const ids = outcomes.map((outcome) => outcome.id);

  if (uniqueCount(ids) !== ids.length) problems.push(`duplicate stage outcome: ${ids.join(',')}`);

  for (const id of ids) {
    if (!STAGE_IDS.includes(id)) problems.push(`unknown stage outcome: ${id}`);
  }

  const missing = STAGE_IDS.filter((id) => !ids.includes(id));

  for (const outcome of outcomes) {
    if (outcome.status === 'ready' && (outcome.execution === null || !Number.isInteger(outcome.execution?.pid) || outcome.execution?.closeConfirmed !== true
      || outcome.execution?.exitCode !== EXIT.READY)) {
      problems.push(`stage ${outcome.id} is ready without executed-child evidence`);
    }
  }

  if (checks.integrity !== true) problems.push('checkout integrity not confirmed');

  if (checks.cleanup !== true) problems.push('cleanup not confirmed');

  if (checks.artifact !== true) problems.push('artifact hash not confirmed after run');

  const failed = outcomes.some((outcome) => FAILURE_STATUSES.has(outcome.status));

  if (failed || problems.length > 0) return { result: 'failed', exitCode: EXIT.FAILED, problems, missing };

  const notReady = outcomes.some((outcome) => outcome.status !== 'ready');

  if (missing.length > 0 || notReady) return { result: 'blocked', exitCode: EXIT.BLOCKED, problems, missing };

  return { result: 'ready', exitCode: EXIT.READY, problems, missing };
}

/* ------------------------------------------------------------------ *
 * Input validation (before any directory is created)
 * ------------------------------------------------------------------ */

async function probeRuntime(role, file, ledger) {
  const resolved = path.resolve(file);
  const run = await runChild(resolved, ['--version'], { timeoutMs: PROBE_TIMEOUT_MS, ledger });
  const version = run.ok ? run.stdout.trim() : null;

  return { role, path: resolved, sha256: sha256File(resolved), bytes: statSync(resolved).size, version, probe: run.ok ? null : childEvidence(run) };
}

export async function validateInputs(options) {
  const missing = [];

  for (const [flag, key] of Object.entries(VALUE_FLAGS)) {
    if (key !== 'results' && options[key] === null) missing.push(`${flag} not supplied`);
  }

  if (missing.length > 0) return { kind: 'blocked', reason: missing.join('; ') };

  const hostMajor = process.versions.node.split('.')[0];

  if (hostMajor !== '24') return { kind: 'blocked', reason: `host toolchain must be the pinned Node 24 line; observed ${process.version}` };

  const absent = ['tarball', 'node22Floor', 'node22', 'node24'].filter((key) => {
    const target = path.resolve(options[key]);

    return !existsSync(target) || !statSync(target).isFile();
  });

  if (absent.length > 0) return { kind: 'blocked', reason: `input file missing: ${absent.join(', ')}` };

  const tar = await probeTar();

  if (tar.problem !== null) return { kind: 'blocked', reason: tar.problem, tar: tar.version };

  const tarballPath = path.resolve(options.tarball);
  const head = Buffer.alloc(2);
  const handle = openSync(tarballPath, 'r');

  try {
    readSync(handle, head, 0, 2, 0);
  } finally {
    closeSync(handle);
  }

  const tarball = { path: tarballPath, sha256: sha256File(tarballPath), bytes: statSync(tarballPath).size };

  if (head[0] !== 0x1f || head[1] !== 0x8b) return { kind: 'failed', reason: 'wrong-artifact: --tarball is not a gzip archive', tarball };

  const ledger = createHealthLedger();

  const runtimes = {
    node22Floor: await probeRuntime('node22Floor', options.node22Floor, ledger),
    node22: await probeRuntime('node22', options.node22, ledger),
    node24: await probeRuntime('node24', options.node24, ledger),
  };

  const problems = [];

  if (ledger.uncertain) problems.push(`runtime probe uncertain: ${ledger.reasons.join('; ')}`);

  check(problems, runtimes.node22Floor.version === FLOOR_VERSION, `wrong-runtime: --node22-floor reports ${String(runtimes.node22Floor.version)}, expected exactly ${FLOOR_VERSION}`);
  check(problems, /^v22\.\d+\.\d+$/.test(String(runtimes.node22.version)) && runtimes.node22.version !== FLOOR_VERSION,
    `wrong-runtime: --node22 reports ${String(runtimes.node22.version)}, expected a later Node 22`);
  check(problems, /^v24\.\d+\.\d+$/.test(String(runtimes.node24.version)), `wrong-runtime: --node24 reports ${String(runtimes.node24.version)}`);

  if (problems.length > 0) return { kind: 'failed', reason: problems.join('; '), tarball, runtimes };

  return { kind: 'ok', tarball, runtimes, tar: tar.version };
}

/**
 * package-contract lists the archive with the `tar` found on PATH and an
 * absolute --tarball. GNU tar (e.g. Git Bash's) reads `D:\...` as a remote
 * host, so on Windows it is a missing prerequisite, not a candidate defect.
 */
async function probeTar() {
  const run = await runChild('tar', ['--version'], { timeoutMs: PROBE_TIMEOUT_MS });
  const version = run.ok ? run.stdout.split(/\r?\n/)[0].trim() : null;

  if (version === null) return { version, problem: 'system tar is unavailable on PATH (required by package-contract)' };

  if (process.platform === 'win32' && /GNU tar/i.test(version)) {
    return { version, problem: `tar on PATH is ${version}, which misreads drive-letter archive paths; run where tar resolves to the Windows bsdtar` };
  }

  return { version, problem: null };
}

export function validateResults(raw, tarballPath) {
  const target = path.resolve(raw);

  validateResultsDestination(target, REPO_ROOT);

  if (!isInside(REPO_ROOT, target)) throw new UsageError('--results must be inside this checkout (the type gate only writes stage reports in-checkout)');

  if (!target.endsWith('.json')) throw new UsageError('--results must end in .json');

  if (tarballPath !== null && samePath(target, tarballPath)) throw new UsageError('--results must not be the tarball');

  if (/session\.json$/i.test(target)) throw new UsageError('--results must not target a claim/session file');

  if (!gitIgnored(target)) throw new UsageError('--results must be a git-ignored path');

  const stageDir = `${target.slice(0, -'.json'.length)}.stages`;

  if (existsSync(stageDir)) throw new UsageError(`stage report directory already exists: ${stageDir}`);

  return { target, stageDir };
}

/* ------------------------------------------------------------------ *
 * Qualification run
 * ------------------------------------------------------------------ */

const LIMITATIONS = Object.freeze([
  'Evidence describes this exact tarball hash and these exact runtime executables on this host platform only; it is not Linux, CI, live-provider, registry or publication evidence.',
  'Gates run as children of the host Node toolchain; package-contract runtime probe, TypeScript compilation, npm install and Miniflare/workerd run on the host, while the floor, mixed-format and framework Node requests run on the supplied target runtimes.',
  'workerd matrices in both framework stages run on the host-bundled Miniflare, not on a target Node runtime.',
  'Artifact binding is the explicit --tarball argv plus the SHA-256 each gate reports and this orchestrator re-measures around every stage; gates are not re-implemented here.',
  'mixed-format-runtime does not report cleanup fields; its cleanup is evidenced by exit 0 (its disposer throws otherwise) plus the orchestrator temp/integrity comparison.',
  'Temp leftovers are detected by new OS-temp entries prefixed hooklatch-; a concurrent unrelated hooklatch process can cause a conservative failure.',
]);

function directCommand(stage, args) {
  return { script: path.join(REPO_ROOT, stage.script), args };
}

export async function runQualification(context, seam = {}) {
  const harness = seam.command !== undefined;
  const command = seam.command ?? directCommand;
  const timeoutMs = seam.timeoutMs ?? STAGE_TIMEOUT_MS;
  const ledger = createHealthLedger();
  const outcomes = [];
  const tempBefore = hooklatchTempEntries();
  const checkoutBefore = snapshotCheckout();
  const statusBefore = gitStatus();
  const fullContext = { ...context, head: checkoutBefore.head };

  for (const stage of STAGES) {
    const outcome = await runStage(stage, fullContext, command, timeoutMs, ledger);

    outcomes.push(outcome);

    if (outcome.status !== 'ready') break;
  }

  for (const stage of STAGES.slice(outcomes.length)) outcomes.push({ id: stage.id, script: stage.script, status: 'not-run', execution: null, problems: [] });

  const artifactAfter = existsSync(context.tarball.path) ? sha256File(context.tarball.path) : null;
  const checkoutAfter = snapshotCheckout();
  const statusAfter = gitStatus();
  const integrityProblems = compareCheckout(checkoutBefore, checkoutAfter);

  if (statusBefore.status !== 0 || statusAfter.status !== 0 || statusBefore.stdout !== statusAfter.stdout) integrityProblems.push('git status changed or unavailable');

  const tempAfter = hooklatchTempEntries();
  const leftovers = tempAfter.filter((name) => !tempBefore.includes(name));
  const cleanup = { uncertain: ledger.uncertain, reasons: [...ledger.reasons], tempLeftovers: leftovers, stageDir: context.stageDir, stageDirRemoved: false, preserved: null };

  if (ledger.uncertain) {
    cleanup.preserved = context.stageDir;
  } else if (context.stageDirScratch) {
    rmSync(context.stageDir, { recursive: true, force: true });
    cleanup.stageDirRemoved = !existsSync(context.stageDir);
  }

  const cleanupOk = !ledger.uncertain && leftovers.length === 0 && (!context.stageDirScratch || cleanup.stageDirRemoved);
  const verdict = aggregate(outcomes, { integrity: integrityProblems.length === 0, cleanup: cleanupOk, artifact: artifactAfter === context.tarball.sha256 });

  return {
    schemaVersion: 1,
    kind: 'phase13-release-candidate',
    controlsOnly: harness,
    result: harness ? `harness-${verdict.result}` : verdict.result,
    exitCode: verdict.exitCode,
    problems: [...verdict.problems, ...integrityProblems],
    missingStages: verdict.missing,
    host: { node: process.version, platform: process.platform, arch: process.arch, tar: context.host.tar ?? null },
    artifact: { ...context.tarball, sha256After: artifactAfter },
    runtimes: context.runtimes,
    stages: outcomes,
    integrity: { head: checkoutBefore.head, before: checkoutBefore, after: checkoutAfter, gitStatusUnchanged: statusBefore.stdout === statusAfter.stdout, problems: integrityProblems },
    cleanup,
    limitations: [...LIMITATIONS],
  };
}

/* ------------------------------------------------------------------ *
 * Self-test (pure, in-process, harness-only)
 * ------------------------------------------------------------------ */

export function syntheticContext() {
  return {
    tarball: { path: path.join(os.tmpdir(), 'synthetic.tgz'), sha256: 'a'.repeat(64), bytes: 100 },
    host: { version: process.version },
    head: 'b'.repeat(40),
    runtimes: {
      node22Floor: { path: path.join(os.tmpdir(), 'floor.exe'), version: FLOOR_VERSION, sha256: 'c'.repeat(64) },
      node22: { path: path.join(os.tmpdir(), 'n22.exe'), version: 'v22.99.0', sha256: 'd'.repeat(64) },
      node24: { path: path.join(os.tmpdir(), 'n24.exe'), version: 'v24.99.0', sha256: 'e'.repeat(64) },
    },
  };
}

/** Production-shaped synthetic reports; used only by harness controls. */
export function syntheticReport(stageId, context) {
  const sha = context.tarball.sha256;
  const ids = (prefix, count) => Array.from({ length: count }, (_unused, index) => `${prefix}-${index + 1}`);

  if (stageId === 'package-contract') {
    return {
      gate: 'phase11-package-contract', mode: 'tarball', controlsOnly: false, status: 'pass', exit: 0,
      environment: { node: context.host.version, tarball: { path: context.tarball.path, sha256: sha, bytes: context.tarball.bytes } },
      summary: { checks: 23, passed: 23, failed: 0, notRun: 0 },
      checks: ids('check', 23).map((id) => ({ id, verdict: 'pass' })),
      findings: [], cleanup: { attempted: true, verified: true, cleanupSafe: true }, integrity: { sampled: true, changed: [] },
    };
  }

  if (stageId === 'types-compatibility') {
    return {
      status: 'ready', mode: 'candidate-tarball', artifact: { sha256: sha }, toolchain: { node: context.host.version, typescript: 'synthetic' },
      cases: ids('case', 142).map((id) => ({ id, status: 'pass' })),
      controls: ids('control', 9).map((id) => ({ id, detected: true })),
      integrity: { head: context.head, failures: [], cleanup: { removed: true } },
      summary: { ready: true, cases: 142, passed: 142, failed: 0, infrastructure: 0, controls: 9, controlsDetected: 9, graphProblems: 0, integrityFailures: 0, tempRemoved: true },
    };
  }

  if (stageId === 'runtime-floor') {
    const { node22Floor, node22 } = context.runtimes;
    const checkIds = ids('floor', 44);

    return {
      summary: {
        result: 'ready', exitCode: 0,
        floor: { executable: node22Floor.path, version: node22Floor.version, sha256: node22Floor.sha256 },
        repeat: { executable: node22.path, version: node22.version, sha256: node22.sha256 },
        tarball: { sha256: sha },
        checkInventories: [{ label: 'node22.0.0-floor', checks: 44, passed: 44 }, { label: `node${node22.version}-repeat`, checks: 44, passed: 44 }],
        cleanup: { confirmed: true }, integrityUnchanged: true,
      },
      evidence: { host: { node: context.host.version }, tuples: [{ validation: { ok: true, checkIds } }, { validation: { ok: true, checkIds } }] },
    };
  }

  if (stageId === 'mixed-format-runtime') {
    const entry = (runtime) => ({ runtime: runtime.version, executable: runtime.path, totalTuplesPerRuntime: 252, pureCjsTuples: 150, importFirstOk: true, requireFirstOk: true, negativeSubpathsOk: true });
    const run = (pass) => ({ pass, node22: entry(context.runtimes.node22), node24: entry(context.runtimes.node24) });

    return {
      status: 'pass', allTuplesMinimumMet: true, candidate: { path: context.tarball.path, sha256: sha },
      runtimesChecked: [context.runtimes.node22.version, context.runtimes.node24.version],
      providersCount: 21, subpathsCount: 6, totalTuplesCount: 504, runs: [run(1), run(2)],
    };
  }

  const runtime = stageId === 'framework-node22' ? context.runtimes.node22 : context.runtimes.node24;

  const nodeTuples = frameworkTuples().map((tuple) => {
    const [framework, format, provider, state] = tuple.split(':');

    return { framework, format, provider, state };
  });

  const worker = { userAgent: 'Cloudflare-Workers', wrongAccount: true, tuples: Array.from({ length: 9 }, () => ({})) };

  return { artifact: { sha256: sha }, runtime: runtime.version, nodeTuples, workers: [worker, worker], controls: [], bundleInputs: ['synthetic'], cleanupVerified: true };
}

function expectThrows(fn, pattern) {
  try {
    fn();
  } catch (error) {
    if (pattern.test(messageOf(error))) return;

    throw new Error(`unexpected error: ${messageOf(error)}`);
  }

  throw new Error('expected an error');
}

function readyOutcome(id) {
  return { id, status: 'ready', execution: { pid: 1, closeConfirmed: true, exitCode: 0 }, problems: [] };
}

export function runSelfTest() {
  const results = [];
  const context = syntheticContext();

  const control = (id, fn) => {
    try {
      fn();
      results.push({ id, status: 'pass' });
    } catch (error) {
      results.push({ id, status: 'fail', detail: messageOf(error) });
    }
  };

  const allChecks = { integrity: true, cleanup: true, artifact: true };

  control('stage-table/six-production-gates', () => {
    if (STAGE_IDS.join(',') !== 'package-contract,types-compatibility,runtime-floor,mixed-format-runtime,framework-node22,framework-node24') throw new Error(STAGE_IDS.join(','));

    for (const stage of STAGES) {
      if (!existsSync(path.join(REPO_ROOT, stage.script))) throw new Error(`gate script missing: ${stage.script}`);

      const args = stage.args(context, 'OUT.json');

      if (args[args.indexOf('--tarball') + 1] !== context.tarball.path || args.at(-1) !== 'OUT.json') throw new Error(`${stage.id} argv binding`);
    }
  });
  control('args/duplicate', () => expectThrows(() => parseArguments(['--tarball', 'a', '--tarball', 'b']), /duplicate/));
  control('args/unknown', () => expectThrows(() => parseArguments(['--node20', 'x']), /unknown/));
  control('args/missing-value', () => expectThrows(() => parseArguments(['--node24']), /missing value/));
  control('args/flag-as-value', () => expectThrows(() => parseArguments(['--tarball', '--node24']), /missing value/));
  control('args/self-test-incompatible', () => expectThrows(() => parseArguments(['--self-test', '--tarball', 'x']), /standalone/));
  control('args/help-incompatible', () => expectThrows(() => parseArguments(['--help', '--self-test']), /standalone/));
  control('aggregate/all-six-ready', () => {
    const verdict = aggregate(STAGE_IDS.map(readyOutcome), allChecks);

    if (verdict.exitCode !== EXIT.READY) throw new Error(JSON.stringify(verdict));
  });
  control('aggregate/missing-stage-blocked', () => {
    const verdict = aggregate(STAGE_IDS.slice(0, 5).map(readyOutcome), allChecks);

    if (verdict.exitCode !== EXIT.BLOCKED || verdict.missing.join() !== 'framework-node24') throw new Error(JSON.stringify(verdict));
  });
  control('aggregate/duplicate-stage-failed', () => {
    const verdict = aggregate([...STAGE_IDS.map(readyOutcome), readyOutcome('runtime-floor')], allChecks);

    if (verdict.exitCode !== EXIT.FAILED) throw new Error(JSON.stringify(verdict));
  });
  control('aggregate/blocked-propagates', () => {
    const outcomes = [readyOutcome(STAGE_IDS[0]), { id: STAGE_IDS[1], status: 'blocked', execution: null, problems: [] },
      ...STAGE_IDS.slice(2).map((id) => ({ id, status: 'not-run', execution: null, problems: [] }))];

    const verdict = aggregate(outcomes, allChecks);

    if (verdict.exitCode !== EXIT.BLOCKED) throw new Error(JSON.stringify(verdict));
  });
  control('aggregate/historical-ready-without-execution', () => {
    const outcomes = STAGE_IDS.map(readyOutcome);

    outcomes[2] = { id: STAGE_IDS[2], status: 'ready', execution: null, problems: [], source: 'phase12-acceptance.json' };

    if (aggregate(outcomes, allChecks).exitCode !== EXIT.FAILED) throw new Error('historical receipt accepted');
  });

  for (const key of ['integrity', 'cleanup', 'artifact']) {
    control(`aggregate/${key}-failure-prevents-ready`, () => {
      if (aggregate(STAGE_IDS.map(readyOutcome), { ...allChecks, [key]: false }).exitCode !== EXIT.FAILED) throw new Error(`${key} ignored`);
    });
  }

  control('classify/timeout-crash-not-rejection', () => {
    const base = { pid: 5, spawnError: null, closeConfirmed: true, timedOut: false, outputLimitExceeded: false, signal: null, exitCode: 0 };

    const cases = [
      [{ ...base, timedOut: true, exitCode: null }, 'timeout'],
      [{ ...base, exitCode: 9 }, 'crashed'],
      [{ ...base, signal: 'SIGKILL', exitCode: null }, 'crashed'],
      [{ ...base, exitCode: 1 }, 'rejected'],
      [{ ...base, exitCode: 3 }, 'blocked'],
      [{ ...base, closeConfirmed: false, timedOut: true }, 'termination-unconfirmed'],
    ];

    for (const [run, expected] of cases) {
      if (classifyChild(run) !== expected) throw new Error(`${JSON.stringify(run)} => ${classifyChild(run)}`);
    }
  });

  for (const stage of STAGES) {
    control(`validator/${stage.id}/accepts-production-shape`, () => {
      const { problems } = stage.validate(syntheticReport(stage.id, context), context);

      if (problems.length > 0) throw new Error(problems.join('; '));
    });
    control(`validator/${stage.id}/rejects-wrong-artifact`, () => {
      const wrong = { ...context, tarball: { ...context.tarball, sha256: 'f'.repeat(64) } };

      if (stage.validate(syntheticReport(stage.id, context), wrong).problems.length === 0) throw new Error('wrong artifact accepted');
    });
  }

  control('validator/runtime-floor/rejects-wrong-floor-runtime', () => {
    const report = syntheticReport('runtime-floor', context);

    report.summary.floor.version = 'v22.23.4';

    if (STAGES[2].validate(report, context).problems.length === 0) throw new Error('later 22 accepted as floor');
  });
  control('validator/framework-node24/rejects-node22-report', () => {
    if (STAGES[5].validate(syntheticReport('framework-node22', context), context).problems.length === 0) throw new Error('node22 report accepted for node24 stage');
  });
  control('validator/types/rejects-missing-case', () => {
    const report = syntheticReport('types-compatibility', context);

    report.cases.pop();

    if (STAGES[1].validate(report, context).problems.length === 0) throw new Error('141 cases accepted');
  });
  control('validator/package/rejects-unverified-cleanup', () => {
    const report = syntheticReport('package-contract', context);

    report.cleanup.verified = false;

    if (STAGES[0].validate(report, context).problems.length === 0) throw new Error('cleanup ignored');
  });

  const failedControls = results.filter((entry) => entry.status !== 'pass');

  return {
    schemaVersion: 1,
    kind: 'phase13-release-candidate-self-test',
    controlsOnly: true,
    result: failedControls.length === 0 ? 'self-test-passed' : 'self-test-failed',
    exitCode: failedControls.length === 0 ? EXIT.READY : EXIT.FAILED,
    controls: results,
    note: 'harness-only; no product qualification was performed',
  };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function emit(report) {
  const summary = {
    kind: report.kind,
    result: report.result,
    exitCode: report.exitCode,
    controlsOnly: report.controlsOnly ?? false,
    artifactSha256: report.artifact?.sha256 ?? null,
    stages: Array.isArray(report.stages) ? report.stages.map((stage) => `${stage.id}:${stage.status}`) : undefined,
    reason: report.reason,
    problems: report.problems,
    resultsFile: report.resultsFile,
  };

  process.stdout.write(`PHASE13_RELEASE_CANDIDATE ${JSON.stringify(summary)}\n`);
}

function writeResults(target, report) {
  validateResultsDestination(target, REPO_ROOT);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
}

export async function main(argv) {
  let options;
  let results = null;

  try {
    options = parseArguments(argv);

    if (options.results !== null) results = validateResults(options.results, options.tarball === null ? null : path.resolve(options.tarball));
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;

    process.stderr.write(`release-candidate: ${error.message}\n`);

    return EXIT.USAGE;
  }

  if (options.help) {
    process.stdout.write(`${USAGE}\n`);

    return EXIT.READY;
  }

  if (options.selfTest) {
    const report = runSelfTest();

    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

    return report.exitCode;
  }

  const startedAt = new Date().toISOString();
  const inputs = await validateInputs(options);

  if (inputs.kind !== 'ok') {
    const report = {
      schemaVersion: 1,
      kind: 'phase13-release-candidate',
      controlsOnly: false,
      result: inputs.kind,
      exitCode: inputs.kind === 'blocked' ? EXIT.BLOCKED : EXIT.FAILED,
      reason: inputs.reason,
      startedAt,
      host: { node: process.version, platform: process.platform, arch: process.arch, tar: inputs.tar ?? null },
      artifact: inputs.tarball ?? null,
      runtimes: inputs.runtimes ?? null,
      stages: STAGES.map((stage) => ({ id: stage.id, status: 'not-run' })),
      note: 'rejected before any stage directory, temp root or gate execution',
    };

    if (results !== null) {
      writeResults(results.target, report);
      report.resultsFile = results.target;
    }

    emit(report);

    return report.exitCode;
  }

  let stageDir;
  let stageDirScratch = false;

  if (results === null) {
    const notes = path.join(REPO_ROOT, 'notes');

    if (!existsSync(notes) || !gitIgnored(path.join(notes, '.release-candidate-probe'))) {
      emit({ kind: 'phase13-release-candidate', result: 'blocked', exitCode: EXIT.BLOCKED, reason: 'no git-ignored notes/ directory for scratch stage reports; pass --results' });

      return EXIT.BLOCKED;
    }

    stageDir = mkdtempSync(path.join(notes, '.release-candidate-'));
    stageDirScratch = true;
  } else {
    mkdirSync(path.dirname(results.stageDir), { recursive: true });
    mkdirSync(results.stageDir);
    stageDir = results.stageDir;
  }

  const report = await runQualification({
    tarball: inputs.tarball,
    runtimes: inputs.runtimes,
    host: { version: process.version, tar: inputs.tar },
    stageDir,
    stageDirScratch,
    runId: randomUUID(),
  });

  report.startedAt = startedAt;
  report.finishedAt = new Date().toISOString();

  if (results !== null) {
    try {
      writeResults(results.target, report);
      report.resultsFile = results.target;
    } catch (error) {
      report.problems.push(`results write failed: ${messageOf(error)}`);
      report.result = 'failed';
      report.exitCode = EXIT.FAILED;
    }
  }

  emit(report);

  return report.exitCode;
}

const invokedDirectly = process.argv[1] !== undefined && samePath(process.argv[1], fileURLToPath(import.meta.url));

if (invokedDirectly) {
  process.exitCode = await main(process.argv.slice(2));
}
