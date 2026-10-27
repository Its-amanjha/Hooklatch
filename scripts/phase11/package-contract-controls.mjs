#!/usr/bin/env node
/**
 * Phase11 package-contract gate - scripted controls (offline).
 *
 * Every control runs the DELIVERED gate (`package-contract.mjs`) as a bounded
 * child process, against either the explicit candidate tarball, a mutated
 * repacked copy of it, or (for default-mode and integrity controls) an
 * isolated owned-temp checkout built from the seed. Each control asserts that
 * a defect reaches EXACTLY its intended check id or classification (never a
 * blanket failure or a silent skip), and positive controls assert real PASS.
 *
 * Coverage:
 *  - pristine seed qualification passes (exit 0, every check verdict pass,
 *    zero findings, cleanup and checkout integrity verified by the gate);
 *  - the gate's own embedded self-test battery passes as a child;
 *  - missing required tarball member (.d.cts) -> tarball-target-presence;
 *  - reordered top-level condition keys -> exports-structure-exact AND
 *    exports-entry-shape (order is part of the frozen contract);
 *  - `types` shadowed below `import`/`default` -> exports-entry-shape;
 *  - wrong `main`, wrong `bin`, non-optional peer meta -> manifest-fields;
 *  - nonempty `optionalDependencies` and nonempty `bundledDependencies` ->
 *    manifest-fields (zero runtime dependencies includes optional/bundled);
 *  - additional public subpath in the manifest -> public-entries-sync with
 *    public-entries-manifest-only (no silent subpath additions);
 *  - omitted `fal` and duplicated `polar` in BOTH provider registry graphs
 *    -> provider-registry-sync (registry stays in both-direction sync);
 *  - candidate registries are evaluated ONLY in the gate's bounded child:
 *    a throwing registry is a semantic provider-registry-import finding,
 *    a never-settling registry and a hard-exiting registry are honest
 *    infrastructure not-run outcomes with confirmed termination;
 *  - complete AST-bound graph checks: a declaration import-type of a missing
 *    .cjs member (real ImportTypeNode), a spaced `require ( 'bare' )` call, a
 *    spaced dynamic import() with a .js specifier, and a nonliteral dynamic
 *    import() are each rejected by their intended check; commented/string
 *    require payloads produce NO false findings;
 *  - declaration edges resolve TYPE members, not runtime twins: a relative
 *    `./x.cjs` specifier in a .d.cts/.d.ts member resolves to the canonical
 *    sibling `x.d.cts` (TypeScript Node16/NodeNext), for ordinary imports,
 *    import-types and facade reexports. Removing an INTERNAL declaration while
 *    its runtime twin stays present fails `declaration-edges` (never silently
 *    passes), removing a declaration reached only through another declaration
 *    import-type fails the same check, intact twins pass, and deleting a
 *    runtime member never passes on its declaration twin;
 *  - mid-run watchers are BOUND to one gate run: each watched base is an owned
 *    scratch child passed to the gate child through its own env, the watcher
 *    requires a run marker, acknowledges readiness before the gate starts,
 *    acknowledges its single mutation, and is stopped with confirmed
 *    termination BEFORE scratch cleanup. An unrelated gate-like temp root (and
 *    another base's gate root) cannot trigger a watcher, and an early BLOCKED
 *    gate never leaves a writer alive;
 *  - a CJS graph edge leaving dist/cjs (require("../index.js")) ->
 *    cjs-graph-edges with cjs-edge-escapes-cjs (no CJS->ESM fallback);
 *  - a broken facade export line -> facade-module-shape;
 *  - a leaked private file (src/leaked.js) -> tarball-member-shape with a
 *    tarball-forbidden-path finding;
 *  - archive member types: a symlink member, a hardlink member, a character
 *    device member and a duplicate member name are each rejected at
 *    tarball-member-shape, extraction and install are explicitly not-run,
 *    and an outside-the-gate-temp sentinel file keeps its exact bytes;
 *  - corrupt/truncated tarball -> tarball-read fails (exit 1, never pass);
 *  - runtime probe hardening: a candidate CJS root that registers a
 *    beforeExit hook forcing exit 9, a candidate that calls process.abort(),
 *    a candidate whose output exceeds the capture limit, and a candidate
 *    that hangs forever each yield infrastructure not-run outcomes for the
 *    runtime checks only (static checks still pass) - a nonzero-exit or
 *    truncated-report child can never smuggle passing phases through;
 *  - portable readiness: default mode in an isolated CONTROLLED nonready
 *    checkout BLOCKS with exit 3 and provably allocates no gate temp root,
 *    while default mode in an isolated ready checkout (seed metadata +
 *    original dist + additive dist/cjs + dist/node, git-tracked, junctioned
 *    node_modules) packs and qualifies PASS 23/23; a variant whose manifest
 *    declares a prepack sentinel hook proves the hardened pack command never
 *    executes pack lifecycle scripts;
 *  - symmetric integrity: an additive-file edit and an additive-file deletion
 *    detected mid-run in an owned-temp ready checkout each surface as an
 *    integrity-change failure, and the change list contains no `added`
 *    entries (the old asymmetric-scope defect);
 *  - the gate copied outside any checkout -> BLOCKED exit 3 before any work;
 *  - usage errors: unknown flag and missing --tarball value -> exit 2 with a
 *    single stderr line; an existing --results destination is refused with
 *    exit 2 and its sentinel content preserved; a junction-ancestor results
 *    destination is refused with exit 2 and the outside sentinel directory
 *    keeps its bytes; a claim-pattern destination (notes/...-session.json)
 *    is refused; a destination created concurrently mid-run makes the final
 *    exclusive `wx` write fail safely (EEXIST) with the concurrent bytes
 *    preserved.
 *
 * Scratch safety: every scratch directory is one `mkdtemp` child of the OS
 * temp directory, recorded in a ledger. Removal verifies the immediate-child
 * containment, refuses to follow symbolic links, and re-checks that the
 * real repo node_modules (junction target) still exists afterwards. When any
 * child termination is uncertain (controls-level spawn timeout), remaining
 * scratch is PRESERVED and the suite fails instead of being cleaned up and
 * reported as a passing negative control.
 *
 * Watcher safety: a watcher is spawned attached (never detached/unref-forget)
 * with its PID in the watcher ledger; it is passed its own watched base, run
 * marker and acknowledgment paths, and it can only touch a target inside the
 * owned run root. It is stopped (confirmed exit) in `finally` before the
 * suite's cleanup phase; a watcher that cannot be confirmed stopped preserves
 * its scratch and fails the suite.
 *
 * Coverage accounting: each declared control reports exactly one of
 * passed/failed/blocked/not-run. A control whose mandatory OS capability is
 * unavailable (the dangling FILE symlink vector) is BLOCKED with its reason;
 * a genuine failure stays FAIL. Full PASS (exit 0) requires the full declared
 * control set executed, every execution passed, and cleanup verified. A
 * blocked/not-run control (or a diagnostics-only `--only` subset) makes the
 * suite INCOMPLETE/BLOCKED with exit 3 - never a full PASS.
 *
 * Environment limits (documented honestly):
 *  - this host cannot create file symlinks unprivileged (EPERM), so the
 *    dangling-file-link vector cannot execute here; that control reports
 *    BLOCKED (exit 3 for the suite) and the junction-ancestor vector stands in
 *    for the link-ancestor rule. The junction proof does NOT execute dangling
 *    FILE symlink semantics; a Linux executor must run that control;
 *  - the isolated ready checkouts use the frozen seed metadata, so they do
 *    not depend on private tasks or on this worktree's live package state.
 *
 * Usage: node scripts/phase11/package-contract-controls.mjs --seed FILE
 *        node scripts/phase11/package-contract-controls.mjs --self-test-aggregation
 *        (--only name1,name2 runs a diagnostics-only subset; a partial
 *        selection can never report suite status pass)
 *
 * Exit codes:
 *   0  PASS    - the full control set executed and every control passed
 *   1  FAIL    - one or more controls failed, or cleanup was not verified
 *   2  USAGE   - invalid controls invocation
 *   3  BLOCKED - no failure, but coverage is incomplete (a mandatory control
 *                could not execute on this host, or --only selected a subset);
 *                a BLOCKED suite is never a full PASS
 */

import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync,
  renameSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { POLICY_PROVIDERS, isPlainRecord } from './package-contract.mjs';

const EXIT = { PASS: 0, FAIL: 1, USAGE: 2, BLOCKED: 3 };
const TAR_TIMEOUT_MS = 60_000;
const GATE_TIMEOUT_MS = 480_000;
const FAST_GATE_TIMEOUT_MS = 120_000;
const PYTHON_TIMEOUT_MS = 120_000;
const GIT_TIMEOUT_MS = 60_000;
const MUTATED_BYTES_LIMIT = 4096;
const GATE_TEMP_PREFIX = 'hooklatch-phase11-contract-';
const WATCHER_START_TIMEOUT_MS = 15_000;
const WATCHER_STOP_TIMEOUT_MS = 15_000;
const WATCHER_SETTLE_MS = 500;
const WATCHER_DEADLINE_MS = GATE_TIMEOUT_MS + 60_000;

/** Checks explicitly not-run when extraction is blocked by member findings. */
const EXTRACTION_BLOCKED_NOT_RUN = Object.freeze([
  'manifest-load',
  'public-entries-sync',
  'exports-structure-exact',
  'exports-entry-shape',
  'manifest-fields',
  'provider-registry-sync',
  'cjs-graph-edges',
  'facade-graph-edges',
  'declaration-edges',
  'facade-module-shape',
  'cli-shebang',
  'original-esm-baseline-pin',
  'install-offline',
  'esbuild-neutral-original-esm',
  'declaration-resolution',
  'runtime-resolutions',
  'runtime-forbidden-deep',
  'runtime-identity-functional',
  'runtime-cli',
]);

/** Runtime checks refused when the probe child's phases cannot be trusted. */
const RUNTIME_NOT_RUN = Object.freeze([
  'runtime-resolutions',
  'runtime-forbidden-deep',
  'runtime-identity-functional',
  'runtime-cli',
]);

const ledger = { entries: [], uncertain: false };
const watcherLedger = [];
let nodeModulesSource = null;
let gatePathGlobal = null;
let lastGateReport = null;

/* -------------------------------------------------------------------------- */
/* assertion helpers                                                          */
/* -------------------------------------------------------------------------- */

/** Assert deep equality via stable JSON; throw with the control label. */
function expectEqual(actual, expected, label) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);

  if (actualJson !== expectedJson) {
    throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
  }
}

/** Assert the gate report failed with every listed check id among the failures. */
function expectFailedChecks(report, label, expectedIds) {
  if (report.status !== 'fail') {
    throw new Error(`${label}: expected status 'fail', got ${JSON.stringify(report.status)}`);
  }

  if (report.exit !== 1) {
    throw new Error(`${label}: expected exit 1, got ${JSON.stringify(report.exit)}`);
  }

  const failed = report.summary.failedCheckIds;

  for (const expectedId of expectedIds) {
    if (!failed.includes(expectedId)) {
      throw new Error(`${label}: expected failing check '${expectedId}' among ${JSON.stringify(failed)}`);
    }
  }

  if (report.cleanup.verified !== true) {
    throw new Error(`${label}: gate child did not verify its own temp cleanup`);
  }
}

/** Assert the listed check ids are exactly the report's not-run checks. */
function expectNotRunChecks(report, label, expectedIds) {
  if (report.status !== 'fail') {
    throw new Error(`${label}: expected status 'fail', got ${JSON.stringify(report.status)}`);
  }

  if (report.exit !== 1) {
    throw new Error(`${label}: expected exit 1, got ${JSON.stringify(report.exit)}`);
  }

  const sortedActual = [...report.summary.notRunCheckIds].sort();
  const sortedExpected = [...expectedIds].sort();

  if (JSON.stringify(sortedActual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${label}: expected not-run checks ${sortedExpected.join(',')}, got ${sortedActual.join(',')}`);
  }

  expectEqual(report.cleanup.verified, true, `${label} gate cleanup`);
}

/** Assert the report's global findingKinds include every listed kind. */
function expectFindingKinds(report, label, expectedKinds) {
  for (const kind of expectedKinds) {
    if (!report.summary.findingKinds.includes(kind)) {
      throw new Error(`${label}: expected finding kind '${kind}' among ${JSON.stringify(report.summary.findingKinds)}`);
    }
  }
}

/** Assert one check's evidence contains a matching item. */
function expectCheckEvidence(report, label, checkId, predicate, description) {
  const check = report.checks.find((entry) => entry.id === checkId);

  if (check === undefined) {
    throw new Error(`${label}: check '${checkId}' absent from report`);
  }

  const evidence = Array.isArray(check.evidence)
    ? check.evidence
    : (isPlainRecord(check.evidence) ? [check.evidence] : []);

  if (!evidence.some((item) => predicate(item))) {
    throw new Error(`${label}: ${description} not found in '${checkId}' evidence: ${JSON.stringify(evidence).slice(0, 400)}`);
  }
}

/** Assert exit 2 with exactly one stderr line (optionally containing a fragment). */
function expectUsageStderr(child, label, fragment) {
  if (child.status !== 2) {
    throw new Error(`${label}: expected exit 2, got ${JSON.stringify(child.status)}`);
  }

  const stderrLines = (child.stderr ?? '').trimEnd().split('\n');

  if (stderrLines.length !== 1 || stderrLines[0] === '') {
    throw new Error(`${label}: expected exactly one stderr line, got ${JSON.stringify(stderrLines)}`);
  }

  if (fragment !== undefined && !stderrLines[0].includes(fragment)) {
    throw new Error(`${label}: stderr lacks '${fragment}': ${stderrLines[0]}`);
  }
}

/** Assert a full PASS report with all checks passing and clean integrity. */
function expectFullPass(report, label) {
  expectEqual(report.status, 'pass', `${label} status`);
  expectEqual(report.exit, 0, `${label} exit`);
  expectEqual(report.summary.failedCheckIds, [], `${label} failed checks`);
  expectEqual(report.summary.notRunCheckIds, [], `${label} not-run checks`);
  expectEqual(report.findings, [], `${label} findings`);
  expectEqual(report.cleanup.verified, true, `${label} cleanup`);
  expectEqual(report.integrity.changed, [], `${label} integrity`);

  const notPassing = report.checks.filter((check) => check.verdict !== 'pass');

  if (notPassing.length > 0) {
    throw new Error(`${label}: checks with a non-pass verdict: ${JSON.stringify(notPassing).slice(0, 400)}`);
  }
}

/* -------------------------------------------------------------------------- */
/* bounded children                                                           */
/* -------------------------------------------------------------------------- */

function boundedText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
}

function runTar(args) {
  const child = spawnSync('tar', args, {
    encoding: 'utf8', timeout: TAR_TIMEOUT_MS, windowsHide: true, maxBuffer: 16 * 1024 * 1024,
  });

  if (child.error !== undefined && child.error.code === 'ETIMEDOUT') {
    ledger.uncertain = true;
    throw new Error(`tar ${args.join(' ')} timed out after ${TAR_TIMEOUT_MS}ms`);
  }

  if (child.status !== 0) {
    throw new Error(`tar ${args.join(' ')} failed (${child.status}): ${boundedText(child.stderr)}`);
  }
}

/**
 * Run one Node script as a bounded child. `tempBase`, when given, is passed
 * through the child's OWN env (TMPDIR/TMP/TEMP) so the child's os.tmpdir()
 * resolves to a per-control base; the parent process env is never mutated and
 * no other agent's temp roots are involved. Returns {status, stdout, stderr}.
 */
function runNodeChild(scriptPath, args, timeout, tempBase) {
  const env = tempBase === undefined
    ? process.env
    : { ...process.env, TMPDIR: tempBase, TMP: tempBase, TEMP: tempBase };
  const child = spawnSync(process.execPath, [scriptPath, ...args], {
    encoding: 'utf8',
    timeout,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
    env,
  });

  if (child.error !== undefined && child.error.code === 'ETIMEDOUT') {
    /* The direct child was killed, but its own children (npm, taskkill
     * targets) may outlive it: termination is uncertain, so the ledger
     * preserves scratch instead of deleting it and calling that a pass. */
    ledger.uncertain = true;
    throw new Error(`node child timed out after ${timeout}ms: ${JSON.stringify([scriptPath, ...args])}`);
  }

  if (child.status === null) {
    ledger.uncertain = true;
    throw new Error(`node child terminated abnormally (signal ${JSON.stringify(child.signal)}): ${JSON.stringify([scriptPath, ...args])}`);
  }

  return child;
}

/** Run the delivered gate as a bounded child in an optional isolated temp base. */
function runGateChild(gatePath, args, timeout, tempBase) {
  return runNodeChild(gatePath, args, timeout, tempBase);
}

/** Run a python heredoc child (tarball crafting); marks uncertainty on timeout. */
function runPython(script, args, label) {
  const child = spawnSync('python', ['-', ...args], {
    encoding: 'utf8', input: script, timeout: PYTHON_TIMEOUT_MS, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  });

  if (child.error !== undefined && child.error.code === 'ETIMEDOUT') {
    ledger.uncertain = true;
    throw new Error(`${label}: python child timed out`);
  }

  if (child.status !== 0) {
    throw new Error(`${label}: python child failed (${child.status}): ${boundedText(child.stderr)}`);
  }

  return child.stdout;
}

/** Run one git command; fails the control when git exits nonzero. */
function runGit(cwd, args) {
  const child = spawnSync('git', args, {
    cwd, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, windowsHide: true,
  });

  if (child.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed (${child.status}): ${boundedText(child.stderr)}`);
  }
}

/** Parse one child's machine-JSON report from its stdout. */
function parseChildJson(child, label) {
  let report = null;

  if (child.stdout !== '') {
    try {
      report = JSON.parse(child.stdout);
    } catch {
      report = null;
    }
  }

  if (report === null || !isPlainRecord(report)) {
    throw new Error(`${label}: child produced no parsable JSON report (status ${child.status}); stderr: ${boundedText(child.stderr)}`);
  }

  return report;
}

/** Parse the gate's machine-JSON report from a child's stdout. */
function parseGateReport(child, label) {
  const report = parseChildJson(child, label);

  lastGateReport = report;

  return report;
}

/** Compact embedded-gate-report summary for the suite JSON (diagnostics). */
function compactGateReport(report) {
  if (report === null) return null;

  return {
    status: report.status ?? null,
    exit: report.exit ?? null,
    mode: report.mode ?? null,
    failedCheckIds: Array.isArray(report.summary?.failedCheckIds) ? report.summary.failedCheckIds : [],
    notRunCheckIds: Array.isArray(report.summary?.notRunCheckIds) ? report.summary.notRunCheckIds : [],
    findingKinds: Array.isArray(report.summary?.findingKinds) ? report.summary.findingKinds : [],
    integrityChanged: Array.isArray(report.integrity?.changed) ? report.integrity.changed : [],
    infrastructureError: report.infrastructureError ?? null,
  };
}

/* -------------------------------------------------------------------------- */
/* ledgered scratch roots                                                     */
/* -------------------------------------------------------------------------- */

/** Record a scratch root in the ledger; returns the root. */
function ledgerRoot(root, label) {
  ledger.entries.push({ root, label, state: 'active' });

  return root;
}

async function newScratchRoot(label) {
  const root = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-control-'));

  return ledgerRoot(root, label);
}

/**
 * Classify and perform the removal of ONE owned-temp scratch root.
 * Classifications: removed | absent | refused-outside-temp |
 * refused-no-follow | refused-leftover | refused-junction-followed.
 * Only `removed` and `absent` count as verified cleanup.
 */
async function removeLedgerRoot(root) {
  const resolved = path.resolve(root);
  const tempBase = path.resolve(tmpdir());

  if (path.dirname(resolved) !== tempBase || resolved === tempBase || !resolved.startsWith(`${tempBase}${path.sep}`)) {
    return 'refused-outside-temp';
  }

  let rootStat = null;

  try {
    rootStat = lstatSync(resolved);
  } catch {
    return 'absent';
  }

  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return 'refused-no-follow';

  try {
    await rm(resolved, { recursive: true, force: false });
  } catch {
    return existsSync(resolved) ? 'refused-leftover' : 'absent';
  }

  if (existsSync(resolved)) return 'refused-leftover';

  /* No-follow guard: the real repo node_modules is the TARGET of junctions
   * used inside ready checkouts; if it vanished, something followed a link. */
  if (nodeModulesSource !== null && !existsSync(nodeModulesSource)) {
    return 'refused-junction-followed';
  }

  return 'removed';
}

/* -------------------------------------------------------------------------- */
/* mutation pipeline (extracted copies of the explicit seed, repacked)        */
/* -------------------------------------------------------------------------- */

/** Extract the seed into a ledgered temp root; returns the package dir. */
async function extractSeed(seedPath, label) {
  const root = await newScratchRoot(label);
  const extractDir = path.join(root, 'extract');

  await mkdir(extractDir, { recursive: true });
  runTar(['-xf', seedPath, '-C', extractDir]);

  const packageDir = path.join(extractDir, 'package');

  if (!existsSync(path.join(packageDir, 'package.json'))) {
    throw new Error(`${label}: seed extraction produced no package/package.json`);
  }

  return { root, packageDir };
}

/** Repack an extracted package/ tree with the system tar. */
function repack(packageDir, label) {
  const root = path.dirname(path.dirname(packageDir));
  const mutatedTarball = path.join(root, 'mutated.tgz');

  runTar(['-czf', mutatedTarball, '-C', path.dirname(packageDir), 'package']);

  if (!existsSync(mutatedTarball) || statSync(mutatedTarball).size === 0) {
    throw new Error(`${label}: repacked tarball is missing or empty`);
  }

  return mutatedTarball;
}

/** Apply one text replacement and require the exact expected occurrence count. */
function replaceExactly(text, needle, replacement, expectedCount, label) {
  const parts = text.split(needle);
  const count = parts.length - 1;

  if (count !== expectedCount) {
    throw new Error(`${label}: expected ${expectedCount} occurrence(s) of ${JSON.stringify(needle)}, found ${count}`);
  }

  return parts.join(replacement);
}

/** Append a payload to a package file, guaranteeing newline separation. */
function appendToFile(packageDir, segments, snippet, label) {
  const filePath = path.join(packageDir, ...segments);
  const original = readFileSync(filePath, 'utf8');
  const separator = original.endsWith('\n') ? '' : '\n';
  const next = `${original}${separator}${snippet}`;

  if (next === original) {
    throw new Error(`${label}: append did not change ${filePath}`);
  }

  writeFileSync(filePath, next, { encoding: 'utf8' });
}

/** Rewrite the package manifest with one mutation applied. */
function mutateManifest(packageDir, label, mutateFn) {
  const manifestPath = path.join(packageDir, 'package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  mutateFn(manifest);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
}

/** Extract, mutate, repack, run the gate child, parse its report. */
async function runMutatedGate(gatePath, seedPath, label, mutateFn) {
  const { packageDir } = await extractSeed(seedPath, label);
  const mutatedTarball = repack(mutateFn(packageDir) ?? packageDir, label);
  const child = runGateChild(gatePath, ['--tarball', mutatedTarball], GATE_TIMEOUT_MS);

  return { child, report: parseGateReport(child, label) };
}

/* -------------------------------------------------------------------------- */
/* crafted member-type tarballs (python tarfile; see control implementations)  */
/* -------------------------------------------------------------------------- */

const PY_CRAFT_TEMPLATE = `import base64, io, json, sys, tarfile

seed_path, out_path, spec = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
types = {
    "sym": tarfile.SYMTYPE,
    "hard": tarfile.LNKTYPE,
    "chr": tarfile.CHRTYPE,
    "blk": tarfile.BLKTYPE,
    "fifo": tarfile.FIFOTYPE,
    "reg": tarfile.REGTYPE,
}
with tarfile.open(seed_path, "r:gz") as source, tarfile.open(out_path, "w:gz") as target:
    for member in source.getmembers():
        payload = source.extractfile(member) if member.isreg() else None
        target.addfile(member, payload)
    for extra in spec.get("extras", []):
        info = tarfile.TarInfo(extra["name"])
        info.type = types[extra["type"]]
        info.linkname = extra.get("link", "")
        data = base64.b64decode(extra.get("data", ""))
        info.size = len(data)
        target.addfile(info, io.BytesIO(data) if info.type == tarfile.REGTYPE else None)
    for duplicate in spec.get("duplicates", []):
        data = base64.b64decode(duplicate["data"])
        info = tarfile.TarInfo(duplicate["name"])
        info.type = tarfile.REGTYPE
        info.size = len(data)
        target.addfile(info, io.BytesIO(data))
print("crafted")
`;

/** Build a seed copy plus crafted extra/duplicate members via python tarfile. */
function craftSeedTarball(seedPath, root, label, spec) {
  const crafted = path.join(root, 'crafted.tgz');

  runPython(PY_CRAFT_TEMPLATE, [seedPath, crafted, JSON.stringify(spec)], label);

  if (!existsSync(crafted) || statSync(crafted).size === 0) {
    throw new Error(`${label}: crafted tarball is missing or empty`);
  }

  return crafted;
}

/* -------------------------------------------------------------------------- */
/* isolated ready / nonready checkouts                                        */
/* -------------------------------------------------------------------------- */

/**
 * Source of ONE run-bound watcher child. It watches ONLY its own watched base,
 * requires the run marker to match its run id for the whole run, performs at
 * most one mutation inside the owned run root, acknowledges readiness,
 * mutation, stop and deadline states, and never scans unrelated temp roots.
 */
function watcherSource() {
  return `/* Phase11 control watcher: bound to exactly ONE gate run. */
import fs from 'node:fs';
import path from 'node:path';

const [watchedBase, markerPath, armedPath, outcomePath, stopPath, mode, target, runId, payload, deadlineRaw, allowedRoot] = process.argv.slice(2);
const deadline = Date.now() + Number(deadlineRaw);

const writeState = (file, value) => {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value));
  fs.renameSync(temp, file);
};

const readMarker = () => {
  try {
    return JSON.parse(fs.readFileSync(markerPath, 'utf8'));
  } catch {
    return null;
  }
};

const refuse = (reason) => {
  writeState(outcomePath, { state: 'refused', reason, mutation: 'none', pid: process.pid, runId, at: new Date().toISOString() });
  process.exit(3);
};

const finish = (state, mutation, watchedRoot) => {
  writeState(outcomePath, { state, mutation, watchedRoot, pid: process.pid, runId, at: new Date().toISOString() });
  process.exit(0);
};

const contains = (root, candidate) => {
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);

  return resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(resolvedRoot + path.sep);
};

const marker = readMarker();

if (marker === null || marker.runId !== runId || marker.watchedRoot !== watchedBase) refuse('run marker mismatch');
if (!contains(allowedRoot, target)) refuse('target outside the owned run root');
if (contains(watchedBase, target)) refuse('target inside the watched gate temp base');
if (!contains(allowedRoot, watchedBase)) refuse('watched base outside the owned run root');

const initial = new Set(fs.readdirSync(watchedBase));

writeState(armedPath, { state: 'armed', pid: process.pid, runId, watchedRoot: watchedBase, target, mode, at: new Date().toISOString() });

const tick = () => {
  if (fs.existsSync(stopPath)) {
    finish('stopped', 'none', null);
    return;
  }

  const current = readMarker();

  if (current === null || current.runId !== runId) refuse('run marker changed during the run');

  try {
    const fresh = fs.readdirSync(watchedBase)
      .filter((name) => name.startsWith('${GATE_TEMP_PREFIX}') && !initial.has(name))
      .map((name) => path.join(watchedBase, name));

    if (fresh.length > 0 && fs.existsSync(path.join(fresh[0], 'extract', 'package', 'package.json'))) {
      if (mode === 'append') fs.appendFileSync(target, '// integrity-probe mutation (comment only)\\n');
      if (mode === 'delete') fs.rmSync(target, { force: true });
      if (mode === 'write') fs.writeFileSync(target, payload);
      finish('mutated', mode, fresh[0]);
      return;
    }
  } catch {
    /* transient FS races during polling are ignored */
  }

  if (Date.now() > deadline) {
    finish('deadline', 'none', null);
    return;
  }

  setTimeout(tick, 100);
};

tick();
`;
}

function readJsonOrNull(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function childExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

async function waitForExit(child, timeoutMs) {
  if (childExited(child)) return true;

  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;

      settled = true;
      resolve(false);
    }, timeoutMs);

    child.once('exit', () => {
      if (settled) return;

      settled = true;
      clearTimeout(timer);
      resolve(true);
    });
  });
}

async function waitForWatcherState(handle, file, timeoutMs) {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const value = readJsonOrNull(file);

    if (value !== null) return value;
    if (handle.spawnError !== null || childExited(handle.child)) return null;
    if (Date.now() > deadline) return null;

    await sleep(50);
  }
}

/**
 * Spawn ONE run-bound watcher, retain its child handle in the watcher ledger,
 * and wait for its bounded readiness acknowledgment BEFORE the gate starts.
 * The watched base is an owned scratch child created here and handed to the
 * gate child through that child's own env, never the parent process env.
 */
async function startWatcher(root, label, mode, target, payload) {
  const watcherDir = path.join(root, 'watcher');
  const watchedBase = path.join(root, 'gate-tmp');
  const runId = randomUUID();
  const watcherPath = path.join(watcherDir, 'watcher.mjs');
  const markerPath = path.join(watcherDir, 'run.json');
  const armedPath = path.join(watcherDir, 'armed.json');
  const outcomePath = path.join(watcherDir, 'outcome.json');
  const stopPath = path.join(watcherDir, 'stop.txt');

  await mkdir(watcherDir, { recursive: true });
  await mkdir(watchedBase, { recursive: true });
  writeFileSync(watcherPath, watcherSource(), { encoding: 'utf8' });
  writeFileSync(markerPath, `${JSON.stringify({ runId, label, watchedRoot: watchedBase, target, mode })}\n`, { encoding: 'utf8' });

  const child = spawn(process.execPath, [
    watcherPath, watchedBase, markerPath, armedPath, outcomePath, stopPath,
    mode, target, runId, payload === undefined ? '' : payload, String(WATCHER_DEADLINE_MS), root,
  ], { stdio: 'ignore', windowsHide: true });

  const record = {
    label,
    runId,
    pid: child.pid ?? null,
    watchedRoot: watchedBase,
    target,
    mode,
    state: 'starting',
    mutation: 'none',
    termination: 'unknown',
    exitCode: null,
    startedAt: new Date().toISOString(),
    stoppedAt: null,
  };

  watcherLedger.push(record);

  const handle = { child, record, runId, watchedRoot: watchedBase, watcherDir, outcomePath, stopPath, spawnError: null };

  child.once('error', (error) => {
    handle.spawnError = boundedText(error);
  });

  const armed = await waitForWatcherState(handle, armedPath, WATCHER_START_TIMEOUT_MS);

  if (armed === null || armed.state !== 'armed' || armed.runId !== runId) {
    record.state = 'failed-start';
    const stopped = await terminateWatcher(handle);

    throw new Error(`${label}: watcher did not acknowledge readiness within ${WATCHER_START_TIMEOUT_MS}ms (pid ${record.pid}, state ${JSON.stringify(armed)}, spawn error ${JSON.stringify(handle.spawnError)}, termination ${stopped ? 'confirmed' : 'unconfirmed; own scratch preserved'})`);
  }

  record.state = 'armed';

  return handle;
}

/** Stop one watcher and confirm termination; records the outcome in the ledger. */
async function terminateWatcher(handle) {
  const { child, record, outcomePath, stopPath } = handle;

  if (!childExited(child)) {
    try {
      writeFileSync(stopPath, `${new Date().toISOString()}\n`, { encoding: 'utf8' });
    } catch {
      /* a missing stop marker still falls through to the kill path */
    }
  }

  let exited = await waitForExit(child, WATCHER_STOP_TIMEOUT_MS);

  if (!exited) {
    child.kill();
    exited = await waitForExit(child, WATCHER_STOP_TIMEOUT_MS);
  }

  const outcome = readJsonOrNull(outcomePath);

  record.outcome = outcome === null ? null : { state: outcome.state, mutation: outcome.mutation ?? 'none' };
  record.exitCode = child.exitCode;

  if (outcome !== null && typeof outcome.mutation === 'string') record.mutation = outcome.mutation;

  record.stoppedAt = new Date().toISOString();

  if (!exited) {
    ledger.uncertain = true;
    record.state = 'stop-unconfirmed';
    record.termination = 'unconfirmed';

    return false;
  }

  record.state = 'stopped';
  record.termination = outcome !== null && outcome.state === 'mutated' ? 'exited-after-mutation' : 'stopped-ack';

  return true;
}

/** Stop a watcher in `finally`; an unconfirmed stop fails and preserves scratch. */
async function stopWatcher(handle) {
  const confirmed = await terminateWatcher(handle);

  if (!confirmed) {
    throw new Error(`${handle.record.label}: watcher pid ${handle.record.pid} did not confirm termination; own scratch preserved`);
  }

  return handle.record;
}

/** Wait for the intended mutation acknowledgment; a stop/deadline is a failure. */
async function requireWatcherMutation(handle, label) {
  const outcome = await waitForWatcherState(handle, handle.outcomePath, WATCHER_STOP_TIMEOUT_MS);

  if (outcome === null) {
    throw new Error(`${label}: watcher produced no mutation acknowledgment (pid ${handle.record.pid}, spawn error ${JSON.stringify(handle.spawnError)})`);
  }

  if (outcome.state !== 'mutated') {
    throw new Error(`${label}: watcher outcome ${JSON.stringify(outcome.state)} is not the intended mutation`);
  }

  if (outcome.runId !== handle.runId) {
    throw new Error(`${label}: watcher mutation acknowledgment run id mismatch`);
  }

  return outcome;
}

/** Compact watcher evidence (PID, run binding, target, termination status). */
function watcherNote(handle) {
  const { record } = handle;

  return {
    watcher: {
      label: record.label,
      runId: record.runId,
      pid: record.pid,
      watchedRoot: record.watchedRoot,
      target: record.target,
      mode: record.mode,
      state: record.state,
      mutation: record.mutation,
      termination: record.termination,
      exitCode: record.exitCode,
    },
  };
}

/** Build an isolated ready checkout (seed metadata + dist) for default mode. */
async function buildReadyCheckout(root, gatePath, seedPath, options = {}) {
  const ready = path.join(root, 'ready');
  const gateScripts = path.join(ready, 'scripts', 'phase11');

  await mkdir(gateScripts, { recursive: true });
  copyFileSync(gatePath, path.join(gateScripts, 'package-contract.mjs'));

  const extractDir = path.join(root, 'seed-extract');

  await mkdir(extractDir, { recursive: true });
  runTar(['-xf', seedPath, '-C', extractDir]);

  const packageDir = path.join(extractDir, 'package');

  for (const entry of readdirSync(packageDir)) {
    renameSync(path.join(packageDir, entry), path.join(ready, entry));
  }

  await rm(extractDir, { recursive: true, force: true });

  writeFileSync(path.join(ready, 'README.md'), '# hooklatch\n\nSynthetic ready checkout for gate controls.\n', { encoding: 'utf8' });
  writeFileSync(path.join(ready, 'LICENSE'), 'Synthetic license text.\n', { encoding: 'utf8' });
  writeFileSync(path.join(ready, '.gitignore'), 'node_modules/\n', { encoding: 'utf8' });

  if (options.integrityProbe) {
    writeFileSync(path.join(ready, 'integrity-probe.txt'), 'owned-temp integrity probe target\n', { encoding: 'utf8' });
  }

  symlinkSync(nodeModulesSource, path.join(ready, 'node_modules'), 'junction');

  runGit(ready, ['init']);
  runGit(ready, ['add', '-A', '.']);

  if (options.prepackSentinel) {
    mutateManifest(ready, 'prepack-sentinel', (manifest) => {
      const scripts = isPlainRecord(manifest.scripts) ? manifest.scripts : {};

      scripts.prepack = "node -e \"require('fs').writeFileSync('PREPACK_RAN','x')\"";
      manifest.scripts = scripts;
    });
    runGit(ready, ['add', '-A', '.']);
  }

  return ready;
}

/** Build an isolated NONready checkout (no conditional exports, no dist). */
async function buildNonreadyCheckout(root, gatePath) {
  const ready = path.join(root, 'nonready');
  const gateScripts = path.join(ready, 'scripts', 'phase11');

  await mkdir(gateScripts, { recursive: true });
  copyFileSync(gatePath, path.join(gateScripts, 'package-contract.mjs'));
  writeFileSync(
    path.join(ready, 'package.json'),
    `${JSON.stringify({ name: 'hooklatch', version: '0.0.0', type: 'module', private: true }, null, 2)}\n`,
    { encoding: 'utf8' },
  );
  writeFileSync(path.join(ready, '.gitignore'), 'node_modules/\n', { encoding: 'utf8' });
  symlinkSync(nodeModulesSource, path.join(ready, 'node_modules'), 'junction');
  runGit(ready, ['init']);
  runGit(ready, ['add', '-A', '.']);

  return ready;
}

/** Count existing gate temp roots under one base (default: the OS temp dir). */
function countGateTempRoots(base = tmpdir()) {
  return readdirSync(base).filter((name) => name.startsWith(GATE_TEMP_PREFIX)).length;
}

/* -------------------------------------------------------------------------- */
/* control implementations                                                    */
/* -------------------------------------------------------------------------- */

/** The explicit seed must qualify with every check passing. */
async function controlPristineSeedPass(gatePath, seedPath) {
  const child = runGateChild(gatePath, ['--tarball', seedPath], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'pristine-seed-pass');

  expectFullPass(report, 'pristine-seed-pass');
  expectEqual(report.mode, 'tarball', 'pristine seed mode');
}

/** The gate's embedded self-test battery must pass as a child. */
async function controlGateSelfTest(gatePath) {
  const child = runGateChild(gatePath, ['--self-test'], FAST_GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'gate-self-test');

  expectEqual(report.status, 'pass', 'self-test status');
  expectEqual(report.exit, 0, 'self-test exit');
  expectEqual(report.controlsOnly, true, 'self-test controls-only marker');
  expectEqual(report.summary.failed, 0, 'self-test failed controls');
}

/** Deleting a required .d.cts member must reach tarball-target-presence. */
async function controlMissingDcts(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'missing-dcts', (packageDir) => {
    unlinkSync(path.join(packageDir, 'dist', 'cjs', 'adapters', 'express.d.cts'));
  });

  expectFailedChecks(report, 'missing-dcts', ['tarball-target-presence']);
}

/** Reordered top-level condition keys must reach structure and shape checks. */
async function controlSwappedConditionOrder(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'swapped-condition-order', (packageDir) => {
    mutateManifest(packageDir, 'swapped-condition-order', (manifest) => {
      const dot = manifest.exports['.'];

      manifest.exports['.'] = { types: dot.types, node: dot.node, import: dot.import, default: dot.default };
    });
  });

  expectFailedChecks(
    report,
    'swapped-condition-order',
    ['exports-structure-exact', 'exports-entry-shape'],
  );
}

/** `types` shadowed below import/default must reach exports-entry-shape. */
async function controlTopTypesShadow(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'top-types-shadow', (packageDir) => {
    mutateManifest(packageDir, 'top-types-shadow', (manifest) => {
      const dot = manifest.exports['.'];

      manifest.exports['.'] = { node: dot.node, import: dot.import, default: dot.default, types: dot.types };
    });
  });

  expectFailedChecks(report, 'top-types-shadow', ['exports-entry-shape']);
}

/** A wrong `main` must reach manifest-fields. */
async function controlWrongMain(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'wrong-main', (packageDir) => {
    mutateManifest(packageDir, 'wrong-main', (manifest) => {
      manifest.main = './dist/index.js';
    });
  });

  expectFailedChecks(report, 'wrong-main', ['manifest-fields']);
}

/** A wrong `bin` target must reach manifest-fields. */
async function controlWrongBin(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'wrong-bin', (packageDir) => {
    mutateManifest(packageDir, 'wrong-bin', (manifest) => {
      manifest.bin = { hooklatch: './dist/cli/wrong.js' };
    });
  });

  expectFailedChecks(report, 'wrong-bin', ['manifest-fields']);
}

/** Peer meta that stops being optional must reach manifest-fields. */
async function controlPeerMetaNotOptional(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'peer-meta-not-optional', (packageDir) => {
    mutateManifest(packageDir, 'peer-meta-not-optional', (manifest) => {
      manifest.peerDependenciesMeta.express.optional = false;
    });
  });

  expectFailedChecks(report, 'peer-meta-not-optional', ['manifest-fields']);
}

/** An additional public subpath must reach public-entries-manifest-only. */
async function controlAdditionalSubpath(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'additional-subpath', (packageDir) => {
    mutateManifest(packageDir, 'additional-subpath', (manifest) => {
      manifest.exports['./secret'] = manifest.exports['./diagnostics'];
    });
  });

  expectFailedChecks(report, 'additional-subpath', ['public-entries-sync']);
  expectFindingKinds(report, 'additional-subpath', ['public-entries-manifest-only']);
}

/** Omitting `fal` from BOTH registry graphs must reach provider-registry-sync. */
async function controlOmittedFal(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'omitted-fal', (packageDir) => {
    for (const rel of ['dist/providers/index.js', 'dist/cjs/providers/index.cjs']) {
      const filePath = path.join(packageDir, ...rel.split('/'));
      const original = readFileSync(filePath, 'utf8');

      writeFileSync(filePath, replaceExactly(original, `    'fal',\n`, '', 1, `omitted-fal ${rel}`), { encoding: 'utf8' });
    }
  });

  expectFailedChecks(report, 'omitted-fal', ['provider-registry-sync']);
  expectFindingKinds(report, 'omitted-fal', ['provider-registry-missing']);
}

/** Duplicating `polar` in BOTH registry graphs must reach provider-registry-sync. */
async function controlDuplicatedPolar(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'duplicated-polar', (packageDir) => {
    for (const rel of ['dist/providers/index.js', 'dist/cjs/providers/index.cjs']) {
      const filePath = path.join(packageDir, ...rel.split('/'));
      const original = readFileSync(filePath, 'utf8');

      writeFileSync(filePath, replaceExactly(original, `    'polar',\n`, `    'polar',\n    'polar',\n`, 1, `duplicated-polar ${rel}`), { encoding: 'utf8' });
    }
  });

  expectFailedChecks(report, 'duplicated-polar', ['provider-registry-sync']);
  expectFindingKinds(report, 'duplicated-polar', ['provider-registry-duplicate']);
}

/** A registry module that throws on import must yield an honest import finding. */
async function controlRegistryThrow(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'registry-throw', (packageDir) => {
    const filePath = path.join(packageDir, 'dist', 'providers', 'index.js');
    const original = readFileSync(filePath, 'utf8');

    writeFileSync(filePath, `throw new Error('registry boom');\n${original}`, { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'registry-throw', ['provider-registry-sync']);
  expectFindingKinds(report, 'registry-throw', ['provider-registry-import']);
}

/** A never-settling registry must be an infrastructure not-run, never a pass. */
async function controlRegistryHang(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'registry-hang', (packageDir) => {
    /* The interval keeps the event loop referenced, so the appended
     * top-level await genuinely never settles and the gate must terminate
     * the registry child on its own bound (an unreferenced pending promise
     * would merely drain the loop and exit 13 without reaching it). */
    appendToFile(
      packageDir,
      ['dist', 'providers', 'index.js'],
      'setInterval(() => {}, 3600000);\nawait new Promise(() => {});\n',
      'registry-hang',
    );
  });

  expectNotRunChecks(report, 'registry-hang', ['provider-registry-sync', ...RUNTIME_NOT_RUN]);
  expectCheckEvidence(
    report,
    'registry-hang',
    'provider-registry-sync',
    (item) => item.kind === 'provider-registry-child' && boundedText(item.detail).includes('timed out'),
    'provider-registry-child timeout detail',
  );
}

/** A registry that hard-exits must be an infrastructure not-run, never a pass. */
async function controlRegistryExit(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'registry-exit', (packageDir) => {
    appendToFile(packageDir, ['dist', 'providers', 'index.js'], 'process.exit(7);\n', 'registry-exit');
  });

  expectNotRunChecks(report, 'registry-exit', ['provider-registry-sync', ...RUNTIME_NOT_RUN]);
  expectCheckEvidence(
    report,
    'registry-exit',
    'provider-registry-sync',
    (item) => item.kind === 'provider-registry-child' && boundedText(item.detail).includes('terminated abnormally'),
    'provider-registry-child abnormal-termination detail',
  );
}

/** A CJS edge leaving dist/cjs must reach cjs-edge-escapes-cjs. */
async function controlCjsEdgeEscapes(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'cjs-edge-escapes', (packageDir) => {
    const filePath = path.join(packageDir, 'dist', 'cjs', 'index.cjs');
    const original = readFileSync(filePath, 'utf8');

    writeFileSync(
      filePath,
      replaceExactly(original, 'require("./core.cjs")', 'require("../index.js")', 1, 'cjs-edge-escapes dist/cjs/index.cjs'),
      { encoding: 'utf8' },
    );
  });

  expectFailedChecks(report, 'cjs-edge-escapes', ['cjs-graph-edges']);
  expectFindingKinds(report, 'cjs-edge-escapes', ['cjs-edge-escapes-cjs']);
}

/** A declaration import-type of a missing member must reach declaration-edges. */
async function controlImportTypeMissing(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'import-type-missing', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.d.cts'],
      'export type MissingProbe = import("./missing-probe.cjs").Gone;\n',
      'import-type-missing',
    );
  });

  expectFailedChecks(report, 'import-type-missing', ['declaration-edges']);
  expectFindingKinds(report, 'import-type-missing', ['declaration-edge-unresolved']);
}

/** A spaced require of a bare specifier must be detected (never skipped). */
async function controlSpacedRequire(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'spaced-require', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      'function neverCalledSpaceProbe() {\n  return require ( \'unregistered-thing\' );\n}\nvoid neverCalledSpaceProbe;\n',
      'spaced-require',
    );
  });

  expectFailedChecks(report, 'spaced-require', ['cjs-graph-edges']);
  expectFindingKinds(report, 'spaced-require', ['cjs-edge-bare']);
}

/** A spaced dynamic import() of a .js specifier must be detected. */
async function controlSpacedDynamicImport(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'spaced-dynamic-import', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      'function neverCalledSpaceImportProbe() {\n  return Promise.resolve().then(() => import ( \'./missing-probe.js\' ));\n}\nvoid neverCalledSpaceImportProbe;\n',
      'spaced-dynamic-import',
    );
  });

  expectFailedChecks(report, 'spaced-dynamic-import', ['cjs-graph-edges']);
  expectFindingKinds(report, 'spaced-dynamic-import', ['cjs-edge-js-specifier']);
}

/** A nonliteral (unprovable) dynamic import edge must be rejected explicitly. */
async function controlUnprovableDynamicEdge(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'unprovable-dynamic-edge', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      'function neverCalledUnprovableProbe() {\n  const dynamicName = \'./missing-probe.cjs\';\n  return Promise.resolve().then(() => import(dynamicName));\n}\nvoid neverCalledUnprovableProbe;\n',
      'unprovable-dynamic-edge',
    );
  });

  expectFailedChecks(report, 'unprovable-dynamic-edge', ['cjs-graph-edges']);
  expectFindingKinds(report, 'unprovable-dynamic-edge', ['cjs-edge-unprovable']);
}

/** Commented/string require payloads must NOT be misclassified as edges. */
async function controlCommentedRequireNoFalsePositive(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'commented-require-no-false-positive', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      '// require("./missing-probe.cjs");\n// await import("./missing-probe.js")\nconst payloadHint = "require(\'./missing-probe.cjs\')";\nconst templateHint = `import(\'./missing-probe.cjs\')`;\n',
      'commented-require-no-false-positive',
    );
  });

  expectFullPass(report, 'commented-require-no-false-positive');
}

/** A broken facade export line must reach facade-module-shape. */
async function controlBrokenFacadeExport(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'broken-facade-export', (packageDir) => {
    const filePath = path.join(packageDir, 'dist', 'node', 'adapters', 'express.js');

    writeFileSync(filePath, 'import implementation from "../../cjs/adapters/express.cjs";\n', { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'broken-facade-export', ['facade-module-shape']);
}

/** A leaked private file (src/leaked.js) must reach tarball-forbidden-path. */
async function controlPrivateFileLeak(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'private-file-leak', (packageDir) => {
    mkdirSync(path.join(packageDir, 'src'), { recursive: true });
    writeFileSync(path.join(packageDir, 'src', 'leaked.js'), 'export const leaked = true;\n', { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'private-file-leak', ['tarball-member-shape']);
  expectFindingKinds(report, 'private-file-leak', ['tarball-forbidden-path']);
}

/** A nonempty optionalDependencies declaration must reach manifest-fields. */
async function controlOptionalDependencyRejected(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'optional-dependency-rejected', (packageDir) => {
    mutateManifest(packageDir, 'optional-dependency-rejected', (manifest) => {
      manifest.optionalDependencies = { 'hooklatch-optional-probe-nonexistent': '^1.0.0' };
    });
  });

  expectFailedChecks(report, 'optional-dependency-rejected', ['manifest-fields']);
  expectCheckEvidence(
    report,
    'optional-dependency-rejected',
    'manifest-fields',
    (item) => item.kind === 'manifest-field' && item.field === 'optionalDependencies',
    'optionalDependencies field finding',
  );
}

/** A nonempty bundledDependencies declaration must reach manifest-fields. */
async function controlBundledDependencyRejected(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'bundled-dependency-rejected', (packageDir) => {
    mutateManifest(packageDir, 'bundled-dependency-rejected', (manifest) => {
      manifest.bundledDependencies = ['hooklatch-bundled-probe-nonexistent'];
    });
  });

  expectFailedChecks(report, 'bundled-dependency-rejected', ['manifest-fields']);
  expectCheckEvidence(
    report,
    'bundled-dependency-rejected',
    'manifest-fields',
    (item) => item.kind === 'manifest-field' && item.field === 'bundledDependencies',
    'bundledDependencies field finding',
  );
}

/**
 * Craft a seed copy with ONE non-plain member and run the gate; asserts the
 * member is rejected at tarball-member-shape, extraction and install are
 * explicitly not-run, and the outside sentinel keeps its exact bytes.
 */
async function controlMemberTypeAborted(gatePath, seedPath, label, extra) {
  const root = await newScratchRoot(label);

  /* Outside sentinel: lives OUTSIDE every ledger scratch root; the gate must
   * never touch it (extraction is aborted before any write). */
  const sentinelDir = path.join(tmpdir(), `hooklatch-phase11-${label}-sentinel`);
  const sentinelFile = path.join(sentinelDir, 'sentinel.txt');
  const sentinelBytes = `${label} outside sentinel\n`;

  rmSyncGuarded(sentinelDir);
  mkdirSync(sentinelDir, { recursive: true });
  writeFileSync(sentinelFile, sentinelBytes, { encoding: 'utf8' });

  try {
    const crafted = craftSeedTarball(seedPath, root, label, { extras: [extra] });
    const child = runGateChild(gatePath, ['--tarball', crafted], GATE_TIMEOUT_MS);
    const report = parseGateReport(child, label);

    expectFailedChecks(report, label, ['tarball-member-shape']);
    expectFindingKinds(report, label, [extra.expectKind]);
    /* A rejected archive is never extracted or handed to npm: every
     * extraction/install/downstream check must be explicitly not-run while
     * tarball-target-presence (listing-only) still runs. */
    expectNotRunChecks(report, label, EXTRACTION_BLOCKED_NOT_RUN);
    expectEqual(readFileSync(sentinelFile, 'utf8'), sentinelBytes, `${label} outside sentinel bytes`);
    expectEqual(existsSync(sentinelFile), true, `${label} outside sentinel exists`);
  } finally {
    rmSyncGuarded(sentinelDir);
  }
}

async function controlSymlinkMemberAborted(gatePath, seedPath) {
  await controlMemberTypeAborted(gatePath, seedPath, 'tarball-symlink-member-abort', {
    name: 'package/dist/leaked-link.js',
    type: 'sym',
    link: '../../../outside-sentinel-target.txt',
    expectKind: 'tarball-member-link',
  });
}

async function controlHardlinkMemberAborted(gatePath, seedPath) {
  await controlMemberTypeAborted(gatePath, seedPath, 'tarball-hardlink-member-abort', {
    name: 'package/dist/leaked-hard.js',
    type: 'hard',
    link: '../../../outside-sentinel-target.txt',
    expectKind: 'tarball-member-link',
  });
}

async function controlDeviceMemberAborted(gatePath, seedPath) {
  await controlMemberTypeAborted(gatePath, seedPath, 'tarball-device-member-abort', {
    name: 'package/dist/leaked-device.js',
    type: 'chr',
    expectKind: 'tarball-member-type',
  });
}

/** A duplicated member name must abort extraction and install. */
async function controlDuplicateMemberAborted(gatePath, seedPath) {
  const root = await newScratchRoot('tarball-duplicate-member-abort');

  const crafted = craftSeedTarball(seedPath, root, 'tarball-duplicate-member-abort', {
    duplicates: [{
      name: 'package/package.json',
      data: Buffer.from(JSON.stringify({ name: 'hooklatch', version: '0.0.0-duplicate', duplicated: true })).toString('base64'),
    }],
  });

  const child = runGateChild(gatePath, ['--tarball', crafted], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'tarball-duplicate-member-abort');

  expectFailedChecks(report, 'tarball-duplicate-member-abort', ['tarball-member-shape']);
  expectFindingKinds(report, 'tarball-duplicate-member-abort', ['tarball-member-duplicate']);
  expectNotRunChecks(report, 'tarball-duplicate-member-abort', EXTRACTION_BLOCKED_NOT_RUN);
}

/** Remove a directory tree defensively (used for outside sentinels only). */
function rmSyncGuarded(dir) {
  try {
    const resolved = path.resolve(dir);
    const tempBase = path.resolve(tmpdir());

    if (path.dirname(resolved) !== tempBase || !resolved.startsWith(`${tempBase}${path.sep}`)) return;

    const currentStat = lstatSync(resolved);

    if (!currentStat.isDirectory() || currentStat.isSymbolicLink()) return;

    rmSync(resolved, { recursive: true, force: true });
  } catch {
    /* leave pre-existing or absent paths alone; the control asserts sentinel state */
  }
}

/** A truncated tarball must fail at tarball-read, never pass. */
async function controlCorruptTarball(gatePath, seedPath) {
  const root = await newScratchRoot('corrupt-tarball');
  const truncated = path.join(root, 'truncated.tgz');

  writeFileSync(truncated, readFileSync(seedPath).subarray(0, MUTATED_BYTES_LIMIT));

  const child = runGateChild(gatePath, ['--tarball', truncated], FAST_GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'corrupt-tarball');

  expectFailedChecks(report, 'corrupt-tarball', ['tarball-read']);
}

/** The gate copied outside any checkout must BLOCK before any temp work. */
async function controlFakeRootBlocked(gatePath, seedPath) {
  const root = await newScratchRoot('fake-root-blocked');
  const fakeScripts = path.join(root, 'scripts', 'phase11');

  await mkdir(fakeScripts, { recursive: true });

  const copiedGate = path.join(fakeScripts, 'package-contract.mjs');

  copyFileSync(gatePath, copiedGate);

  const child = runGateChild(copiedGate, ['--tarball', seedPath], FAST_GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'fake-root-blocked');

  if (child.status !== 3) {
    throw new Error(`fake-root-blocked: expected exit 3, got ${JSON.stringify(child.status)}`);
  }

  expectEqual(report.status, 'blocked', 'fake-root blocked status');
  expectEqual(report.checks, [], 'fake-root blocked runs no checks');

  if (!report.reason.includes('missing host checkout dist/index.js')) {
    throw new Error(`fake-root-blocked: reason does not name the missing dist prerequisite: ${JSON.stringify(report.reason)}`);
  }
}

/**
 * Default mode in an isolated CONTROLLED nonready checkout must BLOCK with
 * exit 3 and must provably allocate no gate temp root in its OWN isolated
 * base (no-temp proof; no global OS-temp scan).
 */
async function controlDefaultNonreadyBlocked(gatePath) {
  const root = await newScratchRoot('default-nonready-blocked');
  const ready = await buildNonreadyCheckout(root, gatePath);
  const copiedGate = path.join(ready, 'scripts', 'phase11', 'package-contract.mjs');
  const tempBase = path.join(root, 'gate-tmp');

  await mkdir(tempBase, { recursive: true });

  const beforeCount = countGateTempRoots(tempBase);
  const child = runGateChild(copiedGate, [], FAST_GATE_TIMEOUT_MS, tempBase);
  const afterCount = countGateTempRoots(tempBase);
  const report = parseGateReport(child, 'default-nonready-blocked');

  if (child.status !== 3) {
    throw new Error(`default-nonready-blocked: expected exit 3, got ${JSON.stringify(child.status)}`);
  }

  expectEqual(report.status, 'blocked', 'default nonready blocked status');
  expectEqual(report.checks, [], 'default nonready blocked runs no checks');

  for (const fragment of ['conditional exports', 'missing dist/cjs/index.cjs']) {
    if (!report.reason.includes(fragment)) {
      throw new Error(`default-nonready-blocked: reason lacks '${fragment}': ${JSON.stringify(report.reason)}`);
    }
  }

  expectEqual(afterCount, beforeCount, 'no gate temp root allocated for a blocked default run');
}

/**
 * Default mode in an isolated READY checkout must pack and qualify PASS:
 * all 23 checks pass, the symmetric integrity snapshot stays empty, and the
 * hardened pack command is recorded in report.environment.
 */
async function controlReadyDefaultPass(gatePath, seedPath) {
  const root = await newScratchRoot('ready-default-pass');
  const ready = await buildReadyCheckout(root, gatePath, seedPath, {});
  const copiedGate = path.join(ready, 'scripts', 'phase11', 'package-contract.mjs');
  const child = runGateChild(copiedGate, [], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'ready-default-pass');

  expectFullPass(report, 'ready-default-pass');
  expectEqual(report.mode, 'default', 'ready default mode marker');

  const packCommand = report.environment.packCommand ?? '';

  for (const requiredFlag of ['--ignore-scripts', '--offline', '--cache']) {
    if (!packCommand.includes(requiredFlag)) {
      throw new Error(`ready-default-pass: packCommand lacks '${requiredFlag}': ${JSON.stringify(packCommand)}`);
    }
  }
}

/**
 * A ready checkout whose manifest declares a prepack sentinel hook must
 * qualify PASS with the hook NEVER executed (PREPACK_RAN must not exist).
 */
async function controlReadyDefaultPackHookless(gatePath, seedPath) {
  const root = await newScratchRoot('ready-default-pack-hookless');
  const ready = await buildReadyCheckout(root, gatePath, seedPath, { prepackSentinel: true });
  const copiedGate = path.join(ready, 'scripts', 'phase11', 'package-contract.mjs');
  const child = runGateChild(copiedGate, [], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'ready-default-pack-hookless');

  expectFullPass(report, 'ready-default-pack-hookless');

  if (existsSync(path.join(ready, 'PREPACK_RAN'))) {
    throw new Error('ready-default-pack-hookless: prepack sentinel hook EXECUTED during default-mode pack');
  }

  if (existsSync(path.join(ready, 'node_modules', 'PREPACK_RAN'))) {
    throw new Error('ready-default-pack-hookless: prepack sentinel hook executed inside the junctioned dependency area');
  }
}

/**
 * An additive-file EDIT performed mid-run (after pack and extraction, before
 * the after-snapshot) must surface as an integrity-change failure with a
 * `modified` entry and NO `added` entries.
 */
async function controlIntegrityAdditiveEdit(gatePath, seedPath) {
  const root = await newScratchRoot('integrity-additive-edit-midrun');
  const ready = await buildReadyCheckout(root, gatePath, seedPath, { integrityProbe: true });
  const copiedGate = path.join(ready, 'scripts', 'phase11', 'package-contract.mjs');
  const additiveFile = path.join(ready, 'dist', 'cjs', 'index.cjs');

  spawnWatcher(root, 'append', additiveFile);

  const child = runGateChild(copiedGate, [], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'integrity-additive-edit-midrun');

  expectEqual(report.status, 'fail', 'integrity edit status');
  expectEqual(report.exit, 1, 'integrity edit exit');
  expectFindingKinds(report, 'integrity-additive-edit-midrun', ['integrity-change']);
  expectEqual(
    report.integrity.changed.some((change) => change.path === 'dist/cjs/index.cjs' && change.change === 'modified'),
    true,
    'integrity edit change entry',
  );
  expectEqual(
    report.integrity.changed.some((change) => change.change === 'added'),
    false,
    'integrity edit must not report unchanged additive files as added',
  );
}

/**
 * An additive-file DELETION performed mid-run must surface as an
 * integrity-change failure with a `removed` entry and NO `added` entries.
 */
async function controlIntegrityAdditiveDelete(gatePath, seedPath) {
  const root = await newScratchRoot('integrity-additive-delete-midrun');
  const ready = await buildReadyCheckout(root, gatePath, seedPath, { integrityProbe: true });
  const copiedGate = path.join(ready, 'scripts', 'phase11', 'package-contract.mjs');
  const additiveFile = path.join(ready, 'dist', 'node', 'adapters', 'express.js');

  spawnWatcher(root, 'delete', additiveFile);

  const child = runGateChild(copiedGate, [], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'integrity-additive-delete-midrun');

  expectEqual(report.status, 'fail', 'integrity delete status');
  expectEqual(report.exit, 1, 'integrity delete exit');
  expectFindingKinds(report, 'integrity-additive-delete-midrun', ['integrity-change']);
  expectEqual(
    report.integrity.changed.some((change) => change.path === 'dist/node/adapters/express.js' && change.change === 'removed'),
    true,
    'integrity delete change entry',
  );
  expectEqual(
    report.integrity.changed.some((change) => change.change === 'added'),
    false,
    'integrity delete must not report unchanged additive files as added',
  );
}

/** A candidate whose probe child exits 9 after good JSON must not pass. */
async function controlProbeExitNine(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'probe-exit-nine', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      'process.on(\'beforeExit\', () => { process.exitCode = 9; });\n',
      'probe-exit-nine',
    );
  });

  expectNotRunChecks(report, 'probe-exit-nine', [...RUNTIME_NOT_RUN]);
  expectCheckEvidence(
    report,
    'probe-exit-nine',
    'runtime-resolutions',
    (item) => boundedText(item.detail).includes('terminated abnormally'),
    'probe exit-nine infrastructure detail',
  );
}

/** A candidate whose probe child crashes must be infrastructure not-run. */
async function controlProbeCrash(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'probe-crash', (packageDir) => {
    appendToFile(packageDir, ['dist', 'cjs', 'index.cjs'], 'process.abort();\n', 'probe-crash');
  });

  expectNotRunChecks(report, 'probe-crash', [...RUNTIME_NOT_RUN]);
}

/** Probe output beyond the capture limit must be refused as infrastructure. */
async function controlProbeOutputOverflow(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'probe-output-overflow', (packageDir) => {
    appendToFile(
      packageDir,
      ['dist', 'cjs', 'index.cjs'],
      "console.log('A'.repeat(17 * 1024 * 1024));\n",
      'probe-output-overflow',
    );
  });

  expectNotRunChecks(report, 'probe-output-overflow', [...RUNTIME_NOT_RUN]);
  expectCheckEvidence(
    report,
    'probe-output-overflow',
    'runtime-resolutions',
    (item) => boundedText(item.detail).includes('output overflow'),
    'probe overflow infrastructure detail',
  );
}

/** A hanging probe child must be killed on the bound and refused. */
async function controlProbeHang(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'probe-hang', (packageDir) => {
    appendToFile(packageDir, ['dist', 'cjs', 'index.cjs'], 'setInterval(() => {}, 3600000);\n', 'probe-hang');
  });

  expectNotRunChecks(report, 'probe-hang', [...RUNTIME_NOT_RUN]);
  expectCheckEvidence(
    report,
    'probe-hang',
    'runtime-resolutions',
    (item) => boundedText(item.detail).includes('timed out'),
    'probe hang infrastructure detail',
  );
}

/** An unknown flag must exit 2 with a single stderr line. */
async function controlUsageUnknownFlag(gatePath) {
  const child = runGateChild(gatePath, ['--bogus'], FAST_GATE_TIMEOUT_MS);

  expectUsageStderr(child, 'usage-unknown-flag');
}

/** `--tarball` without a value must exit 2 with a single stderr line. */
async function controlUsageMissingValue(gatePath) {
  const child = runGateChild(gatePath, ['--tarball'], FAST_GATE_TIMEOUT_MS);

  expectUsageStderr(child, 'usage-missing-value');
}

/**
 * An already existing --results destination must be refused with exit 2 and
 * its sentinel content must be preserved exactly.
 */
async function controlUsageResultsExists(gatePath, seedPath) {
  const root = await newScratchRoot('usage-results-exists');
  const resultsPath = path.join(root, 'results.json');
  const sentinelBytes = '{"results-sentinel": true}\n';

  writeFileSync(resultsPath, sentinelBytes, { encoding: 'utf8' });

  const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', resultsPath], FAST_GATE_TIMEOUT_MS);

  expectUsageStderr(child, 'usage-results-exists', 'already exists');
  expectEqual(readFileSync(resultsPath, 'utf8'), sentinelBytes, 'usage-results-exists sentinel preserved');
}

/** A junction-ancestor results destination must be refused (link cannot redirect). */
async function controlResultsAncestorLinkRefused(gatePath, seedPath) {
  const root = await newScratchRoot('results-ancestor-link-refused');
  const sentinelDir = path.join(tmpdir(), 'hooklatch-phase11-results-sentinel');
  const sentinelFile = path.join(sentinelDir, 'sentinel.txt');
  const sentinelBytes = 'results outside sentinel\n';

  rmSyncGuarded(sentinelDir);
  mkdirSync(sentinelDir, { recursive: true });
  writeFileSync(sentinelFile, sentinelBytes, { encoding: 'utf8' });

  try {
    const resultsDir = path.join(root, 'results');

    await mkdir(resultsDir, { recursive: true });
    symlinkSync(sentinelDir, path.join(resultsDir, 'junction'), 'junction');

    const attempted = path.join(resultsDir, 'junction', 'deep', 'out.json');
    const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', attempted], FAST_GATE_TIMEOUT_MS);

    expectUsageStderr(child, 'results-ancestor-link-refused', 'symbolic link');
    expectEqual(readFileSync(sentinelFile, 'utf8'), sentinelBytes, 'results-ancestor-link-refused sentinel preserved');
    expectEqual(existsSync(path.join(sentinelDir, 'deep')), false, 'results-ancestor-link-refused must not create anything outside');
  } finally {
    rmSyncGuarded(sentinelDir);
  }
}

/**
 * The dangling FINAL-component file-symlink vector, where the host permits
 * file symlink creation. On hosts where creation is unprivileged-blocked
 * (EPERM), the control passes with an honest environment-blocked note
 * because the junction-ancestor control already covers the link rule.
 */
async function controlResultsDanglingFileLink(gatePath, seedPath) {
  const root = await newScratchRoot('results-dangling-file-link');
  const resultsDir = path.join(root, 'results');
  const danglingPath = path.join(resultsDir, 'dangling-out.json');

  await mkdir(resultsDir, { recursive: true });

  let created = true;

  try {
    symlinkSync(path.join(tmpdir(), 'hooklatch-nonexistent-dangling-target'), danglingPath, 'file');
  } catch {
    created = false;
  }

  if (!created) return { environmentBlocked: 'file symlink creation is EPERM-blocked on this host; junction-ancestor control covers the rule' };

  const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', danglingPath], FAST_GATE_TIMEOUT_MS);

  expectUsageStderr(child, 'results-dangling-file-link', 'symbolic link');

  return { note: 'dangling file symlink refused as an existing destination' };
}

/** A claim-pattern results destination (notes/...-session.json) must be refused. */
async function controlResultsClaimPathRefused(gatePath, seedPath) {
  const repoRoot = path.resolve(gatePath, '..', '..', '..');
  const attempted = path.join(repoRoot, 'notes', 'phase-11', 'repair-claim-guard-probe-session.json');
  const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', attempted], FAST_GATE_TIMEOUT_MS);

  expectUsageStderr(child, 'results-claim-path-refused', 'session-claim');
}

/**
 * A destination created concurrently mid-run must make the final exclusive
 * `wx` write fail safely: RED status, an EEXIST write error recorded, and
 * the concurrent bytes preserved (never truncated).
 */
async function controlResultsConcurrentCreation(gatePath, seedPath) {
  const root = await newScratchRoot('results-concurrent-creation');
  const resultsPath = path.join(root, 'results.json');
  const sentinelBytes = '{"concurrent-creation-sentinel": true}\n';

  spawnWatcher(root, 'write', resultsPath, sentinelBytes);

  const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', resultsPath], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'results-concurrent-creation');

  if (child.status !== 1) {
    throw new Error(`results-concurrent-creation: expected exit 1, got ${JSON.stringify(child.status)}`);
  }

  expectEqual(report.status, 'fail', 'results concurrent creation status');
  expectFindingKinds(report, 'results-concurrent-creation', ['results-write-failure']);

  const writeError = boundedText(report.resultsWriteError ?? '');

  if (!writeError.includes('EEXIST') && !writeError.includes('already exists')) {
    throw new Error(`results-concurrent-creation: expected an EEXIST write error, got ${JSON.stringify(report.resultsWriteError)}`);
  }

  expectEqual(readFileSync(resultsPath, 'utf8'), sentinelBytes, 'results-concurrent-creation bytes preserved');
}

/* -------------------------------------------------------------------------- */
/* controls invocation                                                        */
/* -------------------------------------------------------------------------- */

function usageText() {
  return 'package-contract-controls: usage: node scripts/phase11/package-contract-controls.mjs --seed FILE [--only name1,name2] (--only is diagnostics-only: a partial selection can never report suite status pass)';
}

function parseArgs(argv) {
  const parsed = { seed: null, only: null, error: null };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];

    if (flag === '--seed') {
      if (index + 1 >= argv.length) {
        parsed.error = '--seed requires a FILE argument';
        break;
      }

      index += 1;
      parsed.seed = argv[index];
      continue;
    }

    if (flag === '--only') {
      if (index + 1 >= argv.length) {
        parsed.error = '--only requires a comma-separated control-name list';
        break;
      }

      index += 1;
      parsed.only = argv[index].split(',').map((name) => name.trim()).filter((name) => name !== '');
      continue;
    }

    parsed.error = `unknown argument '${flag}'`;
    break;
  }

  return parsed;
}

/* -------------------------------------------------------------------------- */
/* driver                                                                     */
/* -------------------------------------------------------------------------- */

const CONTROLS = [
  ['pristine-seed-pass', (gatePath, seedPath) => controlPristineSeedPass(gatePath, seedPath)],
  ['gate-self-test', (gatePath) => controlGateSelfTest(gatePath)],
  ['missing-dcts-deleted', (gatePath, seedPath) => controlMissingDcts(gatePath, seedPath)],
  ['swapped-condition-order', (gatePath, seedPath) => controlSwappedConditionOrder(gatePath, seedPath)],
  ['top-types-shadow', (gatePath, seedPath) => controlTopTypesShadow(gatePath, seedPath)],
  ['wrong-main', (gatePath, seedPath) => controlWrongMain(gatePath, seedPath)],
  ['wrong-bin', (gatePath, seedPath) => controlWrongBin(gatePath, seedPath)],
  ['peer-meta-not-optional', (gatePath, seedPath) => controlPeerMetaNotOptional(gatePath, seedPath)],
  ['additional-public-subpath', (gatePath, seedPath) => controlAdditionalSubpath(gatePath, seedPath)],
  ['omitted-fal', (gatePath, seedPath) => controlOmittedFal(gatePath, seedPath)],
  ['duplicated-polar', (gatePath, seedPath) => controlDuplicatedPolar(gatePath, seedPath)],
  ['registry-throw', (gatePath, seedPath) => controlRegistryThrow(gatePath, seedPath)],
  ['registry-hang', (gatePath, seedPath) => controlRegistryHang(gatePath, seedPath)],
  ['registry-exit-seven', (gatePath, seedPath) => controlRegistryExit(gatePath, seedPath)],
  ['cjs-edge-escapes-cjs', (gatePath, seedPath) => controlCjsEdgeEscapes(gatePath, seedPath)],
  ['declaration-import-type-missing', (gatePath, seedPath) => controlImportTypeMissing(gatePath, seedPath)],
  ['scanner-spaced-require', (gatePath, seedPath) => controlSpacedRequire(gatePath, seedPath)],
  ['scanner-spaced-dynamic-import', (gatePath, seedPath) => controlSpacedDynamicImport(gatePath, seedPath)],
  ['scanner-dynamic-edge-unprovable', (gatePath, seedPath) => controlUnprovableDynamicEdge(gatePath, seedPath)],
  ['scanner-commented-require-no-false-positive', (gatePath, seedPath) => controlCommentedRequireNoFalsePositive(gatePath, seedPath)],
  ['broken-facade-export', (gatePath, seedPath) => controlBrokenFacadeExport(gatePath, seedPath)],
  ['private-file-leak', (gatePath, seedPath) => controlPrivateFileLeak(gatePath, seedPath)],
  ['optional-dependency-rejected', (gatePath, seedPath) => controlOptionalDependencyRejected(gatePath, seedPath)],
  ['bundled-dependency-rejected', (gatePath, seedPath) => controlBundledDependencyRejected(gatePath, seedPath)],
  ['tarball-symlink-member-abort', (gatePath, seedPath) => controlSymlinkMemberAborted(gatePath, seedPath)],
  ['tarball-hardlink-member-abort', (gatePath, seedPath) => controlHardlinkMemberAborted(gatePath, seedPath)],
  ['tarball-device-member-abort', (gatePath, seedPath) => controlDeviceMemberAborted(gatePath, seedPath)],
  ['tarball-duplicate-member-abort', (gatePath, seedPath) => controlDuplicateMemberAborted(gatePath, seedPath)],
  ['corrupt-tarball', (gatePath, seedPath) => controlCorruptTarball(gatePath, seedPath)],
  ['probe-exit-nine-after-good-json', (gatePath, seedPath) => controlProbeExitNine(gatePath, seedPath)],
  ['probe-crash', (gatePath, seedPath) => controlProbeCrash(gatePath, seedPath)],
  ['probe-output-overflow', (gatePath, seedPath) => controlProbeOutputOverflow(gatePath, seedPath)],
  ['probe-hang', (gatePath, seedPath) => controlProbeHang(gatePath, seedPath)],
  ['fake-root-blocked', (gatePath, seedPath) => controlFakeRootBlocked(gatePath, seedPath)],
  ['default-nonready-blocked', (gatePath) => controlDefaultNonreadyBlocked(gatePath)],
  ['ready-default-pass', (gatePath, seedPath) => controlReadyDefaultPass(gatePath, seedPath)],
  ['ready-default-pack-hookless', (gatePath, seedPath) => controlReadyDefaultPackHookless(gatePath, seedPath)],
  ['integrity-additive-edit-midrun', (gatePath, seedPath) => controlIntegrityAdditiveEdit(gatePath, seedPath)],
  ['integrity-additive-delete-midrun', (gatePath, seedPath) => controlIntegrityAdditiveDelete(gatePath, seedPath)],
  ['usage-unknown-flag', (gatePath) => controlUsageUnknownFlag(gatePath)],
  ['usage-missing-value', (gatePath) => controlUsageMissingValue(gatePath)],
  ['usage-results-exists', (gatePath, seedPath) => controlUsageResultsExists(gatePath, seedPath)],
  ['results-ancestor-link-refused', (gatePath, seedPath) => controlResultsAncestorLinkRefused(gatePath, seedPath)],
  ['results-dangling-file-link', (gatePath, seedPath) => controlResultsDanglingFileLink(gatePath, seedPath)],
  ['results-claim-path-refused', (gatePath, seedPath) => controlResultsClaimPathRefused(gatePath, seedPath)],
  ['results-concurrent-creation', (gatePath, seedPath) => controlResultsConcurrentCreation(gatePath, seedPath)],
];

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const usage = (message) => {
    process.stderr.write(`package-contract-controls: ${message}\n${usageText()}\n`);
    process.exitCode = EXIT.USAGE;
  };

  if (args.error !== null) {
    usage(args.error);

    return;
  }

  if (args.seed === null) {
    usage('missing required --seed FILE (the explicit candidate tarball)');

    return;
  }

  if (!existsSync(args.seed) || !statSync(args.seed).isFile()) {
    usage(`--seed path is not an existing file: ${args.seed}`);

    return;
  }

  gatePathGlobal = fileURLToPath(new URL('./package-contract.mjs', import.meta.url));

  if (!existsSync(gatePathGlobal)) {
    usage(`gate script not found next to the controls: ${gatePathGlobal}`);

    return;
  }

  nodeModulesSource = fileURLToPath(new URL('../../node_modules', import.meta.url));

  if (!existsSync(nodeModulesSource)) {
    usage(`repo node_modules for the junction prerequisite not found: ${nodeModulesSource}`);

    return;
  }

  expectEqual(POLICY_PROVIDERS.length, 21, 'frozen policy provider count');

  /* A --only run is DIAGNOSTICS ONLY: a partial selection can never report
   * suite status 'pass' because pass requires every declared control. */
  const selected = args.only === null
    ? CONTROLS
    : CONTROLS.filter(([name]) => args.only.includes(name));

  if (args.only !== null && selected.length === 0) {
    usage(`no control matches --only ${JSON.stringify(args.only)}`);

    return;
  }

  const gatePath = gatePathGlobal;
  const seedPath = args.seed;
  const controlReports = [];

  for (const [name, control] of selected) {
    lastGateReport = null;

    try {
      const note = await control(gatePath, seedPath);

      controlReports.push({ name, verdict: 'pass', error: '', note: note ?? '', gateReport: compactGateReport(lastGateReport) });
    } catch (error) {
      controlReports.push({ name, verdict: 'fail', error: String(error).slice(0, 600), gateReport: compactGateReport(lastGateReport) });
    }
  }

  const passed = controlReports.filter((entry) => entry.verdict === 'pass').length;
  const failedControls = controlReports.filter((entry) => entry.verdict === 'fail');

  /* ------------------------- cleanup phase ------------------------- */

  let cleanupVerified = false;
  const cleanupOutcomes = [];
  let cleanupNote = '';

  if (ledger.uncertain) {
    /* Child/descendant termination is uncertain somewhere: preserve ALL
     * scratch and fail the suite instead of cleaning up and reporting a
     * passing negative control. */
    cleanupVerified = false;
    cleanupNote = 'child termination uncertain; scratch roots preserved on purpose';
  } else {
    for (const entry of ledger.entries) {
      const classification = await removeLedgerRoot(entry.root);

      entry.state = classification;
      cleanupOutcomes.push({ root: entry.root, label: entry.label, classification });
    }

    const good = cleanupOutcomes.every((outcome) => outcome.classification === 'removed' || outcome.classification === 'absent');

    cleanupVerified = good && cleanupOutcomes.length === ledger.entries.length;
  }

  const status = passed === CONTROLS.length && cleanupVerified ? 'pass' : 'fail';

  console.log(JSON.stringify({
    schemaVersion: 1,
    phase: 'phase-11 package-contract controls',
    status,
    exit: status === 'pass' ? EXIT.PASS : EXIT.FAIL,
    summary: {
      controls: controlReports.length,
      passed,
      failed: failedControls.length,
      cleanupVerified,
      ledger: {
        scratchRoots: ledger.entries.length,
        preserved: ledger.uncertain,
        classifications: [...new Set(cleanupOutcomes.map((outcome) => outcome.classification))].sort(),
      },
    },
    cleanupNote,
    controls: controlReports,
  }, null, 2));

  process.exitCode = status === 'pass' ? EXIT.PASS : EXIT.FAIL;
}

await main();
