#!/usr/bin/env node
/**
 * Phase11 package-contract gate - scripted controls (offline).
 *
 * Every control runs the DELIVERED gate (`package-contract.mjs`) as a bounded
 * child process against either the explicit candidate tarball or a mutated
 * extracted copy of it, and asserts that each defect reaches EXACTLY its
 * intended check id (never a blanket failure or a silent skip).
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
 *  - additional public subpath in the manifest -> public-entries-sync with
 *    public-entries-manifest-only (no silent subpath additions);
 *  - omitted `fal` and duplicated `polar` in BOTH provider registry graphs
 *    -> provider-registry-sync (registry stays in both-direction sync);
 *  - registry module that throws on import -> provider-registry-sync with
 *    an honest provider-registry-import finding;
 *  - a CJS graph edge leaving dist/cjs (require("../index.js")) ->
 *    cjs-graph-edges with cjs-edge-escapes-cjs (no CJS->ESM fallback);
 *  - a broken facade export line -> facade-module-shape;
 *  - a leaked private file (src/leaked.js) -> tarball-member-shape with a
 *    tarball-forbidden-path finding;
 *  - corrupt/truncated tarball -> tarball-read fails (exit 1, never pass);
 *  - gate copied outside a checkout -> BLOCKED exit 3 before any temp work;
 *  - default mode (no --tarball) in this checkout -> BLOCKED exit 3 because
 *    the conditional exports and dist/cjs graph do not exist yet;
 *  - usage errors: unknown flag and missing --tarball value -> exit 2 with
 *    a single stderr line; existing --results file -> exit 2.
 *
 * Scratch safety: mutated tarballs are built inside one ledgered `mkdtemp`
 * root under the OS temp directory, tar and gate children are bounded with
 * timeouts, and the root is removed and verified at the end. A cleanup
 * failure fails the run.
 *
 * Usage: node scripts/phase11/package-contract-controls.mjs --seed FILE
 *
 * Exit codes:
 *   0  PASS  - every control reached its intended verdict
 *   1  FAIL  - one or more controls failed, or cleanup was not verified
 *   2  USAGE - invalid controls invocation
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { POLICY_PROVIDERS, isPlainRecord } from './package-contract.mjs';

const EXIT = { PASS: 0, FAIL: 1, USAGE: 2 };
const TAR_TIMEOUT_MS = 60_000;
const GATE_TIMEOUT_MS = 480_000;
const FAST_GATE_TIMEOUT_MS = 120_000;
const MUTATED_BYTES_LIMIT = 4096;

const ledger = { roots: [], removed: false };

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

/** Assert the report's global findingKinds include every listed kind. */
function expectFindingKinds(report, label, expectedKinds) {
  for (const kind of expectedKinds) {
    if (!report.summary.findingKinds.includes(kind)) {
      throw new Error(`${label}: expected finding kind '${kind}' among ${JSON.stringify(report.summary.findingKinds)}`);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* bounded children                                                           */
/* -------------------------------------------------------------------------- */

function runTar(args) {
  const child = spawnSync('tar', args, {
    encoding: 'utf8', timeout: TAR_TIMEOUT_MS, windowsHide: true, maxBuffer: 16 * 1024 * 1024,
  });

  if (child.status !== 0) {
    throw new Error(`tar ${args.join(' ')} failed (${child.status}): ${(child.stderr ?? '').trim().slice(0, 300)}`);
  }
}

/** Run the delivered gate as a bounded child; returns {status, stdout, stderr}. */
function runGateChild(gatePath, args, timeout) {
  const child = spawnSync(process.execPath, [gatePath, ...args], {
    encoding: 'utf8',
    timeout,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  });

  if (child.error !== undefined && child.error.code === 'ETIMEDOUT') {
    throw new Error(`gate child timed out after ${timeout}ms: ${JSON.stringify(args)}`);
  }

  if (child.status === null) {
    throw new Error(`gate child terminated abnormally (signal ${JSON.stringify(child.signal)}): ${JSON.stringify(args)}`);
  }

  return child;
}

/** Parse the gate's machine-JSON report from a child's stdout. */
function parseGateReport(child, label) {
  let report = null;

  if (child.stdout !== '') {
    try {
      report = JSON.parse(child.stdout);
    } catch {
      report = null;
    }
  }

  if (report === null || !isPlainRecord(report)) {
    throw new Error(`${label}: gate child produced no parsable JSON report (status ${child.status}); stderr: ${(child.stderr ?? '').trim().slice(0, 300)}`);
  }

  return report;
}

/* -------------------------------------------------------------------------- */
/* mutation pipeline (extracted copies of the explicit seed, repacked)        */
/* -------------------------------------------------------------------------- */

/** Extract the seed into a ledgered temp root; returns the package dir. */
async function extractSeed(seedPath, label) {
  const root = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-control-'));
  ledger.roots.push(root);

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

/** Extract, mutate, repack, run the gate child, parse its report. */
async function runMutatedGate(gatePath, seedPath, label, mutateFn) {
  const { root, packageDir } = await extractSeed(seedPath, label);
  const mutatedTarball = repack(mutateFn(packageDir) ?? packageDir, label);
  const child = runGateChild(gatePath, ['--tarball', mutatedTarball], GATE_TIMEOUT_MS);

  return { root, child, report: parseGateReport(child, label) };
}

/* -------------------------------------------------------------------------- */
/* control implementations                                                    */
/* -------------------------------------------------------------------------- */

/** The explicit seed must qualify with every check passing. */
async function controlPristineSeedPass(gatePath, seedPath) {
  const child = runGateChild(gatePath, ['--tarball', seedPath], GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'pristine-seed-pass');

  expectEqual(report.status, 'pass', 'pristine seed status');
  expectEqual(report.exit, 0, 'pristine seed exit');
  expectEqual(report.summary.failedCheckIds, [], 'pristine seed failed checks');
  expectEqual(report.summary.notRunCheckIds, [], 'pristine seed not-run checks');
  expectEqual(report.findings, [], 'pristine seed findings');
  expectEqual(report.cleanup.verified, true, 'pristine seed cleanup');
  expectEqual(report.integrity.changed, [], 'pristine seed checkout integrity');
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
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const dot = manifest.exports['.'];

    manifest.exports['.'] = { types: dot.types, node: dot.node, import: dot.import, default: dot.default };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
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
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const dot = manifest.exports['.'];

    manifest.exports['.'] = { node: dot.node, import: dot.import, default: dot.default, types: dot.types };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'top-types-shadow', ['exports-entry-shape']);
}

/** A wrong `main` must reach manifest-fields. */
async function controlWrongMain(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'wrong-main', (packageDir) => {
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    manifest.main = './dist/index.js';
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'wrong-main', ['manifest-fields']);
}

/** A wrong `bin` target must reach manifest-fields. */
async function controlWrongBin(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'wrong-bin', (packageDir) => {
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    manifest.bin = { hooklatch: './dist/cli/wrong.js' };
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'wrong-bin', ['manifest-fields']);
}

/** Peer meta that stops being optional must reach manifest-fields. */
async function controlPeerMetaNotOptional(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'peer-meta-not-optional', (packageDir) => {
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    manifest.peerDependenciesMeta.express.optional = false;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
  });

  expectFailedChecks(report, 'peer-meta-not-optional', ['manifest-fields']);
}

/** An additional public subpath must reach public-entries-manifest-only. */
async function controlAdditionalSubpath(gatePath, seedPath) {
  const { report } = await runMutatedGate(gatePath, seedPath, 'additional-subpath', (packageDir) => {
    const manifestPath = path.join(packageDir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    manifest.exports['./secret'] = manifest.exports['./diagnostics'];
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: 'utf8' });
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

/** A truncated tarball must fail at tarball-read, never pass. */
async function controlCorruptTarball(gatePath, seedPath) {
  const root = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-control-'));
  ledger.roots.push(root);

  const truncated = path.join(root, 'truncated.tgz');

  writeFileSync(truncated, readFileSync(seedPath).subarray(0, MUTATED_BYTES_LIMIT));

  const child = runGateChild(gatePath, ['--tarball', truncated], FAST_GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'corrupt-tarball');

  expectFailedChecks(report, 'corrupt-tarball', ['tarball-read']);
}

/** The gate copied outside any checkout must BLOCK before any temp work. */
async function controlFakeRootBlocked(gatePath, seedPath) {
  const root = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-control-'));
  ledger.roots.push(root);

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

/** Default mode in this checkout must BLOCK (integration pending, no dist/cjs). */
async function controlDefaultModeBlocked(gatePath) {
  const child = runGateChild(gatePath, [], FAST_GATE_TIMEOUT_MS);
  const report = parseGateReport(child, 'default-mode-blocked');

  if (child.status !== 3) {
    throw new Error(`default-mode-blocked: expected exit 3, got ${JSON.stringify(child.status)}`);
  }

  expectEqual(report.status, 'blocked', 'default mode blocked status');
  expectEqual(report.checks, [], 'default mode blocked runs no checks');

  for (const fragment of ['conditional exports', 'missing dist/cjs/index.cjs']) {
    if (!report.reason.includes(fragment)) {
      throw new Error(`default-mode-blocked: reason lacks '${fragment}': ${JSON.stringify(report.reason)}`);
    }
  }
}

/** An unknown flag must exit 2 with a single stderr line. */
async function controlUsageUnknownFlag(gatePath) {
  const child = runGateChild(gatePath, ['--bogus'], FAST_GATE_TIMEOUT_MS);
  const stderrLines = (child.stderr ?? '').trimEnd().split('\n');

  if (child.status !== 2) {
    throw new Error(`usage-unknown-flag: expected exit 2, got ${JSON.stringify(child.status)}`);
  }

  if (stderrLines.length !== 1 || stderrLines[0] === '') {
    throw new Error(`usage-unknown-flag: expected exactly one stderr line, got ${JSON.stringify(stderrLines)}`);
  }
}

/** `--tarball` without a value must exit 2 with a single stderr line. */
async function controlUsageMissingValue(gatePath) {
  const child = runGateChild(gatePath, ['--tarball'], FAST_GATE_TIMEOUT_MS);
  const stderrLines = (child.stderr ?? '').trimEnd().split('\n');

  if (child.status !== 2) {
    throw new Error(`usage-missing-value: expected exit 2, got ${JSON.stringify(child.status)}`);
  }

  if (stderrLines.length !== 1 || stderrLines[0] === '') {
    throw new Error(`usage-missing-value: expected exactly one stderr line, got ${JSON.stringify(stderrLines)}`);
  }
}

/** An already existing --results file must be refused with exit 2. */
async function controlUsageResultsExists(gatePath, seedPath) {
  const root = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-control-'));
  ledger.roots.push(root);

  const resultsPath = path.join(root, 'results.json');

  writeFileSync(resultsPath, '{}\n', { encoding: 'utf8' });

  const child = runGateChild(gatePath, ['--tarball', seedPath, '--results', resultsPath], FAST_GATE_TIMEOUT_MS);
  const stderrLines = (child.stderr ?? '').trimEnd().split('\n');

  if (child.status !== 2) {
    throw new Error(`usage-results-exists: expected exit 2, got ${JSON.stringify(child.status)}`);
  }

  if (stderrLines.length !== 1 || stderrLines[0] === '') {
    throw new Error(`usage-results-exists: expected exactly one stderr line, got ${JSON.stringify(stderrLines)}`);
  }
}

/* -------------------------------------------------------------------------- */
/* controls invocation                                                        */
/* -------------------------------------------------------------------------- */

function usageText() {
  return 'package-contract-controls: usage: node scripts/phase11/package-contract-controls.mjs --seed FILE';
}

function parseArgs(argv) {
  const parsed = { seed: null, error: null };

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

    parsed.error = `unknown argument '${flag}'`;
    break;
  }

  return parsed;
}

/* -------------------------------------------------------------------------- */
/* driver                                                                     */
/* -------------------------------------------------------------------------- */

const CONTROL_NAMES = [
  'pristine-seed-pass',
  'gate-self-test',
  'missing-dcts-deleted',
  'swapped-condition-order',
  'top-types-shadow',
  'wrong-main',
  'wrong-bin',
  'peer-meta-not-optional',
  'additional-public-subpath',
  'omitted-fal',
  'duplicated-polar',
  'registry-throw',
  'cjs-edge-escapes-cjs',
  'broken-facade-export',
  'private-file-leak',
  'corrupt-tarball',
  'fake-root-blocked',
  'default-mode-blocked',
  'usage-unknown-flag',
  'usage-missing-value',
  'usage-results-exists',
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

  const gatePath = fileURLToPath(new URL('./package-contract.mjs', import.meta.url));

  if (!existsSync(gatePath)) {
    usage(`gate script not found next to the controls: ${gatePath}`);

    return;
  }

  expectEqual(POLICY_PROVIDERS.length, 21, 'frozen policy provider count');

  const controls = [
    () => controlPristineSeedPass(gatePath, args.seed),
    () => controlGateSelfTest(gatePath),
    () => controlMissingDcts(gatePath, args.seed),
    () => controlSwappedConditionOrder(gatePath, args.seed),
    () => controlTopTypesShadow(gatePath, args.seed),
    () => controlWrongMain(gatePath, args.seed),
    () => controlWrongBin(gatePath, args.seed),
    () => controlPeerMetaNotOptional(gatePath, args.seed),
    () => controlAdditionalSubpath(gatePath, args.seed),
    () => controlOmittedFal(gatePath, args.seed),
    () => controlDuplicatedPolar(gatePath, args.seed),
    () => controlRegistryThrow(gatePath, args.seed),
    () => controlCjsEdgeEscapes(gatePath, args.seed),
    () => controlBrokenFacadeExport(gatePath, args.seed),
    () => controlPrivateFileLeak(gatePath, args.seed),
    () => controlCorruptTarball(gatePath, args.seed),
    () => controlFakeRootBlocked(gatePath, args.seed),
    () => controlDefaultModeBlocked(gatePath),
    () => controlUsageUnknownFlag(gatePath),
    () => controlUsageMissingValue(gatePath),
    () => controlUsageResultsExists(gatePath, args.seed),
  ];

  const controlReports = [];

  for (let index = 0; index < controls.length; index += 1) {
    const name = CONTROL_NAMES[index];

    try {
      await controls[index]();
      controlReports.push({ name, verdict: 'pass', error: '' });
    } catch (error) {
      controlReports.push({ name, verdict: 'fail', error: String(error).slice(0, 600) });
    }
  }

  const passed = controlReports.filter((entry) => entry.verdict === 'pass').length;
  const failedControls = controlReports.filter((entry) => entry.verdict === 'fail');

  let cleanupVerified = false;

  if (ledger.roots.length > 0) {
    try {
      await Promise.all(ledger.roots.map((root) => rm(root, { recursive: true, force: false })));
    } catch {
      cleanupVerified = false;
    }

    const leftover = [];

    for (const root of ledger.roots) {
      if (existsSync(root)) leftover.push(root);
    }

    if (leftover.length === 0) {
      cleanupVerified = true;
      ledger.removed = true;
    }
  } else {
    cleanupVerified = true;
  }

  const status = passed === controls.length && cleanupVerified ? 'pass' : 'fail';

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
      ledger: { tempRoots: ledger.roots.length },
    },
    controls: controlReports,
  }, null, 2));

  process.exitCode = status === 'pass' ? EXIT.PASS : EXIT.FAIL;
}

await main();
