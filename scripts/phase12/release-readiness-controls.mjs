#!/usr/bin/env node
/**
 * Phase 12 negative controls for scripts/phase12/release-readiness.mjs.
 *
 * Every control builds a throwaway package fixture under OS temp (never the
 * checkout), runs the real checker CLI against it with an observed process exit
 * code, and compares that exit with the report's own `exit` field. No network,
 * npm authentication, packing, installing or repo writes are performed.
 *
 * Deliberate negative results are CONTROL evidence only: they prove the checker
 * discriminates, not that the SDK, a build or a release is qualified.
 *
 * Exit: 0 every control passed, 1 a control failed, 2 usage.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, symlinkSync, unlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (process.argv.length > 2) {
  console.error('release-readiness-controls: this script takes no arguments.');
  process.exit(2);
}

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CHECKER_PATH = path.join(REPO_ROOT, 'scripts', 'phase12', 'release-readiness.mjs');
const TEMP_PREFIX = 'hooklatch-phase12-readiness-';
const CHECKER_URL = pathToFileURL(CHECKER_PATH).href;

const {
  EXIT, EXPECTED_PROVIDERS, PUBLIC_ENTRIES, REGISTRY_RELATIVE, baseManifest, expectedTargets, runBoundedChild,
} = await import(CHECKER_URL);

const FIXTURE_DOCS = Object.freeze({
  'README.md': '# Fixture package\n\nPublication to npm is pending.\n',
  'CHANGELOG.md': '# Changelog\n\n## Unreleased\n\nNo npm release or Git tag is recorded.\n',
});

const scratchRoots = [];

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/* ------------------------------------------------------------------ *
 * OS-temp scratch (strictly bounded, verified cleanup)
 * ------------------------------------------------------------------ */

function assertInsideTemp(target) {
  const relative = path.relative(path.resolve(os.tmpdir()), path.resolve(target));

  assert(relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to operate outside OS temp: ${path.resolve(target)}`);
}

function createScratch(name) {
  const root = mkdtempSync(path.join(os.tmpdir(), `${TEMP_PREFIX}${name}-`));

  assertInsideTemp(root);
  assert(path.basename(root).startsWith(TEMP_PREFIX), `unexpected scratch name: ${root}`);
  scratchRoots.push(root);

  return root;
}

function disposeScratch(root) {
  assertInsideTemp(root);
  assert(path.basename(root).startsWith(TEMP_PREFIX), `refusing to remove a foreign directory: ${root}`);
  rmSync(root, { recursive: true, force: true });
  assert(!existsSync(root), `scratch survived cleanup: ${root}`);
}

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

function writeFixtureFile(root, relative, content) {
  const file = path.join(root, relative);

  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}

function writeTargetFile(root, relative) {
  writeFixtureFile(root, relative, '// phase12 readiness fixture\n');
}

function registryStub(providers) {
  return `export const SUPPORTED_PROVIDERS = ${JSON.stringify(providers)};\n`;
}

/**
 * Write one fixture package. `options.skipBuild` produces a checkout that was
 * never built; `options.providers` replaces the registry contents (a negative
 * control, never a claim about the real registry).
 */
function writeFixture(root, manifest, options = {}) {
  writeFileSync(path.join(root, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  if (options.skipBuild !== true) {
    for (const entry of PUBLIC_ENTRIES) {
      for (const expected of expectedTargets(entry)) writeTargetFile(root, expected.target.slice('./'.length));
    }

    for (const relative of ['dist/cjs/index.cjs', 'dist/index.d.ts', 'dist/cli/index.js']) writeTargetFile(root, relative);

    writeFixtureFile(root, REGISTRY_RELATIVE, registryStub(options.providers ?? [...EXPECTED_PROVIDERS]));
  }

  for (const name of Object.keys(FIXTURE_DOCS)) writeFileSync(path.join(root, name), FIXTURE_DOCS[name]);
}

/* ------------------------------------------------------------------ *
 * Running the real checker CLI
 * ------------------------------------------------------------------ */

function runChecker(args, cwd) {
  const result = spawnSync(process.execPath, [CHECKER_PATH, ...args], {
    cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
  });

  let report = null;

  try {
    report = JSON.parse(result.stdout);
  } catch {
    report = null;
  }

  return {
    exitCode: result.status,
    signal: result.signal,
    spawnError: result.error === undefined ? null : result.error.message,
    stdout: result.stdout,
    stderr: result.stderr.trim(),
    report,
  };
}

/** Observe a real exit code AND require the printed report to agree with it. */
function assertRun(run, expectedExit, expectedStatus) {
  assert.equal(run.spawnError, null, `checker could not be spawned: ${run.spawnError}`);
  assert.equal(run.signal, null, `checker exited on ${run.signal}`);
  assert.equal(run.exitCode, expectedExit, `expected exit ${expectedExit}, got ${run.exitCode}: ${run.stderr}`);
  assert.notEqual(run.report, null, 'checker did not print a JSON report');
  assert.equal(run.report.exit, expectedExit, `report exit ${run.report.exit} disagrees with process exit ${run.exitCode}`);

  if (expectedStatus !== null) {
    assert.equal(run.report.status, expectedStatus, `expected status ${expectedStatus}, got ${run.report.status}`);
  }

  return run.report;
}

function findingsOf(report) {
  const findings = [];

  for (const check of report.localReadiness.checks) {
    for (const finding of check.findings) findings.push(finding);
  }

  return findings;
}

/* ------------------------------------------------------------------ *
 * Checkout integrity snapshot (tracked files + built dist)
 * ------------------------------------------------------------------ */

function snapshotTree(root) {
  if (!existsSync(root)) return { present: false, count: 0, digest: '' };

  const files = [];

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isSymbolicLink()) continue;

      const full = path.join(directory, entry.name);

      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) files.push(full);
    }
  };

  visit(root);

  const hash = createHash('sha256');

  for (const file of files) {
    hash.update(path.relative(root, file).replaceAll('\\', '/'));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
  }

  return { present: true, count: files.length, digest: hash.digest('hex') };
}

function snapshotCheckout() {
  const listed = spawnSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

  assert.equal(listed.error, undefined, 'git ls-files could not run');
  assert.equal(listed.status, 0, 'git ls-files failed');

  const files = listed.stdout.split('\0').filter((entry) => entry.length > 0).sort();
  const hash = createHash('sha256');

  for (const relative of files) {
    hash.update(relative);
    hash.update('\0');
    hash.update(readFileSync(path.join(REPO_ROOT, relative)));
    hash.update('\0');
  }

  const status = spawnSync('git', ['status', '--porcelain'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

  assert.equal(status.status, 0, 'git status failed');

  return {
    tracked: { count: files.length, digest: hash.digest('hex') },
    dist: snapshotTree(path.join(REPO_ROOT, 'dist')),
    worktree: status.stdout,
  };
}

/* ------------------------------------------------------------------ *
 * Controls
 * ------------------------------------------------------------------ */

const controls = [];

function recordControl(name, run) {
  try {
    controls.push({ name, passed: true, detail: run() });
  } catch (error) {
    controls.push({ name, passed: false, detail: messageOf(error) });
  }
}

recordControl('help-exit-0', () => {
  const run = runChecker(['--help'], REPO_ROOT);

  assert.equal(run.exitCode, EXIT.READY, `--help exited ${run.exitCode}`);
  assert.equal(run.signal, null);
  assert.match(run.stdout, /Local readiness is NOT release authorization/);

  return { exitCode: run.exitCode };
});

recordControl('usage-exit-2', () => {
  const run = runChecker(['--nope'], REPO_ROOT);

  assert.equal(run.exitCode, EXIT.USAGE, `unknown flag exited ${run.exitCode}`);
  assert.equal(run.report, null, 'a usage error must not print a readiness report');
  assert.match(run.stderr, /unknown argument/);

  return { exitCode: run.exitCode };
});

recordControl('self-test-exit-0', () => {
  const run = runChecker(['--self-test'], REPO_ROOT);

  assert.equal(run.exitCode, EXIT.READY, `--self-test exited ${run.exitCode}: ${run.stderr}`);
  assert.equal(run.report.status, 'CONTROLS-PASS');
  assert.equal(run.report.controlsOnly, true);

  const failed = run.report.controls.filter((control) => control.passed !== true);

  assert.equal(failed.length, 0, `failing self-test controls: ${JSON.stringify(failed)}`);

  return { controls: run.report.controls.length };
});

recordControl('missing-build-exit-3', () => {
  const root = createScratch('missing-build');

  writeFixture(root, baseManifest(), { skipBuild: true });

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.BLOCKED, 'blocked');
  const registry = report.localReadiness.checks.find((check) => check.id === 'built-registry');

  assert.equal(report.localReadiness.ready, false);
  assert.equal(registry.status, 'blocked', 'a missing build must never be reported as passed');
  assert.equal(report.localReadiness.checks.some((check) => check.id === 'targets-present' && check.status === 'passed'), false);

  return { exit: report.exit, blockedChecks: report.localReadiness.checks.filter((check) => check.status === 'blocked').map((check) => check.id) };
});

recordControl('missing-export-target-exit-1', () => {
  const root = createScratch('missing-target');

  writeFixture(root, baseManifest());
  rmSync(path.join(root, 'dist/cjs/adapters/hono.cjs'));

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
  const missing = findingsOf(report).filter((finding) => finding.kind === 'missing-target');

  assert.equal(missing.length, 1, `expected one missing-target finding, saw ${JSON.stringify(missing)}`);
  assert.equal(missing[0].target, 'dist/cjs/adapters/hono.cjs');
  assert.equal(report.localReadiness.ready, false);

  return { exit: report.exit, missing: missing[0] };
});

recordControl('nonzero-runtime-dependencies-exit-1', () => {
  const root = createScratch('runtime-deps');
  const manifest = baseManifest();

  manifest.dependencies = { 'left-pad': '1.0.0' };
  writeFixture(root, manifest);

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
  const dependency = findingsOf(report).filter((finding) => finding.kind === 'runtime-dependencies');

  assert.equal(dependency.length, 1, `expected one runtime-dependencies finding, saw ${JSON.stringify(dependency)}`);
  assert.equal(dependency[0].field, 'dependencies');

  return { exit: report.exit, dependencies: dependency[0].observed };
});

recordControl('malformed-package-exit-1', () => {
  const root = createScratch('malformed');

  writeFixture(root, baseManifest());
  writeFileSync(path.join(root, 'package.json'), '{ "name": "hooklatch",\n');

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
  const malformed = findingsOf(report).filter((finding) => finding.kind === 'malformed-package');

  assert.equal(malformed.length, 1, `expected one malformed-package finding, saw ${JSON.stringify(malformed)}`);
  assert.equal(report.localReadiness.ready, false);

  return { exit: report.exit, detail: malformed[0].detail };
});

recordControl('false-publication-claim-exit-1', () => {
  const root = createScratch('published-claim');

  writeFixture(root, baseManifest());
  writeFileSync(path.join(root, 'README.md'), '# Fixture package\n\nHooklatch is published to npm. Hooklatch is now available on npm.\n');

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
  const claims = findingsOf(report).filter((finding) => finding.kind === 'publication-claim');

  assert.equal(claims.length, 2, `expected two publication-claim findings, saw ${JSON.stringify(claims)}`);
  assert.deepEqual(claims.map((finding) => finding.pattern).sort(), ['available-on-npm', 'published-to-npm']);

  return { exit: report.exit, claims: claims.map((finding) => finding.pattern) };
});

recordControl('registry-not-21-exit-1', () => {
  const root = createScratch('registry-short');

  writeFixture(root, baseManifest(), { providers: [...EXPECTED_PROVIDERS].slice(0, EXPECTED_PROVIDERS.length - 1) });

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
  const registry = findingsOf(report).filter((finding) => finding.kind === 'registry-mismatch');

  assert.equal(registry.length, 1, `expected one registry-mismatch finding, saw ${JSON.stringify(registry)}`);
  assert.equal(registry[0].expectedCount, 21);
  assert.equal(registry[0].observedCount, 20);

  return { exit: report.exit, registry: registry[0] };
});

recordControl('valid-esm-cjs-layout-accepted', () => {
  const root = createScratch('valid-layout');

  writeFixture(root, baseManifest());

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.READY, 'ready');
  const notPassed = report.localReadiness.checks.filter((check) => check.status !== 'passed');

  assert.equal(report.localReadiness.ready, true);
  assert.equal(report.localReadiness.findings, 0);
  assert.deepEqual(notPassed, [], `checks did not pass: ${JSON.stringify(notPassed)}`);

  return { exit: report.exit, checks: report.localReadiness.checks.map((check) => check.id) };
});

recordControl('external-evidence-stays-manual-required', () => {
  const root = createScratch('external-evidence');

  writeFixture(root, baseManifest());

  const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.READY, 'ready');
  const external = report.external;

  assert.equal(external.length, 5, `expected five external items, saw ${JSON.stringify(external.map((item) => item.id))}`);
  assert.deepEqual(external.map((item) => item.id), [
    'security-private-reporting',
    'npm-ownership-auth-2fa',
    'exact-sha-ci',
    'final-tarball-review',
    'release-tag-publication',
  ]);

  for (const item of external) {
    assert.equal(item.status === 'manual-required' || item.status === 'not-checked', true, `external item ${item.id} reports ${item.status}`);
  }

  assert.equal(external.some((item) => item.id === 'security-private-reporting' && item.status === 'manual-required'), true);
  assert.equal(report.localReadinessIsReleaseAuthorization, false);
  assert.equal(report.releaseAuthorized, false);
  assert.equal(report.notRunHere.commands.includes('npm run verify'), true);
  assert.equal(report.limitations.length > 0, true);

  return {
    exit: report.exit,
    localReady: report.localReadiness.ready,
    external: external.map((item) => `${item.id}:${item.status}`),
    releaseAuthorized: report.releaseAuthorized,
  };
});

recordControl('cwd-independent-execution', () => {
  const root = createScratch('cwd-independent');
  const foreign = createScratch('foreign-cwd');

  writeFixture(root, baseManifest());

  const fromRepo = runChecker(['--root', root], REPO_ROOT);
  const fromForeign = runChecker(['--root', root], foreign);

  assertRun(fromRepo, EXIT.READY, 'ready');
  assertRun(fromForeign, EXIT.READY, 'ready');
  assert.equal(fromForeign.report.rootSource, 'explicit');

  const defaultFromForeign = runChecker([], foreign);

  assert.equal(defaultFromForeign.report?.rootSource, 'script-location', 'default root must come from the script location, not the cwd');
  assert.equal(defaultFromForeign.exitCode, defaultFromForeign.report.exit);
  assert.equal(defaultFromForeign.report.localReadiness.checks.length > 0, true);

  return {
    explicitRoot: { repo: fromRepo.exitCode, foreign: fromForeign.exitCode },
    defaultRootSource: defaultFromForeign.report.rootSource,
    defaultExit: defaultFromForeign.exitCode,
  };
});

for (const variant of ['default-first', 'extra-condition', 'partial-build', 'registry-directory', 'missing-readme', 'readme-directory', 'absent-build-invalid-export']) {
  recordControl(variant, () => {
    const root = createScratch(variant);
    const manifest = baseManifest();

    if (variant === 'default-first') {
      const entry = manifest.exports['.'];

      manifest.exports['.'] = { default: entry.default, node: entry.node, types: entry.types, import: entry.import };
    }

    if (variant === 'extra-condition') {
      manifest.exports['.'] = { browser: './dist/index.js', ...manifest.exports['.'] };
    }

    if (variant === 'absent-build-invalid-export') delete manifest.exports['./hono'];

    writeFixture(root, manifest, { skipBuild: variant === 'absent-build-invalid-export' });

    if (variant === 'partial-build' || variant === 'registry-directory') {
      rmSync(path.join(root, REGISTRY_RELATIVE));

      if (variant === 'registry-directory') mkdirSync(path.join(root, REGISTRY_RELATIVE));
    }

    if (variant === 'missing-readme' || variant === 'readme-directory') {
      rmSync(path.join(root, 'README.md'));

      if (variant === 'readme-directory') mkdirSync(path.join(root, 'README.md'));
    }

    const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');

    const expected = variant.includes('condition') || variant === 'default-first' ? 'export-condition-order'
      : variant.includes('readme') ? 'missing-doc'
      : variant === 'absent-build-invalid-export' ? 'exports-sync' : 'registry-missing-or-linked';

    assert(findingsOf(report).some((finding) => finding.kind === expected), `missing intended ${expected} finding`);

    return { exit: report.exit, expected };
  });
}

recordControl('ancestor-junction-rejected', () => {
  const root = createScratch('junction');
  const target = createScratch('junction-target');

  writeFixture(root, baseManifest(), { skipBuild: true });
  writeFixture(target, baseManifest());

  const link = path.join(root, 'dist');
  const before = snapshotTree(target);

  symlinkSync(path.join(target, 'dist'), link, process.platform === 'win32' ? 'junction' : 'dir');

  try {
    const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');

    assert(findingsOf(report).some((finding) => finding.kind === 'registry-missing-or-linked'));
    assert.deepEqual(snapshotTree(target), before, 'linked target changed');

    return { exit: report.exit, targetUnchanged: true };
  } finally {
    unlinkSync(link);
  }
});

for (const variant of ['nonzero', 'malformed-output']) {
  recordControl(`registry-${variant}`, () => {
    const root = createScratch(variant);

    writeFixture(root, baseManifest());
    writeFixtureFile(root, REGISTRY_RELATIVE, variant === 'nonzero' ? 'process.exit(9);' : 'console.log("not-json"); export const SUPPORTED_PROVIDERS = [];');

    const report = assertRun(runChecker(['--root', root], REPO_ROOT), EXIT.DEFECT, 'defect');
    const finding = findingsOf(report).find((item) => item.kind === 'registry-probe');

    assert(finding, 'expected registry-probe rejection');
    assert.equal(finding.evidence.closeConfirmed, true);

    return { exit: report.exit, probe: finding.evidence };
  });
}

for (const variant of ['timeout', 'overflow']) {
  try {
    const payload = variant === 'timeout' ? 'setInterval(() => {}, 1000);' : 'setInterval(() => process.stdout.write("x".repeat(65536)), 1);';
    const result = await runBoundedChild(['-e', payload], REPO_ROOT, variant === 'timeout' ? 250 : 5000);

    assert.equal(result.ok, false);
    assert.equal(result.closeConfirmed, true);
    assert.equal(variant === 'timeout' ? result.timedOut : result.outputLimitExceeded, true);
    controls.push({ name: `child-${variant}`, passed: true, detail: { closeConfirmed: true } });
  } catch (error) {
    controls.push({ name: `child-${variant}`, passed: false, detail: messageOf(error) });
  }
}

recordControl('checkout-unmodified', () => {
  const foreign = createScratch('no-write');
  const before = snapshotCheckout();
  const run = runChecker([], foreign);
  const after = snapshotCheckout();

  assert.equal(run.spawnError, null);
  assert.equal(run.signal, null);
  assert.equal(run.exitCode, run.report.exit, 'report exit must equal the observed process exit');
  assert.equal(run.report.rootSource, 'script-location');
  assert.equal(run.exitCode, EXIT.READY, 'integrity control requires a real built checkout');
  assert.equal(run.report.localReadiness.checks.find((check) => check.id === 'built-registry')?.status, 'passed');
  assert.equal(after.tracked.count, before.tracked.count, 'tracked file count changed');
  assert.equal(after.tracked.digest, before.tracked.digest, 'tracked file bytes changed');
  assert.deepEqual(after.dist, before.dist, 'built dist/ changed');
  assert.equal(after.worktree, before.worktree, 'git status changed');

  return {
    exit: run.exitCode,
    tracked: { count: after.tracked.count, unchanged: after.tracked.digest === before.tracked.digest },
    dist: { present: after.dist.present, files: after.dist.count, unchanged: after.dist.digest === before.dist.digest },
    scratchAbsolutePaths: false,
  };
});

/* ------------------------------------------------------------------ *
 * Summary
 * ------------------------------------------------------------------ */

let cleaned = true;

try {
  for (const root of scratchRoots) disposeScratch(root);
} catch (error) {
  cleaned = false;
  console.error(`Cleanup failed: ${messageOf(error)}`);
}

const passed = controls.every((control) => control.passed === true) && cleaned;

console.log(JSON.stringify({
  status: passed ? 'CONTROLS-PASS' : 'CONTROLS-FAILED',
  controlsOnly: true,
  note: 'Fixture-driven negative controls only; not SDK, build or release evidence. Local readiness is never release authorization.',
  scratch: { prefix: TEMP_PREFIX, roots: scratchRoots.length, cleaned },
  controls,
}, null, 2));

process.exitCode = passed ? EXIT.READY : EXIT.DEFECT;
