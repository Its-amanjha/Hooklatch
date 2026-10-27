#!/usr/bin/env node
/**
 * Phase 11 production Node distribution builder.
 *
 * `node scripts/phase11/build-node-distribution.mjs` adds the Node CommonJS
 * graph (dist/cjs) and identity-preserving Node ESM facades (dist/node) on top
 * of the existing neutral/Workers ESM build (dist). It never edits package.json,
 * tsconfig files or src/; the coordinator installs the frozen export policy and
 * appends this command to `npm run build`.
 *
 * Exit codes: 0 built/validated, 1 build or validation failure, 2 usage,
 * 3 blocked prerequisite (missing original ESM output or toolchain).
 */
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  BuildFailure, MAX_OUTPUT_BYTES, PrerequisiteError, assertCompileDependencies, assertInsideTemp,
  assertOriginalEsmOutput, collectSourceModules, compareModuleInventory, createStagingRoot,
  disposeStagingRoot, emitCommonJsModules, findAbsolutePathLeaks, loadTypeScript, relativeFiles,
  rewriteModuleSpecifiers, sameStrings, toPosix, typescriptBinPath, validateCommonJsGraph,
} from './node-emit.mjs';
import {
  POLICY_RELATIVE_PATH, compareRuntimeExports, facadeCommonJsSpecifier, inspectFacadeFiles,
  loadExportPolicy, validateExportPolicy, writeFacadeFiles,
} from './node-facades.mjs';

const USAGE = [
  'Usage: node scripts/phase11/build-node-distribution.mjs [--results FILE]',
  '',
  'Generates the canonical Node CommonJS graph (dist/cjs/*.cjs with .d.cts',
  'declarations) and the six identity-preserving Node ESM facades (dist/node)',
  'from the real src/ TypeScript sources, after the existing `npm run build`.',
  '',
  'Options:',
  '  --help            Show this help and exit 0.',
  '  --self-test       Run harness controls only (no compile, no dist writes).',
  '  --results FILE    Write a JSON evidence report to FILE (must not exist).',
  '',
  'Exit: 0 success, 1 failure, 2 usage, 3 blocked prerequisite.',
].join('\n');

const PROBE_TIMEOUT_MS = 120000;

class UsageError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'UsageError';
  }
}

export function defaultRepoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/* ------------------------------------------------------------------ *
 * Bounded child probe
 * ------------------------------------------------------------------ */

export function runChildProcess(args, cwd, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((done) => {
    const evidence = { exitCode: null, signal: null, stdout: '', stderr: '', timedOut: false, outputLimitExceeded: false, spawnError: null };

    let bytes = 0;
    let settled = false;
    let closeDeadline;
    let child;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(closeDeadline);
      evidence.ok = evidence.exitCode === 0 && evidence.signal === null && !evidence.timedOut
        && !evidence.outputLimitExceeded && evidence.spawnError === null;
      done(evidence);
    };

    const stop = () => {
      clearTimeout(timer);
      child.kill('SIGKILL');
      closeDeadline = setTimeout(() => {
        evidence.spawnError ??= 'child-close-not-confirmed';
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        finish();
      }, 10000);
    };

    const timer = setTimeout(() => {
      evidence.timedOut = true;
      stop();
    }, timeoutMs);

    const capture = (field, chunk) => {
      bytes += chunk.length;

      if (bytes > MAX_OUTPUT_BYTES) {
        if (!evidence.outputLimitExceeded) {
          evidence.outputLimitExceeded = true;
          stop();
        }

        return;
      }

      evidence[field] += chunk.toString('utf8');
    };

    child = spawn(process.execPath, args, { cwd, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));
    child.on('error', (error) => {
      evidence.spawnError = error.message;
      finish();
    });
    child.on('close', (code, signal) => {
      evidence.exitCode = code;
      evidence.signal = signal;
      finish();
    });
  });
}

/* ------------------------------------------------------------------ *
 * Tree snapshots
 * ------------------------------------------------------------------ */

export function snapshotEsmTree(distRoot) {
  const files = relativeFiles(distRoot).filter((file) => !file.startsWith('cjs/') && !file.startsWith('node/'));
  const hash = createHash('sha256');

  for (const relative of files) {
    hash.update(relative);
    hash.update('\0');
    hash.update(readFileSync(path.join(distRoot, path.normalize(relative))));
    hash.update('\0');
  }

  return { files: files.length, digest: hash.digest('hex') };
}

export function snapshotTree(root) {
  const files = relativeFiles(root);
  const hash = createHash('sha256');

  for (const relative of files) {
    hash.update(relative);
    hash.update('\0');
    hash.update(readFileSync(path.join(root, path.normalize(relative))));
    hash.update('\0');
  }

  return { files: files.length, digest: hash.digest('hex') };
}

function outputInventory(root, label) {
  return relativeFiles(root).map((relative) => {
    const bytes = readFileSync(path.join(root, path.normalize(relative)));

    return { path: `${label}/${relative}`, bytes: bytes.length, sha256: sha256Bytes(bytes) };
  });
}

/* ------------------------------------------------------------------ *
 * Runtime inventory and identity (real generated artifacts)
 * ------------------------------------------------------------------ */

function writeProbeFile(stagingRoot, name, source) {
  const file = path.join(stagingRoot.root, name);

  assertInsideTemp(file);
  writeFileSync(file, source);

  return file;
}

const INVENTORY_PROBE = [
  "'use strict';",
  "const { readFileSync } = require('node:fs');",
  'const entries = JSON.parse(readFileSync(process.argv[2], "utf8"));',
  'const inventory = {};',
  'for (const [subpath, file] of Object.entries(entries)) {',
  '  const mod = require(file);',
  '  inventory[subpath] = Object.keys(mod).sort().map((name) => [name, typeof mod[name]]);',
  '}',
  'process.stdout.write(JSON.stringify(inventory));',
  '',
].join('\n');

const IDENTITY_PROBE = [
  "import { createRequire } from 'node:module';",
  "import { readFileSync } from 'node:fs';",
  "import { pathToFileURL } from 'node:url';",
  '',
  'const require = createRequire(import.meta.url);',
  'const entries = JSON.parse(readFileSync(process.argv[2], "utf8"));',
  '',
  'async function main() {',
  '  const results = [];',
  '',
  '  for (const entry of entries) {',
  '    const commonjs = require(entry.commonjs);',
  '    const esm = await import(pathToFileURL(entry.facade).href);',
  '    const missing = entry.names.filter((name) => !(name in esm) || !(name in commonjs));',
  '    const shared = entry.names.filter((name) => esm[name] === commonjs[name]);',
  '    results.push({ subpath: entry.subpath, missing, shared: shared.length, expected: entry.names.length });',
  '  }',
  '',
  '  process.stdout.write(JSON.stringify(results));',
  '}',
  '',
  'main().catch((error) => {',
  '  process.stderr.write(String(error && error.stack ? error.stack : error));',
  '  process.exitCode = 1;',
  '});',
  '',
].join('\n');

async function inspectRuntimeExports(stagingRoot, entries) {
  const destinations = {};

  for (const entry of entries) destinations[entry.subpath] = path.join(stagingRoot.root, 'cjs', `${entry.base}.cjs`);

  const argumentFile = writeProbeFile(stagingRoot, 'inventory-input.json', JSON.stringify(destinations));
  const probe = writeProbeFile(stagingRoot, 'inventory-probe.cjs', INVENTORY_PROBE);
  const run = await runChildProcess([probe, argumentFile], stagingRoot.root);

  if (!run.ok) throw new BuildFailure(`Runtime export inventory probe failed: ${run.stderr || run.stdout || `exit ${String(run.exitCode)}`}`);

  let inventory;

  try {
    inventory = JSON.parse(run.stdout);
  } catch (error) {
    throw new BuildFailure(`Runtime export inventory is not JSON: ${messageOf(error)}`);
  }

  const rows = [];

  for (const entry of entries) {
    const actual = inventory[entry.subpath];

    if (!Array.isArray(actual)) throw new BuildFailure(`Runtime export inventory has no entry for ${entry.subpath}.`);

    const names = actual.map((pair) => pair[0]);
    const comparison = compareRuntimeExports(entry, names);

    if (!comparison.ok) {
      throw new BuildFailure(`Runtime exports for ${entry.subpath} are not the frozen set (missing: ${comparison.missing.join(', ') || 'none'}; extra: ${comparison.extra.join(', ') || 'none'}).`);
    }

    const notCallable = actual.filter((pair) => pair[1] !== 'function').map((pair) => pair[0]);

    if (notCallable.length > 0) throw new BuildFailure(`Runtime exports for ${entry.subpath} are not functions/classes: ${notCallable.join(', ')}`);

    rows.push({ subpath: entry.subpath, runtimeExports: names });
  }

  return rows;
}

async function verifyRuntimeIdentity(stagingRoot, cjsRoot, nodeRoot, entries) {
  const payload = entries.map((entry) => ({
    subpath: entry.subpath,
    names: entry.runtimeExports,
    commonjs: path.join(cjsRoot, `${entry.base}.cjs`),
    facade: path.join(nodeRoot, `${entry.base}.js`),
  }));

  const argumentFile = writeProbeFile(stagingRoot, 'identity-input.json', JSON.stringify(payload));
  const probe = writeProbeFile(stagingRoot, 'identity-probe.mjs', IDENTITY_PROBE);
  const run = await runChildProcess([probe, argumentFile], stagingRoot.root);

  if (!run.ok) throw new BuildFailure(`Node import/require identity probe failed: ${run.stderr || run.stdout || `exit ${String(run.exitCode)}`}`);

  let results;

  try {
    results = JSON.parse(run.stdout);
  } catch (error) {
    throw new BuildFailure(`Node import/require identity evidence is not JSON: ${messageOf(error)}`);
  }

  if (!Array.isArray(results) || results.length !== entries.length) throw new BuildFailure('Node import/require identity evidence has the wrong entry count.');

  const rows = [];

  for (const result of results) {
    const identical = result.shared === result.expected && result.missing.length === 0;

    rows.push({ subpath: result.subpath, identical, shared: result.shared, expected: result.expected, missing: result.missing });

    if (!identical) throw new BuildFailure(`${result.subpath} does not preserve value identity between import and require (${result.shared}/${result.expected} shared).`);
  }

  return { ok: true, entries: rows };
}

/* ------------------------------------------------------------------ *
 * Installation
 * ------------------------------------------------------------------ */

/** Only dist/cjs and dist/node are ever removed or replaced. */
function installOutputs(repoRoot, stagingRoot) {
  const distRoot = path.join(repoRoot, 'dist');
  const stagedCjs = path.join(stagingRoot.root, 'cjs');
  const stagedNode = path.join(stagingRoot.root, 'node');
  const targetCjs = path.join(distRoot, 'cjs');
  const targetNode = path.join(distRoot, 'node');

  assertInsideTemp(stagedCjs);
  assertInsideTemp(stagedNode);

  for (const target of [targetCjs, targetNode]) {
    if (path.dirname(target) !== distRoot) throw new BuildFailure(`Refusing to replace ${target}.`);

    rmSync(target, { recursive: true, force: true });
  }

  cpSync(stagedCjs, targetCjs, { recursive: true });
  cpSync(stagedNode, targetNode, { recursive: true });

  return { cjs: targetCjs, node: targetNode };
}

/* ------------------------------------------------------------------ *
 * Build
 * ------------------------------------------------------------------ */

function describeGraph(graph) {
  return JSON.stringify({
    unresolved: graph.unresolved.slice(0, 5),
    stale: graph.stale.slice(0, 5),
    escapes: graph.escapes.slice(0, 5),
    esmSyntax: graph.esmSyntax.slice(0, 5),
    externalRuntimeSpecifiers: graph.externalRuntimeSpecifiers.slice(0, 5),
    unexpectedFiles: graph.unexpectedFiles.slice(0, 5),
  });
}

/**
 * Build, validate and install the Node distribution for one checkout.
 * Returns an evidence report; throws PrerequisiteError (blocked) or
 * BuildFailure (failed) without installing partial output.
 */
export async function buildNodeDistribution(options) {
  const repoRoot = path.resolve(options.repoRoot ?? defaultRepoRoot());
  const startedAt = Date.now();

  if (!existsSync(path.join(repoRoot, 'package.json'))) throw new PrerequisiteError(`Not a checkout: ${repoRoot}`);

  const { policyPath, entries } = loadExportPolicy(repoRoot);
  const entryBases = entries.map((entry) => entry.base);

  assertCompileDependencies(repoRoot);
  const typescriptBin = typescriptBinPath(repoRoot);
  const typescript = loadTypeScript(repoRoot);
  const sourceModules = collectSourceModules(path.join(repoRoot, 'src'));
  const requiredEsm = assertOriginalEsmOutput(repoRoot, entryBases);

  const distRoot = path.join(repoRoot, 'dist');
  const esmBefore = snapshotEsmTree(distRoot);
  const stagingRoot = createStagingRoot();
  let report;
  let failure = null;

  try {
    const emit = await emitCommonJsModules({ repoRoot, stagingRoot, typescriptBin });
    const inventory = compareModuleInventory(emit.modules, emit.outDir);

    if (!inventory.ok) {
      throw new BuildFailure(`Emitted module inventory does not mirror src/: ${JSON.stringify({
        missingRuntime: inventory.missingRuntime.slice(0, 5),
        extraRuntime: inventory.extraRuntime.slice(0, 5),
        missingDeclarations: inventory.missingDeclarations.slice(0, 5),
        extraDeclarations: inventory.extraDeclarations.slice(0, 5),
        unexpected: inventory.unexpected.slice(0, 5),
      })}`);
    }

    const stagedGraph = validateCommonJsGraph(typescript, emit.outDir);

    if (!stagedGraph.ok) throw new BuildFailure(`Generated CommonJS graph is invalid before installation: ${describeGraph(stagedGraph)}`);

    const stagedNode = path.join(stagingRoot.root, 'node');
    const stagedFacadeFiles = writeFacadeFiles(stagedNode, entries);
    const stagedFacades = inspectFacadeFiles(stagedNode, entries);

    if (!stagedFacades.ok) throw new BuildFailure(`Generated facade set is incomplete: ${JSON.stringify(stagedFacades)}`);

    const runtimeInventory = await inspectRuntimeExports(stagingRoot, entries);
    const forbidden = [toPosix(stagingRoot.root), stagingRoot.root, path.resolve(os.tmpdir()), toPosix(repoRoot), repoRoot];
    const leaks = [...findAbsolutePathLeaks(emit.outDir, forbidden), ...findAbsolutePathLeaks(stagedNode, forbidden)];

    if (leaks.length > 0) throw new BuildFailure(`Generated files embed an absolute build path: ${JSON.stringify(leaks.slice(0, 5))}`);

    // Identity is proved on the staged artifacts; installation then copies the
    // exact probed bytes, and the copy is verified below before PASS.
    const identity = await verifyRuntimeIdentity(stagingRoot, emit.outDir, stagedNode, entries);
    const stagedDigest = { cjs: snapshotTree(emit.outDir), node: snapshotTree(stagedNode) };

    const installed = installOutputs(repoRoot, stagingRoot);
    const installedDigest = { cjs: snapshotTree(installed.cjs), node: snapshotTree(installed.node) };

    if (stagedDigest.cjs.digest !== installedDigest.cjs.digest || stagedDigest.node.digest !== installedDigest.node.digest) {
      throw new BuildFailure('Installed Node outputs differ from the validated staged bytes.');
    }

    const installedGraph = validateCommonJsGraph(typescript, installed.cjs);
    const installedFacades = inspectFacadeFiles(installed.node, entries);

    if (!installedGraph.ok) throw new BuildFailure(`Installed CommonJS graph is invalid: ${describeGraph(installedGraph)}`);

    if (!installedFacades.ok) throw new BuildFailure(`Installed facade set is incomplete: ${JSON.stringify(installedFacades)}`);

    const esmAfter = snapshotEsmTree(distRoot);
    const esmUnchanged = esmAfter.digest === esmBefore.digest && esmAfter.files === esmBefore.files;

    if (!esmUnchanged) throw new BuildFailure('Original neutral/Workers ESM output changed during the Node build.');

    report = {
      status: 'PASS',
      phase: '11',
      owner: 'deepseek-codebuff',
      builder: 'scripts/phase11/build-node-distribution.mjs',
      repoRoot: toPosix(repoRoot),
      policy: { path: POLICY_RELATIVE_PATH, sha256: sha256Bytes(readFileSync(policyPath)) },
      compiler: {
        typescript: String(typescript.version ?? 'unknown'),
        module: 'Node16',
        moduleResolution: 'Node16',
        target: 'ES2022',
        verbatimModuleSyntax: false,
        declarationMap: false,
        sourceMap: false,
      },
      source: {
        modules: emit.modules.length,
        srcTypeScriptFiles: sourceModules.length,
        excludedCliModules: sourceModules.length - emit.modules.length,
      },
      counts: {
        cjsModules: inventory.runtime,
        cjsDeclarations: inventory.declarations,
        facadeModules: installedFacades.runtime,
        facadeDeclarations: installedFacades.declarations,
      },
      inventory,
      graph: {
        ok: installedGraph.ok,
        files: installedGraph.files,
        runtimeFiles: installedGraph.runtimeFiles,
        declarationFiles: installedGraph.declarationFiles,
        runtimeEdges: installedGraph.runtimeEdges,
        declarationEdges: installedGraph.declarationEdges,
        unresolved: installedGraph.unresolved.length,
        stale: installedGraph.stale.length,
        escapes: installedGraph.escapes.length,
        esmSyntax: installedGraph.esmSyntax.length,
        externalRuntimeSpecifiers: installedGraph.externalRuntimeSpecifiers.length,
      },
      facades: { ok: installedFacades.ok, runtime: installedFacades.runtime, declarations: installedFacades.declarations, files: installedFacades.files },
      entries: entries.map((entry, index) => ({
        subpath: entry.subpath,
        base: entry.base,
        runtimeExports: runtimeInventory[index].runtimeExports,
        facade: `dist/node/${entry.base}.js`,
        declaration: `dist/node/${entry.base}.d.ts`,
        commonjs: `dist/cjs/${entry.base}.cjs`,
        declarationTarget: `dist/cjs/${entry.base}.d.cts`,
        identity: identity.entries[index],
      })),
      integrity: {
        esmUnchanged,
        esmFiles: esmAfter.files,
        esmDigest: esmAfter.digest,
        esmRequired: requiredEsm.length,
        absolutePathLeaks: 0,
        rewrittenSpecifiers: emit.renamed.rewritten,
        stagedDigest,
        installedDigest,
      },
      stagedFacadeFiles,
      outputs: [...outputInventory(installed.cjs, 'dist/cjs'), ...outputInventory(installed.node, 'dist/node')],
      elapsedMs: Date.now() - startedAt,
    };
  } catch (error) {
    failure = error;
  }

  let cleanup;
  let cleanupFailure = null;

  try {
    cleanup = disposeStagingRoot(stagingRoot);
  } catch (error) {
    cleanupFailure = error;
  }

  if (failure !== null) {
    throw cleanupFailure === null ? failure : new BuildFailure(`${messageOf(failure)}; staging cleanup also failed: ${messageOf(cleanupFailure)}`);
  }

  if (cleanupFailure !== null) throw cleanupFailure;

  report.cleanup = { ...cleanup, stagingRemoved: true };

  return report;
}

/* ------------------------------------------------------------------ *
 * Self-test (harness controls only: no compile, no dist writes)
 * ------------------------------------------------------------------ */

export async function runSelfTest(options) {
  const repoRoot = path.resolve(options.repoRoot ?? defaultRepoRoot());
  const stagingRoot = createStagingRoot();
  const controls = [];

  const record = (name, run) => {
    try {
      const detail = run();

      controls.push({ name, passed: detail.passed, detail: detail.detail });
    } catch (error) {
      controls.push({ name, passed: false, detail: messageOf(error) });
    }
  };

  try {
    record('export-policy-shape', () => {
      const entries = validateExportPolicy(loadExportPolicy(repoRoot).policy);
      const subpaths = entries.map((entry) => entry.subpath);

      return { passed: sameStrings(subpaths, ['.', './diagnostics', './express', './nextjs', './cloudflare', './hono']), detail: { entries: subpaths } };
    });

    record('ast-runtime-rewrite-preserves-ordinary-strings', () => {
      const typescript = loadTypeScript(repoRoot);

      const file = writeProbeFile(stagingRoot, 'control.cjs', [
        '"use strict";',
        "const marker = './never-rewrite.js';",
        'const text = "require(\'../never/rewrite.js\')";',
        "const core = require('./core.js');",
        "const stripe = require('../providers/stripe.js');",
        "const crypto = require('node:crypto');",
        'module.exports = { marker, text, core, stripe, crypto };',
        '',
      ].join('\n'));

      const outcome = rewriteModuleSpecifiers(typescript, file, 'runtime');
      const source = readFileSync(file, 'utf8');

      const passed = outcome.rewritten === 2
        && source.includes("const marker = './never-rewrite.js';")
        && source.includes("require('./core.cjs')")
        && source.includes("require('../providers/stripe.cjs')")
        && source.includes("require('node:crypto')")
        && source.includes('require(\'../never/rewrite.js\')');

      return { passed, detail: { rewritten: outcome.rewritten, specifiers: outcome.specifiers } };
    });

    record('ast-declaration-rewrite', () => {
      const typescript = loadTypeScript(repoRoot);

      const file = writeProbeFile(stagingRoot, 'control.d.cts', [
        "import type { A } from './types.js';",
        "export * from '../providers/index.js';",
        "declare module 'express-serve-static-core' { interface Request { marker?: A } }",
        "export declare const value: import('./types.js').A;",
        '',
      ].join('\n'));

      const outcome = rewriteModuleSpecifiers(typescript, file, 'declaration');
      const source = readFileSync(file, 'utf8');

      const passed = outcome.rewritten === 3
        && source.includes("from './types.cjs'")
        && source.includes("from '../providers/index.cjs'")
        && source.includes("declare module 'express-serve-static-core'")
        && source.includes("import('./types.cjs')");

      return { passed, detail: { rewritten: outcome.rewritten, specifiers: outcome.specifiers } };
    });

    record('graph-validation-rejects-poisoned-edge', () => {
      const typescript = loadTypeScript(repoRoot);
      const root = path.join(stagingRoot.root, 'control-graph');

      mkdirSync(root, { recursive: true });
      writeFileSync(path.join(root, 'core.cjs'), '"use strict";\nexports.verify = () => true;\n');
      writeFileSync(path.join(root, 'core.d.cts'), 'export declare function verify(): boolean;\n');
      writeFileSync(path.join(root, 'index.cjs'), '"use strict";\nconst core = require("./core.cjs");\nexports.verify = core.verify;\n');
      writeFileSync(path.join(root, 'index.d.cts'), "export { verify } from './core.cjs';\n");

      const clean = validateCommonJsGraph(typescript, root);

      writeFileSync(path.join(root, 'index.cjs'), '"use strict";\nconst core = require("./core.js");\nexports.verify = core.verify;\n');

      const poisoned = validateCommonJsGraph(typescript, root);

      return {
        passed: clean.ok && !poisoned.ok && poisoned.stale.length === 1 && poisoned.stale[0].specifier === './core.js',
        detail: { cleanOk: clean.ok, poisonedOk: poisoned.ok, stale: poisoned.stale },
      };
    });

    record('missing-original-esm-blocks', () => {
      let blocked = false;

      try {
        assertOriginalEsmOutput(path.join(stagingRoot.root, 'empty-checkout'), ['index']);
      } catch (error) {
        blocked = error instanceof PrerequisiteError;
      }

      return { passed: blocked, detail: { blocked } };
    });

    record('facade-inventory-six-entries', () => {
      const entries = validateExportPolicy(loadExportPolicy(repoRoot).policy);
      const nodeRoot = path.join(stagingRoot.root, 'control-facades');
      const files = writeFacadeFiles(nodeRoot, entries);
      const inspected = inspectFacadeFiles(nodeRoot, entries);
      const nested = entries.find((entry) => entry.base.startsWith('adapters/'));

      return {
        passed: inspected.ok && inspected.runtime === 6 && inspected.declarations === 6
          && facadeCommonJsSpecifier(nested.base) === `../../cjs/${nested.base}.cjs`,
        detail: { files, nested: facadeCommonJsSpecifier(nested.base) },
      };
    });
  } finally {
    disposeStagingRoot(stagingRoot);
  }

  return {
    status: controls.every((control) => control.passed) ? 'CONTROLS-PASS' : 'CONTROLS-FAILED',
    controlsOnly: true,
    note: 'Harness control evidence only; not product PASS.',
    controls,
  };
}

/* ------------------------------------------------------------------ *
 * Evidence output
 * ------------------------------------------------------------------ */

const REPORT_FORBIDDEN_PREFIXES = ['dist/', 'src/', 'scripts/', 'tests/', 'tasks/', 'node_modules/', '.git/'];

export function resolveResultsDestination(repoRoot, requested) {
  const raw = String(requested ?? '').trim();

  if (raw.length === 0) throw new UsageError('--results requires a file path.');

  const resolved = path.resolve(repoRoot, raw);
  const relative = toPosix(path.relative(repoRoot, resolved));

  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) throw new UsageError('--results must stay inside the checkout.');

  for (const prefix of REPORT_FORBIDDEN_PREFIXES) {
    if (relative.startsWith(prefix)) throw new UsageError(`--results must not target ${prefix}`);
  }

  if (/^notes\/phase-11\/[A-Za-z0-9._-]*-session\.json$/.test(relative)) throw new UsageError('--results must not target a session claim.');

  if (existsSync(resolved)) throw new BuildFailure(`Refusing to overwrite existing evidence: ${relative}`);

  mkdirSync(path.dirname(resolved), { recursive: true });

  return { resolved, relative };
}

function writeResults(destination, report) {
  writeFileSync(destination.resolved, `${JSON.stringify({ ...report, resultsPath: destination.relative }, null, 2)}\n`);

  return { path: destination.relative, bytes: readFileSync(destination.resolved).length };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

export function parseArguments(argv) {
  const options = { help: false, selfTest: false, results: null };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else if (argument === '--self-test') {
      options.selfTest = true;
    } else if (argument === '--results') {
      const value = argv[index + 1];

      if (value === undefined || value.startsWith('--')) throw new UsageError('--results requires a file path.');

      options.results = value;
      index += 1;
    } else if (argument.startsWith('--results=')) {
      const value = argument.slice('--results='.length);

      if (value.length === 0) throw new UsageError('--results requires a file path.');

      options.results = value;
    } else {
      throw new UsageError(`unknown argument: ${argument}`);
    }
  }

  return options;
}

export async function main(argv = process.argv.slice(2), options = {}) {
  const repoRoot = path.resolve(options.repoRoot ?? defaultRepoRoot());
  let parsed;

  try {
    parsed = parseArguments(argv);
  } catch (error) {
    console.error(`${messageOf(error)}\n\n${USAGE}`);

    return 2;
  }

  if (parsed.help) {
    console.log(USAGE);

    return 0;
  }

  let destination = null;

  try {
    destination = parsed.results === null ? null : resolveResultsDestination(repoRoot, parsed.results);
  } catch (error) {
    console.error(JSON.stringify({ status: 'FAILED', stage: 'results', reason: messageOf(error) }));

    return error instanceof UsageError ? 2 : 1;
  }

  let report;

  try {
    report = parsed.selfTest ? await runSelfTest({ repoRoot }) : await buildNodeDistribution({ repoRoot });
  } catch (error) {
    if (error instanceof PrerequisiteError) {
      console.error(JSON.stringify({ status: 'BLOCKED', reason: messageOf(error) }));

      return 3;
    }

    console.error(JSON.stringify({ status: 'FAILED', reason: error instanceof Error ? (error.stack ?? error.message) : String(error) }));

    return 1;
  }

  let resultsWrite = null;

  if (destination !== null) {
    try {
      resultsWrite = writeResults(destination, report);
    } catch (error) {
      console.error(JSON.stringify({ status: 'FAILED', stage: 'results-write', reason: messageOf(error) }));

      return 1;
    }
  }

  const printable = {
    status: report.status,
    controlsOnly: report.controlsOnly === true,
    sourceModules: report.source?.modules ?? null,
    counts: report.counts ?? null,
    graph: report.graph ?? null,
    facades: report.facades ?? null,
    identity: report.entries?.map((entry) => ({ subpath: entry.subpath, identical: entry.identity.identical })) ?? null,
    integrity: report.integrity === undefined ? null : {
      esmUnchanged: report.integrity.esmUnchanged,
      esmFiles: report.integrity.esmFiles,
      absolutePathLeaks: report.integrity.absolutePathLeaks,
      rewrittenSpecifiers: report.integrity.rewrittenSpecifiers,
    },
    cleanup: report.cleanup ?? null,
    controls: report.controls ?? null,
    resultsWrite,
  };

  console.log(JSON.stringify(printable, null, 2));

  return report.status === 'PASS' || report.status === 'CONTROLS-PASS' ? 0 : 1;
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = await main();
}
