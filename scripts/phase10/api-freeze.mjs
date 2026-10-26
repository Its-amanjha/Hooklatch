#!/usr/bin/env node
/**
 * Phase10 public-API freeze driver.
 *
 * Standalone Node entry point: `node scripts/phase10/api-freeze.mjs`.
 *
 * What it does against the ACTUAL packed tarball (never repository src):
 *   1. packs the built package offline and installs it into disposable
 *      consumer roots (core Web, Express, Hono, plus an intentionally empty
 *      root for infrastructure controls);
 *   2. compiles independent strict consumers from
 *      tests/types/phase10-api-freeze/fixtures.mjs with exact diagnostic
 *      code/line expectations;
 *   3. runs control mutations so a green matrix cannot come from an unresolved
 *      package, a missing export, a skipped compiler, or a classifier that
 *      accepts missing diagnostics;
 *   4. records a reviewable public declaration surface (exported names and
 *      shipped entrypoint declaration text) rather than internal-file hashes;
 *   5. verifies the built registry, runtime export inventory and docs sample
 *      coverage, then snapshots tracked files + dist and removes temp state.
 *
 * Preparation: run `npm run build` first. This harness never builds, installs
 * from a registry, changes tracked checkout files or repairs your environment.
 *
 * Exit codes: 0 every intended outcome, control and cleanup matched; 1 contract
 * or infrastructure failure; 2 usage error. A crash, timeout or status-2
 * infrastructure result is never treated as diagnostic evidence.
 */

import { spawn, spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  CASES, CONTROLS, DOCS_PATH, ENVIRONMENTS, ERROR_CODES, FAILURE_REASONS, PROVIDER_IDS,
} from '../../tests/types/phase10-api-freeze/fixtures.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEMP_PREFIX = 'hooklatch-phase10-api-freeze-';
const EXIT = { PASS: 0, FAIL: 1, USAGE: 2 };
const NPM_TIMEOUT_MS = 180_000;
const NODE_TIMEOUT_MS = 120_000;
const TERMINATE_TIMEOUT_MS = 10_000;
const MESSAGE_LIMIT = 240;
const EXPECTED_ROOT_EXPORTS = ['HooklatchError', 'createVerifier', 'verify', 'verifyRequest'];
const EXPECTED_DIAGNOSTICS_EXPORTS = ['diagnose'];

const USAGE = `Usage: node scripts/phase10/api-freeze.mjs [--json] [--results <path>] [--help]

  (no flags)       run the frozen public-API matrix, controls and surface capture
  --json           print only the machine-readable JSON report
  --results <path> write notes/phase-10/coordinator-api-freeze-results.json only
  --help           print this message
  --self-test      run bounded regression controls without packing or compiling

Preparation: run \`npm run build\` first. Exit 0 = every intended outcome and
cleanup matched; 1 = contract/infrastructure failure; 2 = usage error.`;

class InfrastructureError extends Error {}

const lifecycle = { cleanupSafe: true };

/* -------------------------------------------------------------------------- */
/* small utilities                                                            */
/* -------------------------------------------------------------------------- */

const rel = (from, to) => path.relative(from, to).split(path.sep).join('/');

const bounded = (value) => {
  const text = String(value).replace(/\s+/g, ' ').trim();

  return text.length > MESSAGE_LIMIT ? `${text.slice(0, MESSAGE_LIMIT)}...` : text;
};

const sha256Text = (text) => createHash('sha256').update(text).digest('hex');

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let terminationTimer;
    const limit = 16 * 1024 * 1024;

    const timer = setTimeout(() => {
      timedOut = true;

      if (!child.pid) return;

      if (process.platform === 'win32') {
        const termination = spawnSync(
          'taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
          { windowsHide: true, timeout: 15000, stdio: 'ignore' },
        );

        if (termination.error || termination.status !== 0) {
          lifecycle.cleanupSafe = false;
          child.kill('SIGKILL');
        }
      } else {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          lifecycle.cleanupSafe = false;
          child.kill('SIGKILL');
        }
      }

      terminationTimer = setTimeout(() => {
        lifecycle.cleanupSafe = false;
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        reject(new InfrastructureError(`${options.label ?? command} termination could not be confirmed; temp files retained.`));
      }, 5000);
    }, options.timeout ?? NODE_TIMEOUT_MS);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk.slice(0, Math.max(0, limit - stdout.length)); });
    child.stderr.on('data', (chunk) => { stderr += chunk.slice(0, Math.max(0, limit - stderr.length)); });
    child.on('error', () => {
      clearTimeout(timer);
      reject(new InfrastructureError(`${options.label ?? command} could not start.`));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      clearTimeout(terminationTimer);

      if (timedOut || code !== 0) {
        reject(new InfrastructureError(
          `${options.label ?? command} failed${timedOut ? ' (timeout)' : ` (${code})`}: ${bounded(stderr)}`,
        ));
      } else {
        resolve(stdout);
      }
    });
  });
}

/** npm is not guaranteed to expose npm_execpath when the script runs under plain node. */
function locateNpmCli() {
  const candidates = [];
  const envCli = process.env.npm_execpath;

  if (envCli !== undefined && envCli.length > 0) candidates.push(envCli);

  const nodeDir = path.dirname(process.execPath);

  candidates.push(
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.cjs'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  if (found === undefined) {
    throw new InfrastructureError(
      'npm CLI is unavailable: neither npm_execpath nor the node installation provides npm-cli.js. '
      + 'Run with a normal Node/npm installation; this harness does not install anything.',
    );
  }

  return found;
}

function loadTypeScript() {
  const requireFromRepo = createRequire(pathToFileURL(path.join(REPO_ROOT, 'package.json')).href);

  try {
    return requireFromRepo('typescript');
  } catch {
    throw new InfrastructureError('The pinned typescript package is missing from this checkout node_modules.');
  }
}

function assertInsideTempRoot(dir) {
  const base = path.resolve(tmpdir());
  const resolved = path.resolve(dir);

  if (resolved === base || !resolved.startsWith(`${base}${path.sep}`)) {
    throw new InfrastructureError(`refusing to operate outside the OS temp directory: ${resolved}`);
  }

  if (!path.basename(resolved).startsWith(TEMP_PREFIX)) {
    throw new InfrastructureError(`refusing to operate on a directory without the ${TEMP_PREFIX} prefix: ${resolved}`);
  }

  return resolved;
}

/* -------------------------------------------------------------------------- */
/* checkout snapshot                                                          */
/* -------------------------------------------------------------------------- */

function walkFiles(relativeDir, output) {
  const absolute = path.join(REPO_ROOT, relativeDir);

  if (!existsSync(absolute)) return;

  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;

    const relative = path.join(relativeDir, entry.name);

    if (entry.isDirectory()) walkFiles(relative, output);
    else if (entry.isFile()) output.push(relative.split(path.sep).join('/'));
  }
}

async function gitStatus() {
  return run('git', ['-C', REPO_ROOT, 'status', '--porcelain'], {
    cwd: REPO_ROOT, timeout: 15_000, label: 'git status',
  });
}

async function snapshotCheckout() {
  const tracked = await run('git', ['-C', REPO_ROOT, 'ls-files', '-z'], {
    cwd: REPO_ROOT, timeout: 15_000, label: 'git ls-files',
  });

  const files = tracked.split('\0').filter((file) => file.length > 0);


  walkFiles('dist', files);

  const hashes = new Map();

  for (const file of [...new Set(files)].sort()) {
    const absolute = path.join(REPO_ROOT, file);

    // A tracked deletion is part of the snapshot, rather than a read error.
    hashes.set(file, existsSync(absolute) ? sha256Text(readFileSync(absolute)) : '<missing>');
  }

  let head = null;

  for (let attempt = 0; attempt < 2 && head === null; attempt += 1) {
    try {
      head = (await run('git', ['-C', REPO_ROOT, 'rev-parse', 'HEAD'], {
        cwd: REPO_ROOT, timeout: 15_000, label: 'git rev-parse',
      })).trim();
    } catch {
      head = null;

      if (attempt === 0) {
        await new Promise((resolve) => { setTimeout(resolve, 500); });
      }
    }
  }

  if (head === null) throw new InfrastructureError('Checkout HEAD could not be verified.');

  return { hashes, gitStatus: await gitStatus(), head };
}

function compareSnapshots(before, after) {
  const failures = [];

  if (before.gitStatus !== after.gitStatus) {
    failures.push('checkout git status changed during the run; generated files escaped OS temp');
  }

  if (before.head !== after.head) failures.push('checkout HEAD changed during the run');

  const allKeys = new Set([...before.hashes.keys(), ...after.hashes.keys()]);

  for (const key of [...allKeys].sort()) {
    if (before.hashes.get(key) !== after.hashes.get(key)) failures.push(`checkout file changed during the run: ${key}`);
  }

  return { checkedFiles: allKeys.size, failures };
}

/* -------------------------------------------------------------------------- */
/* package preflight and packing                                              */
/* -------------------------------------------------------------------------- */

function declaredEntrypoints(manifest) {
  const normalize = (value) => (value.startsWith('./') ? value.slice(2) : value);
  const paths = new Set([manifest.main, manifest.types]);

  for (const target of Object.values(manifest.exports ?? {})) {
    paths.add(target.types);
    paths.add(target.import);
  }

  for (const target of Object.values(manifest.bin ?? {})) paths.add(target);

  paths.delete(undefined);

  return [...paths].map(normalize).sort();
}

async function preflight(manifest) {
  const topLevel = (await run('git', ['-C', REPO_ROOT, 'rev-parse', '--show-toplevel'], {
    cwd: REPO_ROOT, timeout: 15_000, label: 'git rev-parse --show-toplevel',
  })).trim();

  if (topLevel.replace(/\\/g, '/').toLowerCase() !== REPO_ROOT.replace(/\\/g, '/').toLowerCase()) {
    throw new InfrastructureError(`driver root ${REPO_ROOT} is not the git checkout root ${topLevel}`);
  }

  const entrypoints = declaredEntrypoints(manifest);
  const missing = entrypoints.filter((entrypoint) => !existsSync(path.join(REPO_ROOT, entrypoint)));

  if (missing.length > 0) {
    throw new InfrastructureError(
      `Built package targets are missing: ${missing.join(', ')}. Run \`npm run build\` in this checkout first; `
      + 'this harness does not build or repair your environment.',
    );
  }

  if (!existsSync(path.join(REPO_ROOT, 'dist', 'providers', 'index.js'))) {
    throw new InfrastructureError('Built provider registry is missing: dist/providers/index.js. Run `npm run build` first.');
  }

  if (!existsSync(path.join(REPO_ROOT, 'node_modules', 'typescript', 'lib', 'typescript.js'))) {
    throw new InfrastructureError('The pinned typescript package is missing from node_modules.');
  }

  if (!existsSync(path.join(REPO_ROOT, DOCS_PATH))) {
    throw new InfrastructureError(`The owned API stability document is missing: ${DOCS_PATH}`);
  }

  return entrypoints;
}

async function packPackage(npmCli, tempRoot, manifest, entrypoints) {
  const packDir = path.join(tempRoot, 'pack');

  mkdirSync(packDir, { recursive: true });

  const stdout = await run(process.execPath, [
    npmCli, 'pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', packDir,
  ], { cwd: REPO_ROOT, timeout: NPM_TIMEOUT_MS, label: 'npm pack' });

  let parsed;

  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new InfrastructureError(`npm pack did not return JSON: ${bounded(stdout)}`);
  }

  const entry = Array.isArray(parsed) ? parsed[0] : undefined;

  if (entry === undefined || entry.filename === undefined || !Array.isArray(entry.files)) {
    throw new InfrastructureError('npm pack returned no single package entry with a file inventory.');
  }

  const tarballName = String(entry.filename);
  const tarballPath = path.join(packDir, tarballName);

  if (!existsSync(tarballPath)) throw new InfrastructureError(`npm pack did not create ${tarballName}.`);

  const files = entry.files.map((file) => ({
    path: String(file.path).split(path.sep).join('/'),
    size: Number(file.size),
  }));

  const allowed = (file) => file === 'package.json' || file === 'README.md' || file === 'LICENSE' || file.startsWith('dist/');
  const disallowed = files.filter((file) => !allowed(file.path)).map((file) => file.path);
  const packedPaths = new Set(files.map((file) => file.path));
  const missingEntrypoints = entrypoints.filter((entrypoint) => !packedPaths.has(entrypoint));
  const unsafe = files.filter((file) => file.path.startsWith('/') || file.path.split('/').includes('..'));

  if (disallowed.length > 0) {
    throw new InfrastructureError(`npm tarball contains files outside dist/package.json/README/LICENSE: ${disallowed.join(', ')}`);
  }

  if (missingEntrypoints.length > 0) {
    throw new InfrastructureError(`npm tarball is missing declared entrypoint(s): ${missingEntrypoints.join(', ')}`);
  }

  if (unsafe.length > 0) {
    throw new InfrastructureError(`npm tarball contains unsafe paths: ${unsafe.map((file) => file.path).join(', ')}`);
  }

  if (Object.keys(manifest.dependencies ?? {}).length !== 0) {
    throw new InfrastructureError('package.json declares runtime dependencies; the core package must stay zero-dependency.');
  }

  return {
    tarballPath,
    filename: tarballName,
    fileCount: files.length,
    unpackedBytes: files.reduce((sum, file) => sum + file.size, 0),
    entrypoints,
    packedPaths,
  };
}

/* -------------------------------------------------------------------------- */
/* isolated consumer environments                                             */
/* -------------------------------------------------------------------------- */

function createLink(target, linkPath, ownedLinks) {
  const resolvedTarget = path.resolve(target);
  const resolvedLink = path.resolve(linkPath);
  const repoNodeModules = path.resolve(REPO_ROOT, 'node_modules');
  const tempRoot = path.resolve(tmpdir());

  if (!resolvedTarget.startsWith(`${repoNodeModules}${path.sep}`)) {
    throw new InfrastructureError(`refusing to link a dependency outside this checkout node_modules: ${resolvedTarget}`);
  }

  if (resolvedTarget === tempRoot || !resolvedLink.startsWith(`${tempRoot}${path.sep}`)) {
    throw new InfrastructureError(`refusing to create a dependency link outside OS temp: ${resolvedLink}`);
  }

  if (!existsSync(resolvedTarget)) throw new InfrastructureError(`linked dependency is missing: ${resolvedTarget}`);

  if (existsSync(resolvedLink)) throw new InfrastructureError(`link target already exists: ${resolvedLink}`);

  const linkType = process.platform === 'win32' ? 'junction' : 'dir';

  const created = { linkPath: resolvedLink, target: resolvedTarget };

  ownedLinks.push(created);
  symlinkSync(resolvedTarget, resolvedLink, linkType);

  return created;
}

async function installEnvironment(npmCli, tempRoot, tarballPath, definition, ownedLinks) {
  const envDir = path.join(tempRoot, `env-${definition.id}`);

  mkdirSync(envDir, { recursive: true });
  await writeFile(path.join(envDir, 'package.json'), `${JSON.stringify({
    name: definition.packageName,
    private: true,
    type: 'module',
  }, null, 2)}\n`, 'utf8');

  await run(process.execPath, [
    npmCli, 'install', tarballPath,
    '--omit=optional', '--ignore-scripts', '--offline', '--no-audit', '--no-fund',
    '--legacy-peer-deps', '--no-save',
  ], { cwd: envDir, timeout: NPM_TIMEOUT_MS, label: `npm install (${definition.id})` });

  const installedRoot = path.join(envDir, 'node_modules', 'hooklatch');

  if (!existsSync(installedRoot)) {
    throw new InfrastructureError(`offline install did not produce node_modules/hooklatch in ${definition.id}.`);
  }

  const installedManifest = JSON.parse(await readFile(path.join(installedRoot, 'package.json'), 'utf8'));
  const links = [];

  for (const link of definition.links) {
    links.push(createLink(path.join(REPO_ROOT, link.target), path.join(envDir, 'node_modules', link.name), ownedLinks));
  }

  return { definition, envDir, installedRoot, installedManifest, links };
}

function verifyInstalledPackage(environment, manifest, pack) {
  const { installedManifest, installedRoot } = environment;
  const problems = [];

  if (installedManifest.name !== manifest.name) problems.push('installed package name differs from package.json');

  if (installedManifest.version !== manifest.version) problems.push('installed package version differs from package.json');

  if (Object.keys(installedManifest.dependencies ?? {}).length !== 0) problems.push('installed package declares runtime dependencies');

  for (const entrypoint of pack.entrypoints) {
    if (!existsSync(path.join(installedRoot, entrypoint))) problems.push(`installed package is missing ${entrypoint}`);
  }

  if (problems.length > 0) throw new InfrastructureError(`installed package failed inspection: ${problems.join('; ')}`);

  return { entrypoints: pack.entrypoints.length, name: installedManifest.name, version: installedManifest.version };
}

/* -------------------------------------------------------------------------- */
/* TypeScript compilation and classification                                  */
/* -------------------------------------------------------------------------- */

function compilerOptions(ts, definition) {
  return {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    lib: [...definition.libs],
    types: [...definition.types],
    strict: true,
    noEmit: true,
    skipLibCheck: false,
    exactOptionalPropertyTypes: true,
    noUncheckedIndexedAccess: true,
    verbatimModuleSyntax: true,
    forceConsistentCasingInFileNames: true,
    noImplicitReturns: true,
    noFallthroughCasesInSwitch: true,
    pretty: false,
  };
}

const IMPORT_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)['"]([^'"]+)['"]/g;

function importedSpecifiers(source) {
  const specifiers = new Set();
  let match;

  IMPORT_SPECIFIER.lastIndex = 0;

  while ((match = IMPORT_SPECIFIER.exec(source)) !== null) specifiers.add(match[1]);

  return [...specifiers];
}

function assertPackageImportsResolve(ts, caseDefinition, envDir, fileName, source, options) {
  for (const specifier of importedSpecifiers(source)) {
    const isPackageImport = specifier === 'hooklatch' || specifier.startsWith('hooklatch/');

    if (!isPackageImport) continue;

    const resolved = ts.resolveModuleName(specifier, fileName, options, ts.sys).resolvedModule;
    const resolvedFile = resolved === undefined ? '' : path.resolve(resolved.resolvedFileName);
    const installedRoot = path.resolve(envDir, 'node_modules', 'hooklatch');

    if (resolved === undefined
      || !resolvedFile.split(path.sep).join('/').toLowerCase().includes('/node_modules/hooklatch/')
      || !resolvedFile.toLowerCase().startsWith(`${installedRoot.toLowerCase()}${path.sep}`)) {
      throw new InfrastructureError(
        `${caseDefinition.id}: required import '${specifier}' did not resolve to the installed packed package `
        + `(${resolved?.resolvedFileName ?? 'unresolved'}). This is an environment failure, not a type rejection.`,
      );
    }
  }
}

function normalizeDiagnostic(ts, diagnostic, envDir) {
  const message = bounded(ts.flattenDiagnosticMessageText(diagnostic.messageText, ' '));

  if (diagnostic.file === undefined || diagnostic.start === undefined) {
    return { code: diagnostic.code, file: '<global>', line: null, character: null, message };
  }

  const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);

  return {
    code: diagnostic.code,
    file: rel(envDir, diagnostic.file.fileName),
    line: position.line + 1,
    character: position.character + 1,
    message,
  };
}

function compileCaseLocal(ts, caseDefinition, environment, source) {
  const fileName = path.join(environment.envDir, caseDefinition.file);

  writeFileSync(fileName, source, 'utf8');

  const options = compilerOptions(ts, environment.definition);

  assertPackageImportsResolve(ts, caseDefinition, environment.envDir, fileName, source, options);

  const program = ts.createProgram({ rootNames: [fileName], options });

  const diagnostics = ts.getPreEmitDiagnostics(program)
    .map((diagnostic) => normalizeDiagnostic(ts, diagnostic, environment.envDir));

  return { fileName, diagnostics };
}

function compileCase(caseDefinition, environment, source) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: {
        caseDefinition: { id: caseDefinition.id, file: caseDefinition.file },
        source,
        environment: { definition: environment.definition, envDir: environment.envDir },
      },
    });

    let settled = false;
    let timer;

    const finish = async (error, result) => {
      if (settled) return;

      settled = true;
      clearTimeout(timer);

      let terminationTimer;

      const terminated = await Promise.race([
        worker.terminate().then(() => true, () => false),
        new Promise((resolve) => {
          terminationTimer = setTimeout(() => resolve(false), TERMINATE_TIMEOUT_MS);
        }),
      ]);

      clearTimeout(terminationTimer);

      if (!terminated) worker.unref();

      try {
        requireConfirmedTermination(terminated);
      } catch (terminationError) {
        reject(terminationError);

        return;
      }

      if (error) reject(error);
      else resolve(result);
    };

    worker.once('message', (message) => {
      if (message.ok) void finish(null, message.result);
      else void finish(new InfrastructureError(message.message));
    });
    worker.once('error', () => { void finish(new InfrastructureError('Compiler worker failed.')); });
    worker.once('exit', () => { if (!settled) void finish(new InfrastructureError('Compiler worker exited without a result.')); });
    timer = setTimeout(() => { void finish(new InfrastructureError('Compiler worker timed out.')); }, NODE_TIMEOUT_MS);
  });
}

function requireConfirmedTermination(terminated) {
  if (terminated) return;

  lifecycle.cleanupSafe = false;

  throw new InfrastructureError('Compiler worker termination could not be confirmed; temp files retained.');
}

function parseMarkers(source) {
  const markers = [];
  const lines = source.split(/\r?\n/);

  lines.forEach((text, index) => {
    const pattern = /@expect-error\s+(TS\d+)/g;
    let match;

    while ((match = pattern.exec(text)) !== null) markers.push({ code: Number(match[1].slice(2)), line: index + 1 });
  });

  return markers;
}

const diagnosticKey = (entry) => `${entry.code}:${entry.line}`;

function classifyMarkedCase(caseDefinition, diagnostics, source) {
  const markers = parseMarkers(source);
  const expected = markers.map(diagnosticKey).sort();
  const actual = diagnostics.map(diagnosticKey).sort();
  const outside = diagnostics.filter((entry) => entry.file !== caseDefinition.file);
  const failures = [];

  if (markers.length === 0) failures.push('fixture has no @expect-error marker');

  if (outside.length > 0) {
    failures.push(
      `unexpected diagnostics outside the case file: ${outside.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`,
    );
  }

  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    failures.push(`expected ${expected.join(', ') || '(none)'} but got ${actual.join(', ') || '(none)'}`);
  }

  return { markers, failures, pass: failures.length === 0 };
}

function classify(caseDefinition, diagnostics, source) {
  if (caseDefinition.kind === 'positive') {
    const failures = [];

    if (diagnostics.length > 0) {
      failures.push(`expected no diagnostics but got ${diagnostics.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`);
    }

    return { markers: [], failures, pass: failures.length === 0 };
  }

  return classifyMarkedCase(caseDefinition, diagnostics, source);
}

/* -------------------------------------------------------------------------- */
/* public declaration surface                                                 */
/* -------------------------------------------------------------------------- */

function exportInventory(ts, fileName, text) {
  const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const exports = [];

  for (const statement of source.statements) {
    if (ts.isExportDeclaration(statement)) {
      if (statement.exportClause !== undefined && ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) {
          exports.push({ name: element.name.text, kind: 're-export' });
        }
      } else {
        exports.push({ name: '*', kind: 'star-export' });
      }

      continue;
    }

    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true;

    if (!exported) continue;

    if (ts.isFunctionDeclaration(statement) && statement.name !== undefined) {
      exports.push({ name: statement.name.text, kind: 'function' });
    } else if (ts.isInterfaceDeclaration(statement)) {
      exports.push({ name: statement.name.text, kind: 'interface' });
    } else if (ts.isTypeAliasDeclaration(statement)) {
      exports.push({ name: statement.name.text, kind: 'type' });
    } else if (ts.isClassDeclaration(statement) && statement.name !== undefined) {
      exports.push({ name: statement.name.text, kind: 'class' });
    } else if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) exports.push({ name: declaration.name.text, kind: 'variable' });
      }
    }
  }

  return exports.sort((left, right) => left.name.localeCompare(right.name));
}

function extractSurface(ts, environment, packageManifest) {
  const entrypoints = [];
  const exportMap = packageManifest.exports ?? {};
  const declarations = new Map();
  const pending = [];

  for (const [subpath, target] of Object.entries(exportMap)) {
    const typesTarget = target.types;

    if (typesTarget === undefined) throw new InfrastructureError(`package export ${subpath} declares no types target`);

    const relative = typesTarget.startsWith('./') ? typesTarget.slice(2) : typesTarget;
    const absolute = path.join(environment.installedRoot, relative);

    if (!existsSync(absolute)) throw new InfrastructureError(`packed types target is missing: ${relative}`);

    const raw = readFileSync(absolute, 'utf8');
    const declaration = raw.replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trimEnd() + '\n';

    entrypoints.push({
      subpath,
      types: relative,
      exports: exportInventory(ts, absolute, declaration),
      sha256: sha256Text(declaration),
      declaration,
    });
    pending.push(absolute);
  }

  const installedRoot = path.resolve(environment.installedRoot);
  const options = { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext };

  while (pending.length > 0) {
    const absolute = path.resolve(pending.pop());
    const relative = rel(installedRoot, absolute);

    if (declarations.has(relative)) continue;

    if (!absolute.startsWith(`${installedRoot}${path.sep}`) || !/\.d\.(?:ts|mts|cts)$/.test(absolute)) {
      throw new InfrastructureError(`public declaration escaped the installed package: ${relative}`);
    }

    const declaration = readFileSync(absolute, 'utf8').replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trimEnd() + '\n';

    declarations.set(relative, {
      types: relative, exports: exportInventory(ts, absolute, declaration), declaration,
    });

    const references = ts.preProcessFile(declaration, true, true);

    for (const reference of references.importedFiles) {
      if (!reference.fileName.startsWith('.')) continue;

      const resolved = ts.resolveModuleName(reference.fileName, absolute, options, ts.sys).resolvedModule;

      if (resolved === undefined) {
        throw new InfrastructureError(`public declaration reference did not resolve: ${relative} -> ${reference.fileName}`);
      }

      pending.push(resolved.resolvedFileName);
    }

    for (const reference of references.referencedFiles) pending.push(path.resolve(path.dirname(absolute), reference.fileName));
  }

  entrypoints.sort((left, right) => left.subpath.localeCompare(right.subpath));

  return {
    source: 'packed dist/*.d.ts as installed from the offline local tarball',
    packageExports: exportMap,
    entrypoints,
    declarations: [...declarations.values()].sort((left, right) => left.types.localeCompare(right.types)),
  };
}

/* -------------------------------------------------------------------------- */
/* runtime export inventory and docs sample coverage                          */
/* -------------------------------------------------------------------------- */

async function runRuntimeInventory(environment) {
  const script = `
const root = await import('hooklatch');
const diagnostics = await import('hooklatch/diagnostics');
console.log(JSON.stringify({ root: Object.keys(root).sort(), diagnostics: Object.keys(diagnostics).sort() }));
`;

  const stdout = await run(process.execPath, ['--input-type=module', '-e', script], {
    cwd: environment.envDir, timeout: NODE_TIMEOUT_MS, label: 'runtime export inventory',
  });

  let parsed;

  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    throw new InfrastructureError(`runtime export inventory did not return JSON: ${bounded(stdout)}`);
  }

  return parsed;
}

function parseDocsSamples(text) {
  const lines = text.split(/\r?\n/);
  const samples = [];
  let caseId = null;

  for (let index = 0; index < lines.length; index += 1) {
    const match = /<!--\s*compiler-case:\s*([A-Za-z0-9/_-]+)\s*-->/.exec(lines[index]);

    if (match !== null) {
      if (caseId !== null) samples.push({ caseId, codeLines: [], error: 'missing fenced code block' });

      caseId = match[1];

      continue;
    }

    const fence = /^\s*(`{3,}|~{3,})\s*(\S*)\s*$/.exec(lines[index]);

    if (fence === null) continue;

    let fenceEnd = index + 1;
    const closing = fence[1][0].repeat(fence[1].length);

    while (fenceEnd < lines.length && lines[fenceEnd].trim() !== closing) fenceEnd += 1;

    if (fenceEnd >= lines.length) {
      samples.push({ caseId, codeLines: [], error: 'missing closing fence' });

      break;
    }

    if (['ts', 'typescript', 'tsx'].includes(fence[2].toLowerCase())) {
      samples.push({
        caseId,
        codeLines: lines.slice(index + 1, fenceEnd),
        error: caseId === null ? 'TypeScript fence is missing a compiler-case marker' : undefined,
      });
    }

    caseId = null;
    index = fenceEnd;
  }

  if (caseId !== null) samples.push({ caseId, codeLines: [], error: 'missing fenced code block' });

  return samples;
}

function verifyDocsSamples() {
  const docsText = readFileSync(path.join(REPO_ROOT, DOCS_PATH), 'utf8');
  const samples = parseDocsSamples(docsText);
  const failures = [];
  const casesById = new Map(CASES.map((caseDefinition) => [caseDefinition.id, caseDefinition]));

  if (samples.length === 0) failures.push('docs contain no compiler-case samples');

  for (const sample of samples) {
    if (sample.error !== undefined) {
      failures.push(`${sample.caseId}: ${sample.error}`);
      continue;
    }

    const caseDefinition = casesById.get(sample.caseId);

    if (caseDefinition === undefined) {
      failures.push(`${sample.caseId}: docs sample names an unknown matrix case`);
      continue;
    }

    const sourceLines = new Set(
      caseDefinition.source.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0),
    );

    for (const line of sample.codeLines) {
      const trimmed = line.trim();

      if (trimmed.length === 0 || trimmed.startsWith('//')) continue;

      if (!sourceLines.has(trimmed)) {
        failures.push(`${sample.caseId}: docs line is not an excerpt of the case: ${bounded(trimmed)}`);
      }
    }
  }

  return {
    path: DOCS_PATH,
    sampleCount: samples.length,
    caseIds: [...new Set(samples.map((sample) => sample.caseId).filter((id) => id !== null))].sort(),
    failures,
    pass: failures.length === 0,
  };
}

/* -------------------------------------------------------------------------- */
/* controls                                                                   */
/* -------------------------------------------------------------------------- */

function lineNumberContaining(source, needle) {
  const lines = source.split(/\r?\n/);
  const matches = [];

  lines.forEach((line, index) => {
    if (line.includes(needle)) matches.push(index + 1);
  });

  if (matches.length !== 1) {
    throw new InfrastructureError(`control expectation "${needle}" must occur on exactly one line; found ${matches.length}`);
  }

  return matches[0];
}

function diagnosticsMatch(diagnostics, code, line) {
  const matching = diagnostics.filter((entry) => entry.code === code && entry.line === line);

  return { matching, exact: diagnostics.length === 1 && matching.length === 1 };
}

async function runControls(ts, environments, tempRoot, report) {
  const casesById = new Map(CASES.map((caseDefinition) => [caseDefinition.id, caseDefinition]));
  const results = [];

  for (const control of CONTROLS) {
    const result = { id: control.id, description: control.description, expected: {}, actual: {}, status: 'fail', detail: '' };

    try {
      if (control.id === 'control/unresolved-package-is-infrastructure') {
        const envDir = path.join(tempRoot, 'env-empty');

        mkdirSync(envDir, { recursive: true });
        const fileName = path.join(envDir, 'control-unresolved.ts');

        writeFileSync(fileName, control.source, 'utf8');

        const options = compilerOptions(ts, ENVIRONMENTS.core);
        let classified = 'none';

        try {
          assertPackageImportsResolve(ts, { id: control.id, file: 'control-unresolved.ts' }, envDir, fileName, control.source, options);
        } catch (error) {
          if (!(error instanceof InfrastructureError)) throw error;

          classified = 'infrastructure';
        }

        result.expected = { classification: 'infrastructure' };
        result.actual = { classification: classified };
        result.status = classified === 'infrastructure' ? 'pass' : 'fail';
        result.detail = classified === 'infrastructure'
          ? 'unresolved package import was rejected as infrastructure'
          : 'unresolved package import was not classified as infrastructure';
      } else if (control.id === 'control/negative-without-diagnostics-fails') {
        const classified = classifyMarkedCase(
          { id: control.id, file: 'control-negative-empty.ts' }, [], control.source,
        );

        result.expected = { classification: 'case-failure' };
        result.actual = { classification: classified.pass ? 'pass' : 'case-failure', failures: classified.failures };
        result.status = classified.pass ? 'fail' : 'pass';
        result.detail = classified.pass
          ? 'a negative expectation with no diagnostics was accepted'
          : 'a negative expectation with no diagnostics failed classification';
      } else {
        const baseCase = casesById.get(control.baseCaseId);

        if (baseCase === undefined) throw new InfrastructureError(`${control.id}: base case ${control.baseCaseId} is missing`);

        const base = report.cases.find((entry) => entry.id === baseCase.id);

        if (base === undefined || base.status !== 'pass') {
          throw new InfrastructureError(`${control.id}: base case ${baseCase.id} did not pass the matrix`);
        }

        let source = baseCase.source;

        for (const replacement of control.replacements ?? []) {
          if (!source.includes(replacement.from)) {
            throw new InfrastructureError(`${control.id}: mutation source text was not found`);
          }

          source = source.replace(replacement.from, replacement.to);
        }

        if (control.append !== undefined) source = `${source}${control.append}`;

        const environment = environments[baseCase.environment];

        if (environment === undefined) throw new InfrastructureError(`${control.id}: unknown environment`);

        const { diagnostics } = await compileCase(
          { id: control.id, file: `control-${control.id.split('/')[1]}.ts`, kind: 'positive' },
          environment,
          source,
        );

        const expectedLine = lineNumberContaining(source, control.expectedLineContains);
        const match = diagnosticsMatch(diagnostics, control.expectedCode, expectedLine);

        const classified = classify(
          { id: control.id, file: `control-${control.id.split('/')[1]}.ts`, kind: 'positive' },
          diagnostics,
          source,
        );

        result.expected = {
          code: control.expectedCode,
          line: expectedLine,
          classification: control.classification ?? 'exact-diagnostic',
        };
        result.actual = {
          diagnostics,
          classification: classified.pass ? 'pass' : 'case-failure',
        };

        if (control.classification === 'case-failure') {
          result.status = !classified.pass && match.matching.length === 1 ? 'pass' : 'fail';
          result.detail = !classified.pass && match.matching.length === 1
            ? `injected TS${control.expectedCode} was classified as a case failure`
            : 'injected diagnostic was not classified as expected';
        } else {
          result.status = match.exact ? 'pass' : 'fail';
          result.detail = match.exact
            ? `exactly one TS${control.expectedCode} on line ${expectedLine}`
            : `expected exactly one TS${control.expectedCode}:${expectedLine}, got ${diagnostics.map((entry) => `TS${entry.code}:${entry.line}`).join(', ') || '(none)'}`;
        }
      }
    } catch (error) {
      result.status = 'fail';
      result.detail = bounded(error?.message ?? error);
    }

    results.push(result);
  }

  return results;
}

/* -------------------------------------------------------------------------- */
/* report helpers                                                             */
/* -------------------------------------------------------------------------- */

async function runRegressionControls() {
  const failures = [];

  const check = async (name, action) => {
    try {
      await action();
      console.log(`PASS ${name}`);
    } catch (error) {
      failures.push(name);
      console.error(`FAIL ${name}: ${bounded(error.message)}`);
    }
  };

  await check('results cannot overwrite claims or unrelated files', () => {
    for (const target of ['package.json', 'notes/phase-10/deepseek-normal-session.json', 'notes/phase-10/api-freeze-results.json']) {
      assert.throws(() => resolveResultsPath(target), /assigned coordinator API result/);
    }

    assert.equal(resolveResultsPath('notes/phase-10/coordinator-api-freeze-results.json'), path.join(REPO_ROOT, 'notes', 'phase-10', 'coordinator-api-freeze-results.json'));
  });

  await check('unmarked TypeScript fence is rejected', () => {
    const samples = parseDocsSamples('```ts\nconst unchecked: string = 42;\n```\n');

    assert.equal(samples.length, 1);
    assert.ok(samples[0].error);
  });
  await check('marked TypeScript fence is recognized across tilde and backtick fences', () => {
    for (const fence of ['```ts', '~~~typescript', '````tsx']) {
      const samples = parseDocsSamples(`<!-- compiler-case: example -->\n${fence}\nconst x = 1;\n${fence.replace(/[a-z]+$/, '')}\n`);

      assert.equal(samples.length, 1);
      assert.equal(samples[0].caseId, 'example');
      assert.equal(samples[0].error, undefined);
    }
  });
  await check('uncertain worker termination fails and preserves scratch', () => {
    const previous = lifecycle.cleanupSafe;

    try {
      assert.throws(() => requireConfirmedTermination(false), InfrastructureError);
      assert.equal(lifecycle.cleanupSafe, false);
    } finally {
      lifecycle.cleanupSafe = previous;
    }

    requireConfirmedTermination(true);
    assert.equal(lifecycle.cleanupSafe, previous);
  });
  await check('all current TypeScript documentation fences are covered', () => {
    const result = verifyDocsSamples();

    assert.deepEqual(result.failures, []);
  });
  await check('tracked root docs and vendored tools are snapshotted', async () => {
    const snapshot = await snapshotCheckout();

    assert.ok(snapshot.hashes.has('README.md'));
    assert.ok(snapshot.hashes.has('tools/oxlint/anti-slop/index.ts'));
    assert.ok(snapshot.head);
    assert.notEqual(snapshot.gitStatus, null);
  });
  await check('public capture includes referenced definitions', () => {
    const surface = extractSurface(loadTypeScript(), { installedRoot: path.join(REPO_ROOT) },
      JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')));

    assert.ok(surface.declarations?.some((entry) => entry.types === 'dist/types.d.ts'));
    assert.ok(surface.declarations?.some((entry) => entry.types === 'dist/core.d.ts'));
    assert.ok(surface.declarations?.some((entry) => entry.types === 'dist/errors.d.ts'));
  });

  return failures.length === 0 ? EXIT.PASS : EXIT.FAIL;
}

function parseArguments(argv) {
  const parsed = { jsonOnly: false, resultsPath: null, help: false, selfTest: false };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--json') {
      parsed.jsonOnly = true;
    } else if (argument === '--self-test') {
      parsed.selfTest = true;
    } else if (argument === '--help') {
      parsed.help = true;
    } else if (argument === '--results') {
      const value = argv[index + 1];

      if (value === undefined) throw new InfrastructureError('--results requires a path');

      parsed.resultsPath = value;
      index += 1;
    } else {
      throw new InfrastructureError(`unknown argument: ${argument}`);
    }
  }

  return parsed;
}

function resolveResultsPath(value) {
  const resolved = path.resolve(REPO_ROOT, value);
  const assigned = path.resolve(REPO_ROOT, 'notes', 'phase-10', 'coordinator-api-freeze-results.json');

  if (resolved !== assigned) throw new InfrastructureError('--results must name the assigned coordinator API result; claims and prior evidence are immutable');

  for (const component of ['notes', 'notes/phase-10', 'notes/phase-10/coordinator-api-freeze-results.json']) {
    const full = path.join(REPO_ROOT, component);

    if (lstatSync(full, { throwIfNoEntry: false })?.isSymbolicLink()) throw new InfrastructureError('--results refuses symbolic links');
  }

  return resolved;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

async function main() {
  let options;

  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`api-freeze: ${bounded(error?.message ?? error)}`);
    console.error(USAGE);

    return EXIT.USAGE;
  }

  if (options.help) {
    console.log(USAGE);

    return EXIT.PASS;
  }

  if (options.selfTest) return runRegressionControls();

  let resultsPath = null;

  try {
    if (options.resultsPath !== null) resultsPath = resolveResultsPath(options.resultsPath);
  } catch (error) {
    console.error(`api-freeze: ${bounded(error?.message ?? error)}`);

    return EXIT.USAGE;
  }

  const manifest = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));

  const report = {
    schemaVersion: 1,
    owner: 'deepseek-normal',
    task: 'phase10-public-api-freeze',
    baseSha: null,
    node: process.version,
    typescript: null,
    package: null,
    environments: {},
    registry: null,
    surface: null,
    docs: null,
    cases: [],
    controls: [],
    runtime: null,
    cleanup: null,
    checkout: null,
    failures: [],
    status: 'fail',
  };

  const links = [];
  let tempRoot = null;
  let before = null;
  let exitCode = EXIT.PASS;
  const say = (line) => { if (!options.jsonOnly) console.log(line); };

  try {
    const ts = loadTypeScript();

    report.typescript = ts.version;
    before = await snapshotCheckout();
    report.baseSha = before.head;

    const entrypoints = await preflight(manifest);
    const { SUPPORTED_PROVIDERS } = await import(pathToFileURL(path.join(REPO_ROOT, 'dist', 'providers', 'index.js')).href);

    if (!Array.isArray(SUPPORTED_PROVIDERS) || SUPPORTED_PROVIDERS.length === 0) {
      throw new InfrastructureError('the built provider registry did not expose a nonempty SUPPORTED_PROVIDERS array');
    }

    const built = [...SUPPORTED_PROVIDERS];
    const pinned = [...PROVIDER_IDS];
    const registryMatches = built.length === pinned.length && built.every((provider, index) => provider === pinned[index]);

    report.registry = {
      built,
      pinned,
      count: built.length,
      matches: registryMatches,
      source: 'dist/providers/index.js',
    };

    if (!registryMatches) {
      throw new InfrastructureError(
        `provider coverage differs: built registry ${built.join(', ')} vs pinned ${pinned.join(', ')}. `
        + 'Update tests/types/phase10-api-freeze/fixtures.mjs PROVIDER_IDS with the new provider before shipping it.',
      );
    }

    const npmCli = locateNpmCli();

    say(`hooklatch Phase10 public-API freeze (base ${report.baseSha ?? 'unknown'}, node ${report.node}, typescript ${ts.version})`);

    tempRoot = assertInsideTempRoot(await mkdtemp(path.join(tmpdir(), TEMP_PREFIX)));
    say(`  temp root        ${tempRoot}`);

    const pack = await packPackage(npmCli, tempRoot, manifest, entrypoints);

    report.package = {
      name: manifest.name,
      version: manifest.version,
      tarball: pack.filename,
      files: pack.fileCount,
      unpackedBytes: pack.unpackedBytes,
      entrypoints: pack.entrypoints,
    };
    say(`  packed           ${pack.filename} (${pack.fileCount} files, ${pack.unpackedBytes} unpacked bytes)`);

    const environments = {};

    for (const definition of Object.values(ENVIRONMENTS)) {
      const environment = await installEnvironment(npmCli, tempRoot, pack.tarballPath, definition, links);

      verifyInstalledPackage(environment, manifest, pack);

      if (definition.id === 'core') {
        for (const forbidden of ['express', 'hono', '@types']) {
          if (existsSync(path.join(environment.envDir, 'node_modules', forbidden))) {
            throw new InfrastructureError(`core-only install unexpectedly contains ${forbidden}; peer/type isolation is broken.`);
          }
        }
      }

      if (definition.id === 'express') {
        if (!existsSync(path.join(environment.envDir, 'node_modules', 'express', 'package.json'))
          || !existsSync(path.join(environment.envDir, 'node_modules', '@types', 'express', 'index.d.ts'))) {
          throw new InfrastructureError('express environment did not expose the pinned express/@types trees.');
        }
      }

      if (definition.id === 'hono' && !existsSync(path.join(environment.envDir, 'node_modules', 'hono', 'package.json'))) {
        throw new InfrastructureError('hono environment did not expose the pinned hono tree.');
      }

      environments[definition.id] = environment;
      report.environments[definition.id] = {
        description: definition.description,
        libs: definition.libs,
        types: definition.types,
        linked: definition.links.map((link) => link.name),
        install: 'local tarball, offline, --omit=optional --ignore-scripts --legacy-peer-deps',
      };
      say(
        `  environment      ${definition.id} `
        + `(${definition.types.length === 0 ? 'types:[]' : `types:[${definition.types.join(',')}]`}`
        + `${definition.links.length > 0 ? `, links:${definition.links.map((link) => link.name).join('+')}` : ''})`,
      );
    }

    let caseFailures = 0;
    let positiveCount = 0;
    let negativeCount = 0;

    for (const caseDefinition of CASES) {
      const environment = environments[caseDefinition.environment];

      if (environment === undefined) throw new InfrastructureError(`case ${caseDefinition.id} names an unknown environment`);

      const { diagnostics } = await compileCase(caseDefinition, environment, caseDefinition.source);
      const classified = classify(caseDefinition, diagnostics, caseDefinition.source);
      const status = classified.pass ? 'pass' : 'fail';

      if (caseDefinition.kind === 'positive') positiveCount += 1;
      else negativeCount += 1;

      if (!classified.pass) caseFailures += 1;

      report.cases.push({
        id: caseDefinition.id,
        kind: caseDefinition.kind,
        environment: caseDefinition.environment,
        description: caseDefinition.description,
        expected: caseDefinition.kind === 'positive'
          ? { outcome: 'clean', diagnostics: [] }
          : { outcome: 'diagnostics', markers: classified.markers },
        actual: { diagnostics },
        status,
        failures: classified.failures,
      });

      say(`  ${status === 'pass' ? 'PASS' : 'FAIL'}  ${caseDefinition.id}${classified.failures.length > 0 ? ` — ${classified.failures[0]}` : ''}`);
    }

    if (caseFailures > 0) throw new InfrastructureError(`${caseFailures} public-API freeze case(s) did not match the intended outcome`);

    const surface = extractSurface(ts, environments.core, manifest);

    report.surface = surface;
    say(`  surface          ${surface.entrypoints.length} packed entrypoints captured`);

    const docs = verifyDocsSamples();

    report.docs = docs;
    say(`  docs samples     ${docs.sampleCount} excerpt(s) across ${docs.caseIds.length} case(s)${docs.pass ? '' : ' (FAIL)'}`);

    if (!docs.pass) throw new InfrastructureError(`docs sample coverage failed: ${docs.failures[0]}`);

    const runtime = await runRuntimeInventory(environments.core);
    const rootMatches = JSON.stringify(runtime.root) === JSON.stringify(EXPECTED_ROOT_EXPORTS);
    const diagnosticsMatches = JSON.stringify(runtime.diagnostics) === JSON.stringify(EXPECTED_DIAGNOSTICS_EXPORTS);

    report.runtime = {
      root: runtime.root,
      diagnostics: runtime.diagnostics,
      expectedRoot: EXPECTED_ROOT_EXPORTS,
      expectedDiagnostics: EXPECTED_DIAGNOSTICS_EXPORTS,
      rootMatches,
      diagnosticsMatches,
    };

    if (!rootMatches || !diagnosticsMatches) {
      throw new InfrastructureError(
        `runtime export inventory differs: root ${runtime.root.join(', ')}; diagnostics ${runtime.diagnostics.join(', ')}`,
      );
    }

    say(`  runtime exports  root:${runtime.root.join(',')} diagnostics:${runtime.diagnostics.join(',')}`);

    const controls = await runControls(ts, environments, tempRoot, report);

    report.controls = controls;

    for (const control of controls) {
      say(`  ${control.status === 'pass' ? 'PASS' : 'FAIL'}  ${control.id}${control.detail ? ` — ${control.detail}` : ''}`);
    }

    if (controls.some((control) => control.status !== 'pass')) {
      throw new InfrastructureError('freeze controls failed; matrix results cannot be trusted');
    }

    const reasonPins = report.cases.find((entry) => entry.id === 'core/positive-provider-and-union-pins');

    if (reasonPins === undefined) throw new InfrastructureError('the provider/reason/code pin case is missing');

    report.pins = {
      providers: [...PROVIDER_IDS],
      failureReasons: [...FAILURE_REASONS],
      errorCodes: [...ERROR_CODES],
      diagnosticCodes: [...FAILURE_REASONS, ...ERROR_CODES],
    };

    say(`  cases            ${positiveCount} positive, ${negativeCount} negative, ${controls.length} controls`);
    report.status = 'pass';
  } catch (error) {
    exitCode = EXIT.FAIL;
    report.status = 'fail';
    report.failures.push(error instanceof InfrastructureError ? bounded(error.message) : bounded(error?.stack ?? error));
    say('');
    say(`  FAIL  ${bounded(error?.message ?? error)}`);
  } finally {
    const cleanup = { tempRoot: tempRoot === null ? null : path.resolve(tempRoot), links: [], removed: false, insideTemp: false };

    if (tempRoot !== null && !lifecycle.cleanupSafe) {
      cleanup.error = 'Child-process termination is uncertain; temp root retained for inspection.';
      report.failures.push(cleanup.error);
      report.status = 'fail';
      exitCode = EXIT.FAIL;
    }

    if (tempRoot !== null && lifecycle.cleanupSafe) {
      try {
        assertInsideTempRoot(tempRoot);
        cleanup.insideTemp = true;

        for (const link of links) {
          const linkPath = path.resolve(link.linkPath);

          if (!linkPath.startsWith(`${cleanup.tempRoot}${path.sep}`)) {
            cleanup.error = `refusing to unlink a dependency link outside the temp root: ${linkPath}`;
            break;
          }

          const linkStat = lstatSync(linkPath, { throwIfNoEntry: false });

          if (linkStat !== undefined) {
            if (!linkStat.isSymbolicLink() || realpathSync(linkPath) !== realpathSync(link.target)) {
              cleanup.error = `dependency link no longer matches the owned target: ${linkPath}`;

              break;
            }

            unlinkSync(linkPath);
          }

          cleanup.links.push(rel(cleanup.tempRoot, linkPath));
        }

        if (cleanup.error === undefined) {
          await rm(cleanup.tempRoot, { recursive: true, force: true });
          cleanup.removed = !existsSync(cleanup.tempRoot);

          if (!cleanup.removed) cleanup.error = 'Temp root remains after cleanup.';
        }
      } catch (cleanupError) {
        cleanup.error = bounded(cleanupError?.message ?? cleanupError);
      }

      if (cleanup.error !== undefined) {
        report.failures.push(`cleanup failed: ${cleanup.error}`);
        exitCode = EXIT.FAIL;
        report.status = 'fail';
      }
    }

    report.cleanup = cleanup;

    if (before !== null) {
      try {
        const after = await snapshotCheckout();
        const comparison = compareSnapshots(before, after);

        report.checkout = {
          head: before.head,
          gitStatusBefore: before.gitStatus,
          gitStatusAfter: after.gitStatus,
          filesChecked: comparison.checkedFiles,
          failures: comparison.failures,
        };

        if (comparison.failures.length > 0) {
          report.failures.push(...comparison.failures);
          report.status = 'fail';
          exitCode = EXIT.FAIL;
        }
      } catch {
        report.failures.push('Final checkout snapshot could not be verified.');
        report.status = 'fail';
        exitCode = EXIT.FAIL;
      }
    }

    if (report.failures.length > 0) {
      report.status = 'fail';

      if (exitCode === EXIT.PASS) exitCode = EXIT.FAIL;
    }

    if (resultsPath !== null) {
      try {
        resolveResultsPath(resultsPath);
        mkdirSync(path.dirname(resultsPath), { recursive: true });
        await writeFile(resultsPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
      } catch (writeError) {
        report.failures.push(`results file could not be written: ${bounded(writeError?.message ?? writeError)}`);
        report.status = 'fail';
        exitCode = EXIT.FAIL;
      }
    }

    if (!options.jsonOnly) {
      say('');
      say(`  cleanup          ${report.cleanup.removed ? 'removed' : 'NOT removed'} ${report.cleanup.tempRoot ?? ''}`);
      say(
        `  checkout         ${report.checkout === null ? 'not snapshotted' : `${report.checkout.filesChecked} files unchanged${report.checkout.failures.length > 0 ? ' (CHANGED)' : ''}`}`,
      );
      say(`  RESULT           ${report.status.toUpperCase()}`);
    }

    console.log(JSON.stringify(report, null, options.jsonOnly ? 2 : 0));
  }

  return exitCode;
}

if (isMainThread) {
  process.exitCode = await main();
} else {
  try {
    const result = compileCaseLocal(loadTypeScript(), workerData.caseDefinition, workerData.environment, workerData.source);

    parentPort.postMessage({ ok: true, result });
  } catch (error) {
    parentPort.postMessage({ ok: false, message: bounded(error?.message ?? error) });
  }
}
