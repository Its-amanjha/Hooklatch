#!/usr/bin/env node
/**
 * Packed public-contract qualification for hooklatch.
 *
 * Standalone Node entry point: `node scripts/public-contract-smoke.mjs`.
 *
 * What it qualifies (against the ACTUAL packed tarball, never repository src):
 *   1. positive TypeScript consumers in isolated environments (core Web, Express,
 *      Hono), strict NodeNext + skipLibCheck:false, with deliberate libs/types;
 *   2. negative public typing, one independent program per class, with exact
 *      diagnostic code and offending line required;
 *   3. result narrowing and authenticated identity typing;
 *   4. absence of hidden Node/framework type dependencies in core-only consumers;
 *   5. Next.js and Cloudflare declaration consumers without their platforms;
 *   6. runtime export encapsulation (internal subpaths rejected by `exports`).
 *
 * Preparation: run `npm run build` first. This harness never builds, installs
 * from a registry, changes the checkout or repairs your environment.
 *
 * Exit codes: 0 all intended outcomes and cleanup match; 1 contract or
 * infrastructure failure; 2 usage error.
 */

import { spawn, spawnSync } from 'node:child_process';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  CASES, ENVIRONMENTS, PROVIDER_IDS, RUNTIME_BOUNDARY, SELF_TEST,
} from './public-contract/fixtures.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TEMP_PREFIX = 'hooklatch-public-contract-';
const EXIT = { PASS: 0, FAIL: 1, USAGE: 2 };
const NPM_TIMEOUT_MS = 180_000;
const NODE_TIMEOUT_MS = 60_000;
const MESSAGE_LIMIT = 240;
const SNAPSHOT_DIRS = ['src', 'tests', 'scripts', 'examples', '.github'];

const SNAPSHOT_FILES = [
  'package.json', 'package-lock.json', 'tsconfig.json', 'tsconfig.check.json', 'tsconfig.cli.json',
  'tsconfig.examples.json', 'tsconfig.workers.json', 'eslint.config.mjs', '.oxlintrc.json',
];

const USAGE = `Usage: node scripts/public-contract-smoke.mjs [--json] [--help]

  (no flags)  qualify the packed declarations and export boundary, print a summary
  --json      print only the machine-readable JSON report
  --help      print this message

Preparation: run \`npm run build\` first. Exit 0 = every intended outcome and
cleanup matched; 1 = contract/infrastructure failure; 2 = usage error.`;

class InfrastructureError extends Error {}

const lifecycle = { cleanupSafe: true };

/* -------------------------------------------------------------------------- */
/* small utilities                                                             */
/* -------------------------------------------------------------------------- */

const rel = (from, to) => path.relative(from, to).split(path.sep).join('/');

const bounded = (value) => {
  const text = String(value).replace(/\s+/g, ' ').trim();

  return text.length > MESSAGE_LIMIT ? `${text.slice(0, MESSAGE_LIMIT)}...` : text;
};

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

async function run(command, args, { cwd, timeout = NODE_TIMEOUT_MS, label }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let terminationTimer;
    const limit = 16 * 1024 * 1024;

    const timer = setTimeout(() => {
      timedOut = true;

      if (!child.pid) return;

      if (process.platform === 'win32') {
        const termination = spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 15000, stdio: 'ignore' });

        if (termination.error || termination.status !== 0) {
          lifecycle.cleanupSafe = false;
          child.kill('SIGKILL');
        }
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); }
        catch { lifecycle.cleanupSafe = false; child.kill('SIGKILL'); }
      }

      terminationTimer = setTimeout(() => {
        lifecycle.cleanupSafe = false;
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        reject(new InfrastructureError(`${label ?? command} termination could not be confirmed; temp files retained.`));
      }, 5000);
    }, timeout);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk.slice(0, Math.max(0, limit - stdout.length)); });
    child.stderr.on('data', (chunk) => { stderr += chunk.slice(0, Math.max(0, limit - stderr.length)); });
    child.on('error', () => { clearTimeout(timer); reject(new InfrastructureError(`${label ?? command} could not start.`)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      clearTimeout(terminationTimer);

      if (timedOut || code !== 0) reject(new InfrastructureError(`${label ?? command} failed${timedOut ? ' (timeout)' : ` (${code})`}: ${bounded(stderr)}`));
      else resolve(stdout);
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
/* checkout snapshot                                                           */
/* -------------------------------------------------------------------------- */

function walkFiles(relativeDir, output) {
  const absolute = path.join(REPO_ROOT, relativeDir);

  if (!existsSync(absolute)) return;

  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    const relative = path.join(relativeDir, entry.name);

    if (entry.isDirectory()) walkFiles(relative, output);
    else if (entry.isFile()) output.push(relative.split(path.sep).join('/'));
  }
}

async function gitStatus() {
  try {
    return await run('git', ['-C', REPO_ROOT, 'status', '--porcelain'], {
      cwd: REPO_ROOT, timeout: 15_000, label: 'git status',
    });
  } catch {
    return null;
  }
}

async function snapshotCheckout() {
  const files = [];

  for (const dir of SNAPSHOT_DIRS) walkFiles(dir, files);

  for (const file of SNAPSHOT_FILES) if (existsSync(path.join(REPO_ROOT, file))) files.push(file);

  const hashes = new Map();

  for (const file of [...new Set(files)].sort()) hashes.set(file, sha256(path.join(REPO_ROOT, file)));

  let head = null;

  try {
    head = (await run('git', ['-C', REPO_ROOT, 'rev-parse', 'HEAD'], { cwd: REPO_ROOT, timeout: 15_000, label: 'git rev-parse' })).trim();
  } catch {
    head = null;
  }

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
/* package preflight and packing                                               */
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

async function preflightBuild(manifest) {
  const entrypoints = declaredEntrypoints(manifest);
  const missing = entrypoints.filter((entrypoint) => !existsSync(path.join(REPO_ROOT, entrypoint)));

  if (missing.length > 0) {
    throw new InfrastructureError(
      `Built package targets are missing: ${missing.join(', ')}. Run \`npm run build\` in this checkout first; `
      + 'this harness does not build or repair your environment.',
    );
  }

  const registry = path.join(REPO_ROOT, 'dist', 'providers', 'index.js');

  if (!existsSync(registry)) {
    throw new InfrastructureError(
      'Built provider registry is missing: dist/providers/index.js. Run `npm run build` first.',
    );
  }

  if (!existsSync(path.join(REPO_ROOT, 'node_modules', 'typescript', 'lib', 'typescript.js'))) {
    throw new InfrastructureError('The pinned typescript package is missing from node_modules.');
  }

  const binTarget = Object.values(manifest.bin ?? {})[0];

  if (binTarget === undefined) throw new InfrastructureError('package.json declares no CLI bin target.');

  const binRelative = String(binTarget).startsWith('./') ? String(binTarget).slice(2) : String(binTarget);
  const binPath = path.join(REPO_ROOT, binRelative);

  if (!readFileSync(binPath, 'utf8').startsWith('#!/usr/bin/env node')) {
    throw new InfrastructureError(`Built CLI entrypoint lacks the expected shebang: ${rel(REPO_ROOT, binPath)}`);
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

  if (disallowed.length > 0) {
    throw new InfrastructureError(`npm tarball contains files outside dist/package.json/README/LICENSE: ${disallowed.join(', ')}`);
  }

  if (missingEntrypoints.length > 0) {
    throw new InfrastructureError(`npm tarball is missing declared entrypoint(s): ${missingEntrypoints.join(', ')}`);
  }

  const unsafe = files.filter((file) => file.path.startsWith('/') || file.path.split('/').includes('..'));

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
/* isolated consumer environments                                              */
/* -------------------------------------------------------------------------- */

function createLink(target, linkPath) {
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

  symlinkSync(resolvedTarget, resolvedLink, process.platform === 'win32' ? 'junction' : 'dir');

  return { linkPath: resolvedLink, target: resolvedTarget };
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
    const created = createLink(path.join(REPO_ROOT, link.target), path.join(envDir, 'node_modules', link.name));

    ownedLinks.push(created);
    links.push(created);
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
/* TypeScript compilation and classification                                   */
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

async function compileCase(caseDefinition, environment, source) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), { workerData: {
      caseDefinition, source, environment: { definition: environment.definition, envDir: environment.envDir },
    } });

    let settled = false;
    let timer;

    const finish = async (error, result) => {
      if (settled) return;

      settled = true;
      clearTimeout(timer);
      await worker.terminate();

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

function parseMarkers(source) {
  const markers = [];
  const lines = source.split(/\r?\n/);

  lines.forEach((text, index) => {
    const pattern = /@expect-error\s+(TS\d+)/g;
    let match;

    while ((match = pattern.exec(text)) !== null) {
      markers.push({ code: Number(match[1].slice(2)), line: index + 1 });
    }
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
    failures.push(`unexpected diagnostics outside the case file: ${outside.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`);
  }

  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    failures.push(`expected ${expected.join(', ') || '(none)'} but got ${actual.join(', ') || '(none)'}`);
  }

  return { markers, failures, pass: failures.length === 0 };
}

function classifyExternalCase(caseDefinition, diagnostics) {
  const expected = caseDefinition.externalDiagnostics ?? [];

  const matches = (entry, expectation) => entry.code === expectation.code
    && entry.file.split(path.sep).join('/').endsWith(expectation.fileSuffix)
    && entry.message.includes(expectation.messageIncludes);

  const failures = [];

  if (expected.length === 0) failures.push('fixture declares no externalDiagnostics expectation');

  for (const entry of diagnostics) {
    if (!expected.some((expectation) => matches(entry, expectation))) {
      failures.push(`unexpected diagnostic ${entry.file}:${entry.line} TS${entry.code}: ${entry.message}`);
    }
  }

  for (const expectation of expected) {
    if (!diagnostics.some((entry) => matches(entry, expectation))) {
      failures.push(`missing expected TS${expectation.code} in ${expectation.fileSuffix} (${expectation.messageIncludes})`);
    }
  }

  return { markers: [], failures, pass: failures.length === 0 };
}

function classify(caseDefinition, diagnostics, source) {
  const normalized = diagnostics.map((entry) => ({
    ...entry,
    file: entry.file.split(path.sep).join('/'),
  }));

  if (caseDefinition.kind === 'positive') {
    return {
      markers: [],
      failures: normalized.length === 0
        ? []
        : normalized.map((entry) => `unexpected TS${entry.code} at ${entry.file}:${entry.line}`),
      pass: normalized.length === 0,
    };
  }

  if (caseDefinition.kind === 'negative-external') return classifyExternalCase(caseDefinition, normalized);

  return classifyMarkedCase(caseDefinition, normalized, source);
}

/* -------------------------------------------------------------------------- */
/* classifier self-tests                                                       */
/* -------------------------------------------------------------------------- */

async function runClassifierSelfTests(ts, coreEnvironment, tempRoot, results) {
  // 1. A valid program with a marker must NOT be accepted as a passing negative.
  const validName = 'selftest-valid-program-not-negative.ts';
  const validSource = `${SELF_TEST.validProgramSource}// @expect-error ${SELF_TEST.mismatchedMarkerCode}\n`;
  const validCase = { id: 'selftest/valid-program-not-negative', kind: 'negative', file: validName };

  try {
    const { diagnostics } = await compileCase(validCase, coreEnvironment, validSource);
    const classified = classify(validCase, diagnostics, validSource);

    results.push({
      id: validCase.id,
      status: classified.pass ? 'fail' : 'pass',
      detail: classified.pass
        ? 'classifier accepted a diagnostic-free program as a negative success'
        : 'classifier rejected the diagnostic-free program as required',
    });
  } catch (error) {
    results.push({ id: validCase.id, status: 'fail', detail: bounded(error?.message ?? error) });
  }

  // 2. An unresolved package is infrastructure failure, never a type rejection.
  const emptyDir = path.join(tempRoot, 'selftest-unresolved');
  mkdirSync(emptyDir, { recursive: true });
  const emptyFile = path.join(emptyDir, 'unresolved.ts');
  const unresolvedSource = `import '${SELF_TEST.unresolvedSpecifier}';\n`;

  writeFileSync(emptyFile, unresolvedSource, 'utf8');
  const unresolvedCase = { id: 'selftest/unresolved-package', kind: 'negative', file: 'unresolved.ts' };

  try {
    assertPackageImportsResolve(ts, unresolvedCase, emptyDir, emptyFile, unresolvedSource, compilerOptions(ts, ENVIRONMENTS.core));
    results.push({
      id: unresolvedCase.id,
      status: 'fail',
      detail: 'an unresolved package was not classified as infrastructure failure',
    });
  } catch (error) {
    const infrastructure = error instanceof InfrastructureError;

    results.push({
      id: unresolvedCase.id,
      status: infrastructure ? 'pass' : 'fail',
      detail: infrastructure
        ? 'unresolved package raised InfrastructureError as required'
        : `unexpected error class: ${bounded(error?.message ?? error)}`,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* runtime export boundary                                                     */
/* -------------------------------------------------------------------------- */

const RUNTIME_DRIVER = `
const report = { rootExports: [], checks: [] };
const required = ${JSON.stringify(RUNTIME_BOUNDARY.expectedRootExports)};
const blocked = ${JSON.stringify(RUNTIME_BOUNDARY.blockedSubpaths)};
const absentPeers = ${JSON.stringify(RUNTIME_BOUNDARY.absentPeers)};

const root = await import('${RUNTIME_BOUNDARY.root}');
report.rootExports = Object.keys(root).sort();
for (const name of required) {
  report.checks.push({ id: 'root-export:' + name, status: typeof root[name] === 'function' ? 'pass' : 'fail' });
}

const diagnostics = await import('${RUNTIME_BOUNDARY.diagnostics}');
report.checks.push({ id: 'diagnostics-export:diagnose', status: typeof diagnostics.diagnose === 'function' ? 'pass' : 'fail' });

for (const specifier of blocked) {
  try {
    await import(specifier);
    report.checks.push({ id: 'blocked:' + specifier, status: 'fail', detail: 'import unexpectedly succeeded' });
  } catch (error) {
    const code = error && error.code;
    report.checks.push({
      id: 'blocked:' + specifier,
      status: code === 'ERR_PACKAGE_PATH_NOT_EXPORTED' ? 'pass' : 'fail',
      code,
      message: String((error && error.message) || error).slice(0, ${MESSAGE_LIMIT}),
    });
  }
}

for (const peer of absentPeers) {
  try {
    await import(peer);
    report.checks.push({ id: 'absent-peer:' + peer, status: 'fail', detail: 'peer resolved in a core-only install' });
  } catch (error) {
    const code = error && error.code;
    report.checks.push({
      id: 'absent-peer:' + peer,
      status: code === 'ERR_MODULE_NOT_FOUND' ? 'pass' : 'fail',
      code,
      message: String((error && error.message) || error).slice(0, ${MESSAGE_LIMIT}),
    });
  }
}

console.log(JSON.stringify(report));
`;

async function runRuntimeBoundary(coreEnvironment) {
  const driverPath = path.join(coreEnvironment.envDir, 'runtime-boundary.mjs');

  await writeFile(driverPath, RUNTIME_DRIVER, 'utf8');

  const stdout = await run(process.execPath, [driverPath], {
    cwd: coreEnvironment.envDir, timeout: NODE_TIMEOUT_MS, label: 'runtime boundary driver',
  });

  const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1);

  if (line === undefined) throw new InfrastructureError('runtime boundary driver produced no output');

  let parsed;

  try {
    parsed = JSON.parse(line);
  } catch {
    throw new InfrastructureError(`runtime boundary driver produced non-JSON output: ${bounded(line)}`);
  }

  const requiredIds = [
    ...RUNTIME_BOUNDARY.expectedRootExports.map((name) => `root-export:${name}`),
    'diagnostics-export:diagnose',
    ...RUNTIME_BOUNDARY.blockedSubpaths.map((name) => `blocked:${name}`),
    ...RUNTIME_BOUNDARY.absentPeers.map((name) => `absent-peer:${name}`),
  ];

  if (!Array.isArray(parsed.checks) || parsed.checks.length !== requiredIds.length
      || new Set(parsed.checks.map((check) => check.id)).size !== requiredIds.length
      || !requiredIds.every((id) => parsed.checks.some((check) => check.id === id))) {
    throw new InfrastructureError('runtime boundary report has incomplete checks');
  }

  return { rootExports: parsed.rootExports ?? [], checks: parsed.checks };
}

/* -------------------------------------------------------------------------- */
/* main                                                                        */
/* -------------------------------------------------------------------------- */

function baseReport() {
  return {
    schemaVersion: 1,
    harness: 'scripts/public-contract-smoke.mjs',
    status: 'fail',
    node: process.version,
    platform: process.platform,
    typescript: null,
    npmCli: null,
    baseCommit: null,
    package: null,
    environments: {},
    registry: null,
    cases: [],
    selfTests: [],
    runtimeBoundary: null,
    checkout: null,
    cleanup: null,
    failures: [],
  };
}

async function main() {
  const args = process.argv.slice(2);
  const known = new Set(['--json', '--help', '-h']);

  for (const arg of args) {
    if (!known.has(arg)) {
      console.error(`unknown argument: ${arg}\n\n${USAGE}`);

      return EXIT.USAGE;
    }
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);

    return EXIT.PASS;
  }

  const jsonOnly = args.includes('--json');
  const report = baseReport();
  let tempRoot = null;
  let links = [];
  let before = null;
  let exitCode = EXIT.PASS;

  const say = (line) => {
    if (!jsonOnly) console.log(line);
  };

  try {
    const manifest = JSON.parse(await readFile(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    const ts = loadTypeScript();

    report.typescript = ts.version;
    report.baseCommit = (await (async () => {
      try {
        return (await run('git', ['-C', REPO_ROOT, 'rev-parse', 'HEAD'], {
          cwd: REPO_ROOT, timeout: 15_000, label: 'git rev-parse',
        })).trim();
      } catch {
        return null;
      }
    })());

    before = await snapshotCheckout();

    // Fail before packing or importing anything generated when the build is absent.
    const entrypoints = await preflightBuild(manifest);

    // Registry coverage is derived from the built declarations/runtime, not assumed.
    const { SUPPORTED_PROVIDERS } = await import(
      pathToFileURL(path.join(REPO_ROOT, 'dist', 'providers', 'index.js')).href
    );

    if (!Array.isArray(SUPPORTED_PROVIDERS) || SUPPORTED_PROVIDERS.length === 0) {
      throw new InfrastructureError('the built provider registry did not expose a nonempty SUPPORTED_PROVIDERS array');
    }

    const built = [...SUPPORTED_PROVIDERS];
    const fixtures = [...PROVIDER_IDS];
    const registryMatches = built.length === fixtures.length && built.every((provider, index) => provider === fixtures[index]);

    report.registry = {
      built,
      fixture: fixtures,
      count: built.length,
      matches: registryMatches,
      source: 'dist/providers/index.js',
    };

    if (!registryMatches) {
      throw new InfrastructureError(
        `provider coverage differs: built registry ${built.join(', ')} vs fixtures ${fixtures.join(', ')}. `
        + 'Update scripts/public-contract/fixtures.mjs PROVIDER_IDS with the new provider before shipping it.',
      );
    }

    const npmCli = locateNpmCli();

    report.npmCli = path.basename(npmCli);
    say(`hooklatch packed public-contract qualification (base ${report.baseCommit ?? 'unknown'}, node ${report.node}, typescript ${ts.version})`);

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
      say(`  environment      ${definition.id} (${definition.types.length === 0 ? 'types:[]' : `types:[${definition.types.join(',')}]`}${definition.links.length > 0 ? `, links:${definition.links.map((link) => link.name).join('+')}` : ''})`);
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
          : {
            outcome: 'diagnostics',
            markers: classified.markers,
            external: caseDefinition.externalDiagnostics ?? null,
          },
        actual: { diagnostics },
        status,
        failures: classified.failures,
      });

      say(`  ${status === 'pass' ? 'PASS' : 'FAIL'}  ${caseDefinition.id}${classified.failures.length > 0 ? ` — ${classified.failures[0]}` : ''}`);
    }

    if (caseFailures > 0) throw new InfrastructureError(`${caseFailures} public-contract case(s) did not match the intended outcome`);

    await runClassifierSelfTests(ts, environments.core, tempRoot, report.selfTests);

    for (const selfTest of report.selfTests) {
      say(`  ${selfTest.status === 'pass' ? 'PASS' : 'FAIL'}  ${selfTest.id} — ${selfTest.detail}`);
    }

    if (report.selfTests.some((selfTest) => selfTest.status !== 'pass')) {
      throw new InfrastructureError('classifier self-tests failed; classification results cannot be trusted');
    }

    const runtime = await runRuntimeBoundary(environments.core);

    report.runtimeBoundary = runtime;

    for (const check of runtime.checks) {
      say(`  ${check.status === 'pass' ? 'PASS' : 'FAIL'}  ${check.id}${check.detail ? ` — ${check.detail}` : ''}`);
    }

    if (runtime.checks.some((check) => check.status !== 'pass')) {
      throw new InfrastructureError('runtime export-boundary checks failed');
    }

    say(`  cases            ${positiveCount} positive, ${negativeCount} negative`);
    report.status = 'pass';
  } catch (error) {
    exitCode = EXIT.FAIL;
    report.status = 'fail';
    report.failures.push(error instanceof InfrastructureError ? bounded(error.message) : bounded(error?.stack ?? error));
    say('');
    say(`  FAIL  ${bounded(error?.message ?? error)}`);
  } finally {
    // Always unlink dependency junctions before any recursive removal so a
    // cleanup can never traverse into the shared checkout node_modules.
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

          if (lstatSync(linkPath, { throwIfNoEntry: false }) !== undefined) unlinkSync(linkPath);
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

    if (!jsonOnly) {
      say('');
      say(`  cleanup          ${report.cleanup.removed ? 'removed' : 'NOT removed'} ${report.cleanup.tempRoot ?? ''}`);
      say(`  checkout         ${report.checkout === null ? 'not snapshotted' : `${report.checkout.filesChecked} files unchanged${report.checkout.failures.length > 0 ? ' (CHANGED)' : ''}`}`);
      say(`  RESULT           ${report.status.toUpperCase()}`);
    }

    console.log(JSON.stringify(report, null, jsonOnly ? 2 : 0));
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
