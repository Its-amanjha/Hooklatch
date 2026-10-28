#!/usr/bin/env node
/**
 * Phase11 packed CommonJS/ESM public-declaration compatibility gate.
 *
 * Standalone Node entry point: `node scripts/phase11/types-compatibility.mjs`.
 * It is a delivered consumer gate, not a production builder: it never edits
 * src/, package.json, dist/, claims, tasks, notes or any other checkout file.
 *
 * Modes:
 *   - default: inspect the ACTUAL built checkout, then pack that build and test
 *     it. Missing canonical dist/cjs, dist/node facades or the frozen six-entry
 *     export policy is BLOCKED exit 3 before temp, pack, install or dispatch.
 *   - `--tarball FILE`: qualify one explicit, already-built package artifact.
 *     The artifact's SHA-256 and file inventory are recorded as evidence.
 *
 * What every ready run does:
 *   1. reads the artifact as a gzip/tar package and validates its manifest,
 *      export-map key order and complete file inventory without executing it;
 *   2. installs it offline into eight isolated consumer roots, each with its own
 *      package.json/node_modules, plus read-only links to the pinned real peer
 *      type trees only where a peer environment needs them;
 *   3. compiles independent `.mts` and `.cts` consumers under NodeNext and
 *      Node16, a neutral Bundler/Workers `.ts` consumer, and the four frozen
 *      documentation samples with the real pinned TypeScript 6.0.3 at
 *      `skipLibCheck: false`;
 *   4. records TypeScript module-resolution evidence for every package import:
 *      Node ESM facade for `.mts`, canonical `dist/cjs/*.d.cts` for `.cts`,
 *      original `dist/*.d.ts` for Bundler/Workers;
 *   5. walks the reachable facade/declaration graph, checks every edge exists,
 *      proves the Node graph never reaches an original duplicate declaration,
 *      and confirms `HooklatchError` has exactly one declaration path;
 *   6. runs real-compiler negative controls in isolated package copies (missing
 *      target, removed export, widened union) plus unresolved-package and
 *      classifier controls;
 *   7. snapshots tracked files, dist and linked peer manifests before/after,
 *      removes temp state, verifies cleanup and refuses to overwrite results.
 *
 * Exit codes: 0 every intended outcome and control matched; 1 contract or
 * infrastructure failure; 2 usage error; 3 blocked prerequisite (missing
 * canonical build, toolchain, peer tree or explicit tarball).
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { gunzipSync } from 'node:zlib';

import {
  CASES, CONTROLS, DIAGNOSTIC_CODES, DOC_ENVIRONMENT, DOC_SAMPLES, ENVIRONMENTS, ERROR_CODES,
  EXPECTED_EXPORT_MAP, FAILURE_REASONS, PACKAGE_POLICY, PROVIDER_IDS, PUBLIC_ENTRIES,
  PUBLIC_ENTRY_BY_SPECIFIER, expectedDeclaration,
} from '../../tests/types/phase11-commonjs/fixtures.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEMP_PREFIX = 'hooklatch-phase11-types-';
const RESULT_SCHEMA = 1;
const EXIT = Object.freeze({ READY: 0, FAIL: 1, USAGE: 2, BLOCKED: 3 });
const NPM_TIMEOUT_MS = 180_000;
const COMPILE_TIMEOUT_MS = 240_000;
const CONTROL_TIMEOUT_MS = 120_000;
const TERMINATE_TIMEOUT_MS = 10_000;
const MESSAGE_LIMIT = 240;
const REPORT_DIAGNOSTIC_LIMIT = 40;
const TYPESCRIPT_VERSION = '6.0.3';

const EXPECTED_PEERS = Object.freeze({
  express: '5.3.0',
  hono: '4.13.13',
  '@types/express': '5.0.6',
});

const NODE_TYPES_MAJOR = 22;

const LINKED_MANIFESTS = Object.freeze([
  'node_modules/express/package.json',
  'node_modules/hono/package.json',
  'node_modules/@types/express/package.json',
  'node_modules/@types/node/package.json',
]);

const LIMITATIONS = Object.freeze([
  'Evidence is host-specific: this run does not substitute for the coordinator-owned Linux Node 22.0.0/22/24 CI jobs.',
  'An explicit --tarball candidate is qualified only as an artifact; the Phase10 prototype CJS emitter is not the production builder.',
  'This gate checks declaration resolution and strict type acceptance, not runtime HooklatchError/function identity or raw-byte execution.',
  'Express, Hono and @types trees are read-only junctions to this checkout node_modules; the gate never installs or updates them.',
  'Documentation samples are compiled verbatim from the embedded fixtures with allowJs/checkJs in the docs environment.',
  'Default checkout mode never silently falls back to a seed candidate; missing canonical build output is BLOCKED exit 3.',
]);

const USAGE = `Usage: node scripts/phase11/types-compatibility.mjs [options]

  (no flags)              verify the ACTUAL built checkout, then pack and test it
  --tarball <file>        qualify one explicit, already-built package tarball
  --results <file>        write a new JSON evidence report inside this checkout
  --self-test             run pure harness/classifier regression controls only
  --help                  print this message

Exit codes:
  0  every intended case, control, graph edge, integrity and cleanup check matched
  1  contract or infrastructure failure
  2  usage error
  3  blocked prerequisite (missing canonical build, toolchain, pinned peer tree or tarball)

Default mode is intentionally BLOCKED until dist/cjs, dist/node facades and the
frozen six-entry export policy exist in the checkout. The harness never builds,
installs dependencies from a registry, edits tracked files, pushes or publishes.
--results refuses to overwrite an existing file and may not target .git or a claim.`;

class UsageError extends Error {}

class BlockedError extends Error {}

class GateError extends Error {}

const lifecycle = { cleanupSafe: true };

/* -------------------------------------------------------------------------- */
/* small utilities                                                            */
/* -------------------------------------------------------------------------- */

const toPosix = (value) => String(value).split(path.sep).join('/');

const relPosix = (from, to) => toPosix(path.relative(from, to));

const bounded = (value) => {
  const text = String(value).replace(/\s+/g, ' ').trim();

  return text.length > MESSAGE_LIMIT ? `${text.slice(0, MESSAGE_LIMIT)}...` : text;
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const isPlainObject = (value) => value !== null && Object.prototype.toString.call(value) === '[object Object]';

const isInside = (parent, child) => {
  const relative = path.relative(parent, child);

  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
};

const isInsideOrEqual = (parent, child) => path.resolve(parent) === path.resolve(child) || isInside(parent, child);

function assertCondition(condition, message) {
  if (!condition) throw new GateError(message);
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new GateError(`cannot read JSON from ${relPosix(REPO_ROOT, file) || file}`);
  }
}

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
    const label = options.label ?? command;

    const timer = setTimeout(() => {
      timedOut = true;

      if (!child.pid) return;

      if (process.platform === 'win32') {
        const termination = spawnSync(
          'taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
          { windowsHide: true, timeout: 15_000, stdio: 'ignore' },
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
        reject(new GateError(`${label} termination could not be confirmed; temp files retained.`));
      }, 5_000);
    }, options.timeout ?? COMPILE_TIMEOUT_MS);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk.slice(0, Math.max(0, limit - stdout.length)); });
    child.stderr.on('data', (chunk) => { stderr += chunk.slice(0, Math.max(0, limit - stderr.length)); });
    child.on('error', () => {
      clearTimeout(timer);
      reject(new GateError(`${label} could not start.`));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      clearTimeout(terminationTimer);

      if (timedOut || code !== 0) {
        reject(new GateError(`${label} failed${timedOut ? ' (timeout)' : ` (${code})`}: ${bounded(stderr)}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

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
    throw new BlockedError(
      'npm CLI is unavailable: neither npm_execpath nor the node installation provides npm-cli.js. '
      + 'Use a normal Node/npm installation; this harness installs nothing.',
    );
  }

  return found;
}

function readToolchain() {
  const major = Number(process.versions.node.split('.')[0]);

  if (!Number.isInteger(major) || major < 22) {
    throw new BlockedError(`Node >=22 is required by the package contract; this host is ${process.version}.`);
  }

  const tsManifestPath = path.join(REPO_ROOT, 'node_modules', 'typescript', 'package.json');

  if (!existsSync(tsManifestPath)) {
    throw new BlockedError('The pinned typescript package is missing from this checkout node_modules.');
  }

  const tsManifest = readJson(tsManifestPath);

  if (tsManifest.version !== TYPESCRIPT_VERSION) {
    throw new BlockedError(
      `This gate requires TypeScript ${TYPESCRIPT_VERSION}; checkout node_modules has ${String(tsManifest.version)}.`,
    );
  }

  return {
    node: process.version,
    typescript: tsManifest.version,
    npmCli: locateNpmCli(),
    platform: process.platform,
    arch: process.arch,
  };
}

function readPeerToolchain() {
  const versions = {};

  for (const relative of LINKED_MANIFESTS) {
    const absolute = path.join(REPO_ROOT, relative);

    if (!existsSync(absolute)) {
      throw new BlockedError(`The pinned peer type tree is missing: ${relative}. Run npm ci in this checkout.`);
    }

    versions[relative] = readJson(absolute).version;
  }

  const express = versions['node_modules/express/package.json'];
  const hono = versions['node_modules/hono/package.json'];
  const typesExpress = versions['node_modules/@types/express/package.json'];
  const typesNode = String(versions['node_modules/@types/node/package.json']);
  const typesNodeMajor = Number(typesNode.split('.')[0]);

  if (express !== EXPECTED_PEERS.express) {
    throw new BlockedError(`Express must be pinned to ${EXPECTED_PEERS.express}; found ${String(express)}.`);
  }

  if (hono !== EXPECTED_PEERS.hono) {
    throw new BlockedError(`Hono must be pinned to ${EXPECTED_PEERS.hono}; found ${String(hono)}.`);
  }

  if (typesExpress !== EXPECTED_PEERS['@types/express']) {
    throw new BlockedError(
      `@types/express must be pinned to ${EXPECTED_PEERS['@types/express']}; found ${String(typesExpress)}.`,
    );
  }

  if (typesNodeMajor !== NODE_TYPES_MAJOR) {
    throw new BlockedError(`@types/node must stay on major ${NODE_TYPES_MAJOR}; found ${typesNode}.`);
  }

  return {
    express,
    hono,
    '@types/express': typesExpress,
    '@types/node': typesNode,
  };
}

/* -------------------------------------------------------------------------- */
/* argument parsing and path guards                                           */
/* -------------------------------------------------------------------------- */

function parseArgs(argv) {
  const options = { help: false, selfTest: false, tarball: undefined, results: undefined };
  const seen = new Set();

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--help' || argument === '--self-test') {
      if (seen.has(argument)) throw new UsageError(`duplicate option ${argument}`);

      seen.add(argument);

      if (argument === '--help') options.help = true;
      else options.selfTest = true;

      continue;
    }

    if (argument === '--tarball' || argument === '--results') {
      if (seen.has(argument)) throw new UsageError(`duplicate option ${argument}`);

      seen.add(argument);

      const value = argv[index + 1];

      if (value === undefined || value.startsWith('--')) {
        throw new UsageError(`${argument} requires a file path`);
      }

      if (argument === '--tarball') options.tarball = value;
      else options.results = value;
      index += 1;

      continue;
    }

    throw new UsageError(`unknown option: ${argument}`);
  }

  if (options.selfTest && (options.tarball !== undefined || options.results !== undefined)) {
    throw new UsageError('--self-test is standalone and cannot be combined with --tarball or --results');
  }

  if (options.help && (options.selfTest || options.tarball !== undefined || options.results !== undefined)) {
    throw new UsageError('--help is standalone');
  }

  return options;
}

function validateResultsPath(file) {
  const resolved = path.resolve(REPO_ROOT, file);

  if (!isInsideOrEqual(REPO_ROOT, resolved) || path.resolve(REPO_ROOT) === resolved) {
    throw new UsageError('--results must name a file inside this checkout, not the checkout root');
  }

  const relative = path.relative(REPO_ROOT, resolved);
  const segments = relative.split(path.sep);

  if (segments.includes('.git')) throw new UsageError('--results may not target .git');

  if (/session\.json$/i.test(path.basename(resolved))) {
    throw new UsageError('--results may not target a session/claim file');
  }

  if (path.extname(resolved).toLowerCase() !== '.json') {
    throw new UsageError('--results must end in .json');
  }

  if (existsSync(resolved)) {
    throw new UsageError(`--results refuses to overwrite an existing file: ${relPosix(REPO_ROOT, resolved)}`);
  }

  const parent = path.dirname(resolved);

  if (!existsSync(parent) || !statSync(parent).isDirectory()) {
    throw new UsageError(`--results parent directory does not exist: ${relPosix(REPO_ROOT, parent)}`);
  }

  let cursor = REPO_ROOT;

  for (const segment of segments.slice(0, -1)) {
    cursor = path.join(cursor, segment);

    if (existsSync(cursor) && lstatSync(cursor).isSymbolicLink()) {
      throw new UsageError('--results may not traverse a symbolic link');
    }
  }

  return resolved;
}

function checkTempPath(dir) {
  const base = path.resolve(tmpdir());
  const resolved = path.resolve(dir);

  if (resolved === base || !isInside(base, resolved)) {
    throw new GateError(`refusing to operate outside the OS temp directory: ${resolved}`);
  }

  if (!path.basename(resolved).startsWith(TEMP_PREFIX)) {
    throw new GateError(`refusing to operate on a directory without the ${TEMP_PREFIX} prefix: ${resolved}`);
  }

  return resolved;
}

function assertInsideTempRoot(dir) {
  const resolved = realpathSync(dir);

  return checkTempPath(resolved);
}

function createTempRoot() {
  const base = realpathSync(tmpdir());
  const root = mkdtempSync(path.join(base, TEMP_PREFIX));

  return assertInsideTempRoot(root);
}

function cleanupTempRoot(root) {
  if (root === null || !existsSync(root)) return { removed: true, path: null };

  if (!lifecycle.cleanupSafe) {
    return { removed: false, path: root, reason: 'a child termination could not be confirmed' };
  }

  try {
    assertInsideTempRoot(root);
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (error) {
    return { removed: false, path: root, reason: bounded(error instanceof Error ? error.message : error) };
  }

  return { removed: !existsSync(root), path: existsSync(root) ? root : null };
}

/* -------------------------------------------------------------------------- */
/* gzip/tar package inspection                                                */
/* -------------------------------------------------------------------------- */

function cString(buffer, offset, length) {
  let end = offset;

  while (end < offset + length && buffer[end] !== 0) end += 1;

  return buffer.subarray(offset, end).toString('utf8');
}

function parseOctal(field) {
  const text = field.replace(/\0/g, '').trim();

  if (text.length === 0) return 0;

  const value = Number.parseInt(text, 8);

  return Number.isInteger(value) ? value : -1;
}

function parsePax(data) {
  const result = {};
  let offset = 0;

  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);

    if (space === -1) break;

    const length = Number.parseInt(data.subarray(offset, space).toString('ascii'), 10);

    if (!Number.isInteger(length) || length <= 0 || offset + length > data.length) break;

    const record = data.subarray(offset, offset + length);
    const equals = record.indexOf(0x3d);

    if (equals > 0) {
      const key = record.subarray(0, equals).toString('utf8');
      const value = record.subarray(equals + 1, Math.max(equals + 1, record.length - 1)).toString('utf8');

      result[key] = value;
    }

    offset += length;
  }

  return result;
}

function normalizeTarPath(entryName) {
  const normalized = String(entryName).replace(/\\/g, '/');

  assertCondition(!normalized.startsWith('/') && !normalized.includes('\0'), `unsafe absolute tar path: ${normalized}`);

  const segments = normalized.split('/');

  assertCondition(
    segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..'),
    `unsafe tar path segment: ${normalized}`,
  );
  assertCondition(segments[0] === 'package', `tar entry is outside the package root: ${normalized}`);

  return normalized;
}

function readTarEntries(tarballPath) {
  const compressed = readFileSync(tarballPath);
  let tar;

  try {
    tar = gunzipSync(compressed);
  } catch {
    throw new GateError(`package artifact is not gzip-compressed: ${path.basename(tarballPath)}`);
  }

  const entries = new Map();
  let offset = 0;
  let longName = null;
  let pax = null;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    let zero = true;

    for (let index = 0; index < 512; index += 1) {
      if (header[index] !== 0) {
        zero = false;
        break;
      }
    }

    if (zero) break;

    const name = cString(header, 0, 100);
    const prefix = cString(header, 345, 155);
    const size = parseOctal(cString(header, 124, 12));
    const type = String.fromCharCode(header[156]);
    const dataStart = offset + 512;

    assertCondition(size >= 0 && dataStart + size <= tar.length, `corrupt tar size for ${name || '<unnamed>'}`);

    const data = tar.subarray(dataStart, dataStart + size);

    if (type === 'L') {
      longName = cString(data, 0, data.length);
    } else if (type === 'x') {
      pax = parsePax(data);
    } else if (type !== 'g') {
      if (type === '0' || type === '\0') {
        const entryName = pax?.path ?? longName ?? (prefix.length > 0 ? `${prefix}/${name}` : name);
        const normalized = normalizeTarPath(entryName);

        entries.set(normalized, Buffer.from(data));
      } else if (type === '5') {
        const directoryName = prefix.length > 0 ? `${prefix}/${name}` : name;

        normalizeTarPath(directoryName.replace(/\/+$/, ''));
      }

      longName = null;
      pax = null;
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return { entries, compressed };
}

function inspectTarball(tarballPath) {
  const { entries, compressed } = readTarEntries(tarballPath);
  const packageEntry = entries.get('package/package.json');

  if (packageEntry === undefined) throw new GateError('package artifact has no package/package.json');

  let manifest;

  try {
    manifest = JSON.parse(packageEntry.toString('utf8'));
  } catch {
    throw new GateError('package artifact package.json is not valid JSON');
  }

  const files = [...entries.keys()].sort();
  let unpackedBytes = 0;

  for (const data of entries.values()) unpackedBytes += data.length;

  return {
    tarballPath: path.resolve(tarballPath),
    sha256: sha256(compressed),
    compressedBytes: compressed.length,
    fileCount: files.length,
    unpackedBytes,
    files,
    entries,
    manifest,
  };
}

/* -------------------------------------------------------------------------- */
/* frozen package policy                                                      */
/* -------------------------------------------------------------------------- */

function normalizeTarget(value) {
  const text = String(value);

  assertCondition(
    !text.startsWith('/') && !text.split('/').includes('..'),
    `package target is unsafe: ${text}`,
  );

  return text.startsWith('./') ? text.slice(2) : text;
}

function declaredTargets(manifest) {
  const targets = new Set();

  const add = (value) => {
    if (value !== undefined) targets.add(normalizeTarget(value));
  };

  const walk = (value) => {
    if (isPlainObject(value)) {
      for (const nested of Object.values(value)) walk(nested);
    } else {
      add(value);
    }
  };

  add(manifest.main);
  add(manifest.types);

  if (isPlainObject(manifest.bin)) {
    for (const value of Object.values(manifest.bin)) add(value);
  } else {
    add(manifest.bin);
  }

  walk(manifest.exports);

  return [...targets].sort();
}

function checkConditionMap(actual, expected, label, problems) {
  if (!isPlainObject(actual)) {
    problems.push(`${label}: expected an object`);

    return;
  }

  const actualKeys = Object.keys(actual);
  const expectedKeys = Object.keys(expected);

  if (actualKeys.join('|') !== expectedKeys.join('|')) {
    problems.push(`${label}: key order/set must be ${expectedKeys.join(',')} but was ${actualKeys.join(',')}`);
  }

  for (const key of expectedKeys) {
    const expectedValue = expected[key];

    if (isPlainObject(expectedValue)) {
      checkConditionMap(actual[key], expectedValue, `${label}.${key}`, problems);
    } else if (actual[key] !== expectedValue) {
      problems.push(`${label}.${key}: expected ${String(expectedValue)} but got ${String(actual[key])}`);
    }
  }
}

function checkExportMap(actual) {
  const problems = [];

  if (!isPlainObject(actual)) {
    problems.push('exports: expected an object');

    return problems;
  }

  const actualKeys = Object.keys(actual);
  const expectedKeys = PUBLIC_ENTRIES.map((entry) => entry.subpath);

  if (actualKeys.join('|') !== expectedKeys.join('|')) {
    problems.push(`exports: subpaths must be ${expectedKeys.join(',')} but were ${actualKeys.join(',')}`);
  }

  for (const entry of PUBLIC_ENTRIES) {
    checkConditionMap(actual[entry.subpath], EXPECTED_EXPORT_MAP[entry.subpath], `exports[${entry.subpath}]`, problems);
  }

  return problems;
}

function checkManifestPolicy(manifest) {
  const problems = [];

  if (manifest.name !== PACKAGE_POLICY.name) problems.push(`name must be ${PACKAGE_POLICY.name}`);

  if (manifest.type !== PACKAGE_POLICY.type) problems.push(`type must be ${PACKAGE_POLICY.type}`);

  if (manifest.main !== PACKAGE_POLICY.main) problems.push(`main must be ${PACKAGE_POLICY.main}`);

  if (manifest.types !== PACKAGE_POLICY.types) problems.push(`types must be ${PACKAGE_POLICY.types}`);

  if (!isPlainObject(manifest.bin) || manifest.bin.hooklatch !== PACKAGE_POLICY.bin.hooklatch) {
    problems.push(`bin.hooklatch must be ${PACKAGE_POLICY.bin.hooklatch}`);
  }

  if (!isPlainObject(manifest.engines) || manifest.engines.node !== PACKAGE_POLICY.engines.node) {
    problems.push(`engines.node must be ${PACKAGE_POLICY.engines.node}`);
  }

  const dependencies = manifest.dependencies;

  if (isPlainObject(dependencies) && Object.keys(dependencies).length > 0) {
    problems.push('runtime dependencies must stay empty');
  }

  const peers = manifest.peerDependencies;

  if (!isPlainObject(peers)) {
    problems.push('peerDependencies must declare express and hono');
  } else {
    const keys = Object.keys(peers).sort();

    if (keys.join('|') !== 'express|hono') problems.push('peerDependencies must contain exactly express and hono');

    if (peers.express !== PACKAGE_POLICY.peerDependencies.express) {
      problems.push(`peerDependencies.express must be ${PACKAGE_POLICY.peerDependencies.express}`);
    }

    if (peers.hono !== PACKAGE_POLICY.peerDependencies.hono) {
      problems.push(`peerDependencies.hono must be ${PACKAGE_POLICY.peerDependencies.hono}`);
    }
  }

  problems.push(...checkExportMap(manifest.exports));

  return problems;
}

function validateArtifact(artifact) {
  const { manifest, entries, files } = artifact;
  const problems = checkManifestPolicy(manifest);

  if (problems.length > 0) {
    throw new GateError(`package artifact does not implement the frozen public policy: ${problems.slice(0, 12).join('; ')}`);
  }

  const entrySet = new Set(files);

  const allowedTopLevel = (file) => file === 'package/package.json'
    || file === 'package/README.md'
    || file === 'package/LICENSE'
    || file.startsWith('package/dist/');

  const disallowed = files.filter((file) => !allowedTopLevel(file));

  if (disallowed.length > 0) {
    throw new GateError(`package artifact contains files outside package.json/README/LICENSE/dist: ${disallowed.join(', ')}`);
  }

  const declared = declaredTargets(manifest);
  const missing = declared.filter((target) => !entrySet.has(`package/${target}`));

  if (missing.length > 0) {
    throw new GateError(`package artifact is missing declared target(s): ${missing.join(', ')}`);
  }

  const cjsFiles = files.filter((file) => file.startsWith('package/dist/cjs/') && file.endsWith('.cjs'));
  const cjsDeclarations = files.filter((file) => file.startsWith('package/dist/cjs/') && file.endsWith('.d.cts'));
  const cjsDeclarationSet = new Set(cjsDeclarations);
  const cjsRuntimeSet = new Set(cjsFiles);
  const facadeFiles = files.filter((file) => file.startsWith('package/dist/node/') && file.endsWith('.d.ts'));

  if (cjsFiles.length === 0 || cjsDeclarations.length === 0) {
    throw new GateError('package artifact has no canonical dist/cjs runtime/declaration graph');
  }

  if (facadeFiles.length !== PUBLIC_ENTRIES.length) {
    throw new GateError(`package artifact must contain exactly ${PUBLIC_ENTRIES.length} Node facade declarations`);
  }

  if (files.some((file) => file.startsWith('package/dist/cjs/cli/'))) {
    throw new GateError('canonical CJS graph must exclude the ESM CLI');
  }

  for (const file of cjsFiles) {
    const declaration = `${file.slice(0, -4)}.d.cts`;

    if (!cjsDeclarationSet.has(declaration)) problems.push(`missing CJS declaration for ${file}`);
  }

  for (const file of cjsDeclarations) {
    const runtime = `${file.slice(0, -6)}.cjs`;

    if (!cjsRuntimeSet.has(runtime)) problems.push(`missing CJS runtime for ${file}`);
  }

  for (const entry of PUBLIC_ENTRIES) {
    const facade = `package/dist/node/${entry.base}.d.ts`;
    const runtime = `package/dist/node/${entry.base}.js`;
    const leaf = `package/dist/cjs/${entry.base}.d.cts`;

    if (!entrySet.has(facade)) problems.push(`missing Node facade ${facade}`);

    if (!entrySet.has(runtime)) problems.push(`missing Node facade runtime ${runtime}`);

    if (!entrySet.has(leaf)) problems.push(`missing canonical CJS leaf ${leaf}`);

    if (entrySet.has(facade)) {
      const text = entries.get(facade).toString('utf8');

      if (!text.includes('.cjs')) problems.push(`Node facade ${facade} does not re-export a .cjs specifier`);

      if (/\bdeclare\s+(?:class|interface|type|function)\b/.test(text)) {
        problems.push(`Node facade ${facade} contains a duplicate declaration body`);
      }
    }
  }

  for (const entry of PUBLIC_ENTRIES) {
    const original = `package/dist/${entry.base}.d.ts`;

    if (!entrySet.has(original)) problems.push(`missing original neutral declaration ${original}`);
  }

  if (problems.length > 0) throw new GateError(`package artifact graph is incomplete: ${problems.slice(0, 12).join('; ')}`);
}

function listFiles(root, relative = '', output = []) {
  const absolute = relative.length === 0 ? root : path.join(root, relative);

  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const nested = relative.length === 0 ? entry.name : path.join(relative, entry.name);

    if (entry.isDirectory()) {
      listFiles(root, nested, output);
    } else if (entry.isFile()) {
      output.push(toPosix(nested));
    } else {
      output.push(`<unsupported:${toPosix(nested)}>`);
    }
  }

  return output;
}

function verifyInstalledFiles(artifact, installedRoot) {
  const problems = [];
  const expected = new Map();

  for (const [key, data] of artifact.entries) {
    const relative = key.slice('package/'.length);

    expected.set(relative, sha256(data));
    const absolute = path.join(installedRoot, relative);

    if (!existsSync(absolute) || !lstatSync(absolute).isFile()) {
      problems.push(`installed package is missing ${relative}`);

      continue;
    }

    if (lstatSync(absolute).isSymbolicLink()) problems.push(`installed package file is a link: ${relative}`);
    else if (sha256(readFileSync(absolute)) !== expected.get(relative)) {
      problems.push(`installed package file differs from artifact: ${relative}`);
    }
  }

  const installed = listFiles(installedRoot).sort();
  const expectedList = [...expected.keys()].sort();

  if (installed.join('|') !== expectedList.join('|')) {
    const extra = installed.filter((file) => !expected.has(file));
    const missing = expectedList.filter((file) => !installed.includes(file));

    if (extra.length > 0) problems.push(`installed package has extra files: ${extra.slice(0, 8).join(', ')}`);

    if (missing.length > 0) problems.push(`installed package is missing files: ${missing.slice(0, 8).join(', ')}`);
  }

  if (problems.length > 0) throw new GateError(problems.slice(0, 12).join('; '));
}

/* -------------------------------------------------------------------------- */
/* default checkout readiness                                                 */
/* -------------------------------------------------------------------------- */

function assertProductionReady() {
  const manifestPath = path.join(REPO_ROOT, 'package.json');

  if (!existsSync(manifestPath)) throw new BlockedError('checkout package.json is missing');

  const manifest = readJson(manifestPath);
  const problems = checkManifestPolicy(manifest);

  if (problems.length > 0) {
    throw new BlockedError(
      `canonical CommonJS/facade package policy is not implemented: ${problems.slice(0, 10).join('; ')}. `
      + 'This checkout is BLOCKED before temp, pack, install or dispatch.',
    );
  }

  const missing = [];

  const addIfMissing = (target) => {
    const absolute = path.join(REPO_ROOT, target);

    if (!existsSync(absolute) || !statSync(absolute).isFile()) missing.push(target);
  };

  for (const target of declaredTargets(manifest)) addIfMissing(target);

  for (const entry of PUBLIC_ENTRIES) {
    addIfMissing(`dist/cjs/${entry.base}.cjs`);
    addIfMissing(`dist/cjs/${entry.base}.d.cts`);
    addIfMissing(`dist/node/${entry.base}.js`);
    addIfMissing(`dist/node/${entry.base}.d.ts`);
  }

  const uniqueMissing = [...new Set(missing)].sort();

  if (uniqueMissing.length > 0) {
    throw new BlockedError(
      `canonical CJS/facade build outputs are missing: ${uniqueMissing.slice(0, 12).join(', ')}. `
      + 'Run `npm run build` in this checkout first; the harness never builds or repairs production mode.',
    );
  }

  for (const entry of PUBLIC_ENTRIES) {
    const facade = readFileSync(path.join(REPO_ROOT, 'dist', 'node', `${entry.base}.d.ts`), 'utf8');

    if (!facade.includes('.cjs') || /\bdeclare\s+(?:class|interface|type|function)\b/.test(facade)) {
      throw new BlockedError(`dist/node/${entry.base}.d.ts is not a canonical CJS re-export facade`);
    }
  }

  return manifest;
}

async function packCheckout(tempRoot, toolchain) {
  const packDir = path.join(tempRoot, 'pack');

  mkdirSync(packDir, { recursive: true });

  const stdout = await run(process.execPath, [
    toolchain.npmCli, 'pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', packDir,
  ], { cwd: REPO_ROOT, timeout: NPM_TIMEOUT_MS, label: 'npm pack' });

  let parsed;

  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new GateError(`npm pack did not return JSON: ${bounded(stdout)}`);
  }

  const entry = Array.isArray(parsed) ? parsed[0] : undefined;

  if (!isPlainObject(entry) || entry.filename === undefined) {
    throw new GateError('npm pack returned no package entry with a filename');
  }

  return inspectTarball(path.join(packDir, String(entry.filename)));
}

/* -------------------------------------------------------------------------- */
/* isolated consumer environments                                             */
/* -------------------------------------------------------------------------- */

function createLink(target, linkPath, tempRoot) {
  const lexicalTarget = path.resolve(target);
  const resolvedTarget = realpathSync(lexicalTarget);
  const repoNodeModules = path.resolve(REPO_ROOT, 'node_modules');
  const resolvedRepoNodeModules = realpathSync(repoNodeModules);
  const resolvedLink = path.resolve(linkPath);

  if (!isInsideOrEqual(repoNodeModules, lexicalTarget) || !isInsideOrEqual(resolvedRepoNodeModules, resolvedTarget)) {
    throw new GateError(`refusing to link a dependency outside this checkout node_modules: ${resolvedTarget}`);
  }

  if (!isInside(tempRoot, resolvedLink)) {
    throw new GateError(`refusing to create a dependency link outside OS temp: ${resolvedLink}`);
  }

  if (existsSync(resolvedLink)) throw new GateError(`link target already exists: ${resolvedLink}`);

  const linkType = process.platform === 'win32' ? 'junction' : 'dir';

  symlinkSync(resolvedTarget, resolvedLink, linkType);

  return { linkPath: resolvedLink, target: resolvedTarget };
}

function verifyIsolation(envDir, definition) {
  const nodeModules = path.join(envDir, 'node_modules');
  const allowed = new Set(['hooklatch']);

  for (const link of definition.links) allowed.add(link.name);

  const visible = readdirSync(nodeModules).filter((name) => !name.startsWith('.'));
  const unexpected = visible.filter((name) => !allowed.has(name));

  if (unexpected.length > 0) {
    throw new GateError(`${definition.id}: unexpected node_modules entries: ${unexpected.join(', ')}`);
  }

  for (const link of definition.links) {
    const linkPath = path.join(nodeModules, link.name);
    const linkStat = lstatSync(linkPath);

    if (!linkStat.isSymbolicLink()) throw new GateError(`${definition.id}: ${link.name} is not a read-only link`);

    const expectedTarget = realpathSync(path.join(REPO_ROOT, link.target));
    const actualTarget = realpathSync(linkPath);

    if (actualTarget.toLowerCase() !== expectedTarget.toLowerCase()) {
      throw new GateError(`${definition.id}: ${link.name} links to ${actualTarget}, expected ${expectedTarget}`);
    }
  }

  if (existsSync(path.join(nodeModules, '@types', 'hooklatch'))) {
    throw new GateError(`${definition.id}: a stub @types/hooklatch package is present`);
  }

  if (definition.links.every((link) => link.name !== '@types') && existsSync(path.join(nodeModules, '@types'))) {
    throw new GateError(`${definition.id}: @types is present in a no-Node-types environment`);
  }

  const packageStat = lstatSync(path.join(nodeModules, 'hooklatch'));

  if (packageStat.isSymbolicLink()) throw new GateError(`${definition.id}: installed hooklatch is a link, not the artifact`);

  return visible.sort();
}

async function installEnvironment(artifact, definition, tempRoot, toolchain) {
  const envDir = path.join(tempRoot, `env-${definition.id}`);

  mkdirSync(envDir, { recursive: true });
  writeFileSync(path.join(envDir, 'package.json'), `${JSON.stringify({
    name: definition.packageName,
    private: true,
    type: 'module',
  }, null, 2)}\n`, 'utf8');

  await run(process.execPath, [
    toolchain.npmCli, 'install', artifact.tarballPath,
    '--omit=optional', '--ignore-scripts', '--offline', '--no-audit', '--no-fund',
    '--legacy-peer-deps', '--no-save', '--no-package-lock', '--cache', path.join(tempRoot, 'npm-cache'),
  ], { cwd: envDir, timeout: NPM_TIMEOUT_MS, label: `npm install (${definition.id})` });

  const installedRoot = path.join(envDir, 'node_modules', 'hooklatch');

  if (!existsSync(installedRoot)) {
    throw new GateError(`offline install did not produce node_modules/hooklatch in ${definition.id}`);
  }

  const installedManifest = readJson(path.join(installedRoot, 'package.json'));

  if (installedManifest.name !== artifact.manifest.name || installedManifest.version !== artifact.manifest.version) {
    throw new GateError(`${definition.id}: installed package identity differs from the artifact manifest`);
  }

  const policyProblems = checkManifestPolicy(installedManifest);

  if (policyProblems.length > 0) {
    throw new GateError(`${definition.id}: installed manifest policy differs: ${policyProblems.slice(0, 8).join('; ')}`);
  }

  verifyInstalledFiles(artifact, installedRoot);

  for (const link of definition.links) {
    createLink(path.join(REPO_ROOT, link.target), path.join(envDir, 'node_modules', link.name), tempRoot);
  }

  const visible = verifyIsolation(envDir, definition);

  return { definition, envDir, installedRoot, installedManifest, visible };
}

/* -------------------------------------------------------------------------- */
/* TypeScript compilation                                                     */
/* -------------------------------------------------------------------------- */

function loadTypeScript() {
  const requireFromRepo = createRequire(pathToFileURL(path.join(REPO_ROOT, 'package.json')).href);

  let ts;

  try {
    ts = requireFromRepo('typescript');
  } catch {
    throw new GateError('The pinned typescript package is missing from this checkout node_modules.');
  }

  if (ts.version !== TYPESCRIPT_VERSION) {
    throw new GateError(`Compiler worker loaded TypeScript ${String(ts.version)}, expected ${TYPESCRIPT_VERSION}.`);
  }

  return ts;
}

function compilerOptions(ts, definition, envDir) {
  const mappings = {
    nodenext: [ts.ModuleKind.NodeNext, ts.ModuleResolutionKind.NodeNext],
    node16: [ts.ModuleKind.Node16, ts.ModuleResolutionKind.Node16],
    bundler: [ts.ModuleKind.ESNext, ts.ModuleResolutionKind.Bundler],
  };

  const mapping = mappings[definition.module];

  if (mapping === undefined) throw new GateError(`unknown module mode: ${String(definition.module)}`);

  const [module, moduleResolution] = mapping;
  const allowJs = definition.allowJs === true;

  return {
    target: ts.ScriptTarget.ES2022,
    module,
    moduleResolution,
    lib: [...definition.libs],
    types: [...definition.types],
    typeRoots: [path.join(envDir, 'node_modules', '@types')],
    strict: true,
    noEmit: true,
    skipLibCheck: false,
    exactOptionalPropertyTypes: true,
    noUncheckedIndexedAccess: true,
    verbatimModuleSyntax: !allowJs,
    allowJs,
    checkJs: allowJs,
    forceConsistentCasingInFileNames: true,
    noImplicitReturns: true,
    noFallthroughCasesInSwitch: true,
    pretty: false,
  };
}

function normalizeDiagnostic(ts, diagnostic, envDir) {
  const message = bounded(ts.flattenDiagnosticMessageText(diagnostic.messageText, ' '));

  if (diagnostic.file === undefined || diagnostic.start === undefined) {
    return { code: diagnostic.code, file: '<global>', line: null, character: null, message };
  }

  const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);

  return {
    code: diagnostic.code,
    file: relPosix(envDir, diagnostic.file.fileName),
    line: position.line + 1,
    character: position.character + 1,
    message,
  };
}

function resolutionModeForFile(ts, fileName) {
  if (fileName.endsWith('.cts') || fileName.endsWith('.cjs')) return ts.ModuleKind.CommonJS;

  return ts.ModuleKind.ESNext;
}

function scanSourceSpecifiers(source) {
  const lines = String(source).split(/\r?\n/);
  const found = [];

  const patterns = [
    { pattern: /\bfrom\s+['"]([^'"]+)['"]/g, dynamic: false },
    { pattern: /\brequire\s*\(\s*['"]([^'"]+)['"]/g, dynamic: false },
    { pattern: /^\s*import\s+['"]([^'"]+)['"]/g, dynamic: false },
    { pattern: /\bimport\s*\(\s*['"]([^'"]+)['"]/g, dynamic: true },
  ];

  const seen = new Set();

  lines.forEach((text, index) => {
    for (const { pattern, dynamic } of patterns) {
      pattern.lastIndex = 0;

      let match;

      while ((match = pattern.exec(text)) !== null) {
        const key = `${index}:${match.index}:${match[1]}:${String(dynamic)}`;

        if (seen.has(key)) continue;

        seen.add(key);
        found.push({ specifier: match[1], dynamic, line: index + 1 });
      }
    }
  });

  return found.sort((left, right) => left.line - right.line);
}

function buildProbes(caseDefinition) {
  const probes = [];
  const environment = ENVIRONMENTS[caseDefinition.environment];

  for (const occurrence of scanSourceSpecifiers(caseDefinition.source)) {
    if (!occurrence.specifier.startsWith('hooklatch')) continue;

    const entry = PUBLIC_ENTRY_BY_SPECIFIER[occurrence.specifier];

    if (entry === undefined) {
      probes.push({
        fileName: caseDefinition.fileName,
        specifier: occurrence.specifier,
        dynamic: occurrence.dynamic,
        line: occurrence.line,
        expected: null,
        expectedKind: caseDefinition.allowUnresolved === true ? 'unresolved-expected' : 'unexpected-specifier',
      });

      continue;
    }

    let expected;

    if (environment.distribution === 'neutral') expected = `dist/${entry.base}.d.ts`;
    else if (occurrence.dynamic || caseDefinition.format === '.mts' || caseDefinition.format === '.mjs') {
      expected = `dist/node/${entry.base}.d.ts`;
    } else {
      expected = `dist/cjs/${entry.base}.d.cts`;
    }

    probes.push({
      fileName: caseDefinition.fileName,
      specifier: occurrence.specifier,
      dynamic: occurrence.dynamic,
      line: occurrence.line,
      expected,
      expectedKind: 'declaration',
    });
  }

  return probes;
}

function compileEnvironment(environment, caseDefinitions) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: {
        kind: 'compile',
        envDir: environment.envDir,
        definition: environment.definition,
        fileNames: caseDefinitions.map((caseDefinition) => caseDefinition.fileName),
        probes: caseDefinitions.flatMap((caseDefinition) => buildProbes(caseDefinition)),
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
        new Promise((done) => {
          terminationTimer = setTimeout(() => done(false), TERMINATE_TIMEOUT_MS);
        }),
      ]);

      clearTimeout(terminationTimer);

      if (!terminated) worker.unref();

      if (!terminated) {
        lifecycle.cleanupSafe = false;
        reject(new GateError('Compiler worker termination could not be confirmed; temp files retained.'));

        return;
      }

      if (error !== null) reject(error);
      else resolve(result);
    };

    worker.once('message', (message) => {
      if (message.ok) void finish(null, message.result);
      else void finish(new GateError(String(message.message)));
    });
    worker.once('error', () => { void finish(new GateError('Compiler worker failed.')); });
    worker.once('exit', () => { if (!settled) void finish(new GateError('Compiler worker exited without a result.')); });
    timer = setTimeout(() => {
      void finish(new GateError('Compiler worker timed out.'));
    }, environment.definition.id.startsWith('control') ? CONTROL_TIMEOUT_MS : COMPILE_TIMEOUT_MS);
  });
}

/* -------------------------------------------------------------------------- */
/* classification                                                             */
/* -------------------------------------------------------------------------- */

function parseMarkers(source) {
  const markers = [];
  const lines = String(source).split(/\r?\n/);

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

function classifyCase(caseDefinition, diagnostics, source, siblingFiles = []) {
  const markers = parseMarkers(source);
  const siblings = new Set(siblingFiles);
  const inFile = diagnostics.filter((entry) => entry.file === caseDefinition.fileName);
  const outside = diagnostics.filter((entry) => entry.file !== caseDefinition.fileName && !siblings.has(entry.file));
  const failures = [];

  if (caseDefinition.kind === 'positive') {
    if (markers.length > 0) failures.push('positive fixture contains an @expect-error marker');

    if (inFile.length > 0) {
      failures.push(`expected no diagnostics but got ${inFile.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`);
    }

    if (outside.length > 0) {
      failures.push(`unexpected diagnostics outside ${caseDefinition.fileName}: ${outside.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`);
    }

    return {
      status: failures.length === 0 ? 'pass' : 'fail',
      failureKind: failures.length === 0 ? null : 'unexpected-diagnostics',
      markers,
      actual: inFile,
      outside,
      failures,
    };
  }

  if (markers.length === 0) failures.push('negative fixture has no @expect-error marker');

  if (outside.length > 0) {
    failures.push(`unexpected diagnostics outside ${caseDefinition.fileName}: ${outside.map((entry) => `${entry.file}:${entry.line} TS${entry.code}`).join(', ')}`);
  }

  const expected = markers.map(diagnosticKey).sort();
  const actual = inFile.map(diagnosticKey).sort();
  let failureKind = null;

  if (actual.length === 0) failureKind = 'silent-success';
  else if (expected.join('|') !== actual.join('|')) failureKind = 'mismatch';

  if (actual.length === 0) failures.push('negative fixture produced no type diagnostics');
  else if (failureKind === 'mismatch') {
    failures.push(`expected ${expected.join(', ')} but got ${actual.join(', ')}`);
  }

  return {
    status: failures.length === 0 ? 'pass' : 'fail',
    failureKind: failures.length === 0 ? null : (failureKind ?? 'mismatch'),
    markers,
    actual: inFile,
    outside,
    failures,
  };
}

function evaluateCase(caseDefinition, diagnostics, probes, siblingFiles = []) {
  const caseProbes = probes.filter((probe) => probe.fileName === caseDefinition.fileName);
  const resolutionProblems = [];

  for (const probe of caseProbes) {
    if (probe.expectedKind === 'unexpected-specifier') {
      resolutionProblems.push({
        kind: 'unexpected-specifier',
        message: `${probe.specifier} is not one of the six public subpaths`,
      });

      continue;
    }

    if (probe.expected === null) {
      if (probe.outside) {
        resolutionProblems.push({
          kind: 'unexpected-resolution',
          message: `${probe.specifier} resolved outside the installed package`,
        });
      } else if (probe.actual !== null) {
        resolutionProblems.push({
          kind: 'unexpected-resolution',
          message: `${probe.specifier} resolved to ${probe.actual} although the exports map must reject it`,
        });
      }

      continue;
    }

    if (probe.outside) {
      resolutionProblems.push({
        kind: 'resolution-escaped-package',
        message: `${probe.specifier} resolved outside the installed package`,
      });
    } else if (probe.actual === null) {
      resolutionProblems.push({
        kind: 'unresolved-package',
        message: `${probe.specifier} did not resolve to ${probe.expected}`,
      });
    } else if (probe.actual.toLowerCase() !== probe.expected.toLowerCase()) {
      resolutionProblems.push({
        kind: 'wrong-resolution',
        message: `${probe.specifier} resolved to ${probe.actual}, expected ${probe.expected}`,
      });
    }
  }

  if (caseDefinition.kind === 'positive' && caseProbes.length === 0) {
    resolutionProblems.push({ kind: 'missing-import', message: 'positive fixture has no package import to resolve' });
  }

  const classification = classifyCase(caseDefinition, diagnostics, caseDefinition.source, siblingFiles);
  const unresolved = resolutionProblems.some((problem) => problem.kind === 'unresolved-package');

  const status = resolutionProblems.length > 0
    ? (unresolved ? 'infrastructure' : 'fail')
    : classification.status;

  const failureKind = resolutionProblems.length > 0
    ? resolutionProblems[0].kind
    : classification.failureKind;

  return {
    id: caseDefinition.id,
    familyId: caseDefinition.familyId,
    kind: caseDefinition.kind,
    environment: caseDefinition.environment,
    format: caseDefinition.format,
    description: caseDefinition.description,
    status,
    failureKind,
    resolutionProblems,
    resolution: caseProbes.map((probe) => ({
      specifier: probe.specifier,
      dynamic: probe.dynamic,
      line: probe.line,
      expected: probe.expected,
      actual: probe.actual,
      outside: probe.outside,
      status: probe.outside || probe.actual === null
        ? (probe.expected === null ? 'expected-unresolved' : 'unresolved')
        : (probe.expected === null ? 'unexpected-resolution' : 'resolved'),
    })),
    markers: classification.markers,
    diagnostics: classification.actual.slice(0, REPORT_DIAGNOSTIC_LIMIT),
    outside: classification.outside.slice(0, REPORT_DIAGNOSTIC_LIMIT),
    failures: [...resolutionProblems.map((problem) => problem.message), ...classification.failures].slice(0, REPORT_DIAGNOSTIC_LIMIT),
    isDocs: caseDefinition.isDocs === true,
  };
}

/* -------------------------------------------------------------------------- */
/* graph walks                                                                */
/* -------------------------------------------------------------------------- */

const RELATIVE_SPECIFIER = /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"](\.[^'"]+)['"]/g;

function relativeSpecifiers(text) {
  const found = [];
  const pattern = new RegExp(RELATIVE_SPECIFIER.source, 'g');

  let match;

  while ((match = pattern.exec(text)) !== null) found.push(match[1]);

  return found;
}

function mapDeclarationTarget(from, specifier) {
  const joined = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));

  if (joined.startsWith('../') || joined.startsWith('/')) return null;

  if (specifier.endsWith('.cjs')) return `${joined.slice(0, -4)}.d.cts`;

  if (specifier.endsWith('.js')) return `${joined.slice(0, -3)}.d.ts`;

  if (specifier.endsWith('.mjs')) return `${joined.slice(0, -4)}.d.mts`;

  return null;
}

function mapRuntimeTarget(from, specifier) {
  const joined = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));

  if (joined.startsWith('../') || joined.startsWith('/')) return null;

  return joined;
}

function walkDeclarationGraph(installedRoot) {
  const problems = [];
  const edges = [];
  const visited = new Set();
  const queue = PUBLIC_ENTRIES.map((entry) => `dist/node/${entry.base}.d.ts`);
  const facadeLeaves = {};

  while (queue.length > 0) {
    const file = queue.shift();

    if (visited.has(file)) continue;

    const absolute = path.join(installedRoot, file);

    if (!existsSync(absolute)) {
      problems.push(`reachable declaration is missing: ${file}`);

      continue;
    }

    visited.add(file);

    const text = readFileSync(absolute, 'utf8');

    for (const specifier of relativeSpecifiers(text)) {
      const target = mapDeclarationTarget(file, specifier);

      if (target === null) {
        problems.push(`${file}: unsupported relative declaration specifier ${specifier}`);

        continue;
      }

      edges.push({ from: file, specifier, to: target });

      if (file.startsWith('dist/node/')) {
        if (!target.startsWith('dist/cjs/') || !target.endsWith('.d.cts')) {
          problems.push(`${file}: Node facade edge must stay on the canonical CJS declaration graph (${target})`);
        }

        if (facadeLeaves[file] === undefined) facadeLeaves[file] = target;
      } else if (file.startsWith('dist/cjs/')) {
        if (!target.startsWith('dist/cjs/') || !target.endsWith('.d.cts')) {
          problems.push(`${file}: CJS declaration edge escaped dist/cjs (${target})`);
        }
      } else {
        problems.push(`${file}: declaration is outside dist/node and dist/cjs`);
      }

      if (!existsSync(path.join(installedRoot, target))) {
        problems.push(`${file}: missing declaration edge target ${target}`);
      } else {
        queue.push(target);
      }
    }
  }

  const classPaths = [];

  for (const file of visited) {
    const text = readFileSync(path.join(installedRoot, file), 'utf8');
    const matches = text.match(/\bclass\s+HooklatchError\b/g);

    if (matches !== null) classPaths.push({ file, count: matches.length });

    if (file.startsWith('dist/cjs/') && file.endsWith('.d.cts')) {
      const runtime = `${file.slice(0, -6)}.cjs`;

      if (!existsSync(path.join(installedRoot, runtime))) problems.push(`${file}: missing sibling runtime ${runtime}`);
    }
  }

  if (classPaths.length !== 1 || classPaths[0].file !== 'dist/cjs/errors.d.cts' || classPaths[0].count !== 1) {
    problems.push(
      `HooklatchError must have exactly one declaration path at dist/cjs/errors.d.cts; found ${JSON.stringify(classPaths)}`,
    );
  }

  for (const entry of PUBLIC_ENTRIES) {
    const leaf = `dist/cjs/${entry.base}.d.cts`;

    if (!visited.has(leaf)) problems.push(`public entry ${entry.subpath} does not reach ${leaf}`);
  }

  for (const entry of PUBLIC_ENTRIES) {
    const facade = `dist/node/${entry.base}.d.ts`;
    const runtime = `dist/node/${entry.base}.js`;

    if (!existsSync(path.join(installedRoot, runtime))) problems.push(`missing facade runtime ${runtime}`);

    if (facadeLeaves[facade] !== `dist/cjs/${entry.base}.d.cts`) {
      problems.push(`${facade}: first facade edge must be dist/cjs/${entry.base}.d.cts`);
    }
  }

  const allDeclarations = listFiles(installedRoot).filter((file) => file.endsWith('.d.cts'));

  return {
    facades: PUBLIC_ENTRIES.map((entry) => `dist/node/${entry.base}.d.ts`),
    facadeLeaves,
    reachableDeclarations: [...visited].filter((file) => file.endsWith('.d.cts')).sort(),
    declarationCount: allDeclarations.length,
    edges,
    classPaths,
    problems,
  };
}

function walkRuntimeGraph(installedRoot) {
  const problems = [];

  const files = listFiles(installedRoot).filter((file) => (
    (file.startsWith('dist/cjs/') && file.endsWith('.cjs')) || (file.startsWith('dist/node/') && file.endsWith('.js'))
  ));

  let edges = 0;

  for (const file of files) {
    const text = readFileSync(path.join(installedRoot, file), 'utf8');

    for (const specifier of relativeSpecifiers(text)) {
      const target = mapRuntimeTarget(file, specifier);

      if (target === null) {
        problems.push(`${file}: relative runtime specifier escaped the package: ${specifier}`);

        continue;
      }

      edges += 1;

      if (!specifier.endsWith('.cjs')) problems.push(`${file}: relative runtime edge is not .cjs: ${specifier}`);

      if (!existsSync(path.join(installedRoot, target))) problems.push(`${file}: missing runtime edge target ${target}`);
    }
  }

  return { files: files.length, edges, problems };
}

/* -------------------------------------------------------------------------- */
/* controls                                                                   */
/* -------------------------------------------------------------------------- */

function findCase(controlCase) {
  const found = CASES.find((entry) => (
    entry.familyId === controlCase.familyId
    && entry.environment === controlCase.environment
    && entry.format === controlCase.format
  ));

  if (found === undefined) {
    throw new GateError(`control case is not in the frozen matrix: ${JSON.stringify(controlCase)}`);
  }

  return found;
}

function copyInstalledPackage(source, destination) {
  mkdirSync(destination, { recursive: true });

  for (const entry of readdirSync(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(destination, entry.name);

    if (entry.isDirectory()) {
      copyInstalledPackage(from, to);
    } else if (entry.isFile()) {
      writeFileSync(to, readFileSync(from));
    } else {
      throw new GateError(`installed package contains an unsupported file type: ${from}`);
    }
  }
}

function applyMutation(installedRoot, mutation) {
  if (mutation.type === 'move-augmentation') {
    const canonical = path.join(installedRoot, 'dist', 'cjs', 'adapters', `${mutation.provider}.d.cts`);
    const facade = path.join(installedRoot, 'dist', 'node', 'adapters', `${mutation.provider}.d.ts`);
    const before = readFileSync(canonical, 'utf8');
    const start = before.indexOf('declare module ');
    const end = before.indexOf('\n}', start) + 2;

    if (start < 0 || end < start) throw new GateError('augmentation control cannot find its declared module');

    const augmentation = before.slice(start, end);

    writeFileSync(canonical, before.slice(0, start) + before.slice(end));
    writeFileSync(facade, `${readFileSync(facade, 'utf8')}\nimport type { VerificationSuccess } from '../../cjs/types.cjs';\n${augmentation}\n`);

    return { type: mutation.type, provider: mutation.provider, movedTo: 'esm-facade-only' };
  }

  if (mutation.type === 'delete-file') {
    const target = path.join(installedRoot, mutation.file);

    if (!existsSync(target)) throw new GateError(`control mutation target is missing: ${mutation.file}`);

    rmSync(target);

    return { type: mutation.type, file: mutation.file, removed: true };
  }

  if (mutation.type === 'unexport') {
    const target = path.join(installedRoot, mutation.file);

    if (!existsSync(target)) throw new GateError(`control mutation target is missing: ${mutation.file}`);

    const before = readFileSync(target, 'utf8');
    const needle = `export type ${mutation.symbol} =`;
    const after = before.replace(needle, `type ${mutation.symbol} =`);

    if (after === before) throw new GateError(`control mutation did not find ${needle}`);

    writeFileSync(target, after, 'utf8');

    return { type: mutation.type, file: mutation.file, symbol: mutation.symbol, exported: false };
  }

  if (mutation.type === 'widen-provider') {
    const target = path.join(installedRoot, 'dist', 'cjs', 'types.d.cts');

    if (!existsSync(target)) throw new GateError('control mutation target is missing: dist/cjs/types.d.cts');

    const before = readFileSync(target, 'utf8');
    const after = before.replace(/export type Provider =[\s\S]*?;/, 'export type Provider = string;');

    if (after === before) throw new GateError('control mutation did not find the Provider union');

    writeFileSync(target, after, 'utf8');

    return { type: mutation.type, file: 'dist/cjs/types.d.cts', provider: 'string' };
  }

  throw new GateError(`unknown control mutation: ${String(mutation.type)}`);
}

async function compileControlCase(caseDefinition, envDir, definition) {
  const fileName = path.join(envDir, caseDefinition.fileName);

  mkdirSync(envDir, { recursive: true });
  writeFileSync(fileName, caseDefinition.source, 'utf8');

  const result = await compileEnvironment(
    { definition, envDir },
    [caseDefinition],
  );

  return evaluateCase(caseDefinition, result.diagnostics, result.probes);
}

async function runControls(baseEnvironment, tempRoot) {
  const controls = [];

  for (const control of CONTROLS) {
    const caseDefinition = findCase(control.case);
    let actualStatus;
    let actualFailureKind;
    let detail;
    let detected;

    if (control.kind === 'classifier') {
      const classification = classifyCase(caseDefinition, [], caseDefinition.source);

      actualStatus = classification.status;
      actualFailureKind = classification.failureKind;
      detected = classification.status === 'fail' && classification.failureKind === 'silent-success';
      detail = { classification: classification.failures, compilerDispatched: false };
    } else if (control.kind === 'unresolved-package') {
      const envDir = path.join(tempRoot, 'controls', control.id.replace(/[^a-z0-9-]/gi, '-'));

      const result = await compileControlCase(
        caseDefinition, envDir, ENVIRONMENTS[caseDefinition.environment],
      );

      actualStatus = result.status;
      actualFailureKind = result.failureKind;
      detected = result.status === 'infrastructure';
      detail = { resolution: result.resolution, failures: result.failures, compilerDispatched: true };
    } else if (control.kind === 'mutate-package') {
      const envDir = path.join(tempRoot, 'controls', control.id.replace(/[^a-z0-9-]/gi, '-'));
      const installedRoot = path.join(envDir, 'node_modules', 'hooklatch');

      copyInstalledPackage(baseEnvironment.installedRoot, installedRoot);

      const mutation = applyMutation(installedRoot, control.mutation);
      const definition = ENVIRONMENTS[caseDefinition.environment];

      for (const link of definition.links) {
        createLink(path.join(REPO_ROOT, link.target), path.join(envDir, 'node_modules', link.name), tempRoot);
      }

      const result = await compileControlCase(
        caseDefinition, envDir, ENVIRONMENTS[caseDefinition.environment],
      );

      actualStatus = result.status;
      actualFailureKind = result.failureKind;
      detected = control.expect === 'infrastructure'
        ? result.status === 'infrastructure'
        : (result.status === 'fail' && result.failureKind === control.expect);

      if (control.expectedDiagnostic !== undefined) {
        const line = caseDefinition.source.split('\n').findIndex((text) => text.includes(control.lineText)) + 1;

        detected = line > 0 && result.status === 'fail' && result.outside.length === 0
          && result.diagnostics.some((diagnostic) => diagnostic.code === control.expectedDiagnostic
            && diagnostic.line === line && diagnostic.file === caseDefinition.fileName);
      }

      detail = {
        mutation,
        resolution: result.resolution,
        diagnostics: result.diagnostics,
        outside: result.outside,
        failures: result.failures,
        compilerDispatched: true,
      };
    } else {
      throw new GateError(`unknown control kind: ${String(control.kind)}`);
    }

    controls.push({
      id: control.id,
      kind: control.kind,
      description: control.description,
      expected: control.expect,
      actualStatus,
      actualFailureKind,
      detected,
      detail,
    });
  }

  if (controls.length !== CONTROLS.length) throw new GateError('not every frozen control was executed');

  return controls;
}

/* -------------------------------------------------------------------------- */
/* checkout snapshot and integrity                                            */
/* -------------------------------------------------------------------------- */

async function git(args, label) {
  return run('git', ['-C', REPO_ROOT, ...args], {
    cwd: REPO_ROOT, timeout: 30_000, label: label ?? `git ${args[0]}`,
  });
}

function walkCheckoutDirectory(relativeDir, files) {
  const absolute = path.join(REPO_ROOT, relativeDir);

  if (!existsSync(absolute)) {
    files.set(relativeDir, '<absent>');

    return;
  }

  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;

    const nested = path.join(relativeDir, entry.name);

    if (entry.isDirectory()) walkCheckoutDirectory(nested, files);
    else if (entry.isFile()) files.set(toPosix(nested), sha256(readFileSync(path.join(REPO_ROOT, nested))));
    else files.set(toPosix(nested), '<unsupported>');
  }
}

async function snapshotCheckout() {
  const tracked = (await git(['ls-files', '-z'], 'git ls-files')).split('\0').filter((file) => file.length > 0);
  const files = new Map();

  for (const file of tracked) {
    const absolute = path.join(REPO_ROOT, file);

    files.set(toPosix(file), existsSync(absolute) ? sha256(readFileSync(absolute)) : '<missing>');
  }

  for (const file of ['package.json', 'scripts/phase11/types-compatibility.mjs', 'tests/types/phase11-commonjs/fixtures.mjs']) {
    const absolute = path.join(REPO_ROOT, file);

    if (existsSync(absolute)) files.set(toPosix(file), sha256(readFileSync(absolute)));
  }

  walkCheckoutDirectory('dist', files);

  for (const relative of LINKED_MANIFESTS) {
    const absolute = path.join(REPO_ROOT, relative);

    files.set(`link:${relative}`, existsSync(absolute) ? sha256(readFileSync(absolute)) : '<missing>');
  }

  const status = await git(['status', '--porcelain'], 'git status');
  const head = (await git(['rev-parse', 'HEAD'], 'git rev-parse')).trim();

  return { files, status, head, count: files.size };
}

function compareSnapshots(before, after) {
  const failures = [];

  if (before.status !== after.status) failures.push('checkout git status changed during the run');

  if (before.head !== after.head) failures.push('checkout HEAD changed during the run');

  const keys = new Set([...before.files.keys(), ...after.files.keys()]);

  for (const key of [...keys].sort()) {
    if (before.files.get(key) !== after.files.get(key)) failures.push(`checkout file changed during the run: ${key}`);
  }

  return { checkedFiles: keys.size, failures, head: after.head, gitStatus: after.status };
}

/* -------------------------------------------------------------------------- */
/* report and results                                                         */
/* -------------------------------------------------------------------------- */

function artifactReport(artifact) {
  return {
    tarball: artifact.tarballPath,
    basename: path.basename(artifact.tarballPath),
    sha256: artifact.sha256,
    compressedBytes: artifact.compressedBytes,
    unpackedBytes: artifact.unpackedBytes,
    fileCount: artifact.fileCount,
    package: { name: artifact.manifest.name, version: artifact.manifest.version },
    entries: PUBLIC_ENTRIES.map((entry) => entry.subpath),
  };
}

function summarizeCases(caseResults) {
  const summary = {
    cases: caseResults.length,
    positives: 0,
    negatives: 0,
    docs: 0,
    passed: 0,
    failed: 0,
    infrastructure: 0,
  };

  for (const result of caseResults) {
    if (result.kind === 'positive') summary.positives += 1;
    else summary.negatives += 1;

    if (result.isDocs) summary.docs += 1;

    if (result.status === 'pass') summary.passed += 1;
    else if (result.status === 'infrastructure') summary.infrastructure += 1;
    else summary.failed += 1;
  }

  return summary;
}

function buildReport(context) {
  const summary = summarizeCases(context.caseResults);
  const detectedControls = context.controls.filter((control) => control.detected).length;
  const graphProblems = [...context.graph.problems, ...context.graph.runtime.problems];
  const integrityFailures = [...context.integrity.failures];

  const ready = summary.failed === 0
    && summary.infrastructure === 0
    && detectedControls === context.controls.length
    && graphProblems.length === 0
    && integrityFailures.length === 0
    && context.cleanup.removed;

  return {
    schemaVersion: RESULT_SCHEMA,
    phase: 11,
    gate: 'packed-commonjs-esm-public-declarations',
    status: ready ? 'ready' : 'failed',
    mode: context.mode,
    startedAt: context.startedAt,
    finishedAt: new Date().toISOString(),
    toolchain: context.toolchain,
    peers: context.peers,
    artifact: artifactReport(context.artifact),
    environments: context.environments.map((environment) => ({
      id: environment.definition.id,
      module: environment.definition.module,
      distribution: environment.definition.distribution,
      formats: [...environment.definition.formats],
      libs: [...environment.definition.libs],
      types: [...environment.definition.types],
      links: environment.definition.links.map((link) => ({ ...link })),
      installedFiles: context.artifact.fileCount,
      visibleNodeModules: environment.visible,
      description: environment.definition.description,
    })),
    cases: context.caseResults,
    controls: context.controls,
    graph: {
      facades: context.graph.facades,
      facadeLeaves: context.graph.facadeLeaves,
      reachableDeclarations: context.graph.reachableDeclarations,
      declarationCount: context.graph.declarationCount,
      edgeCount: context.graph.edges.length,
      classPaths: context.graph.classPaths,
      runtime: {
        files: context.graph.runtime.files,
        edges: context.graph.runtime.edges,
      },
      problems: graphProblems,
    },
    integrity: {
      checkedFiles: context.integrity.checkedFiles,
      failures: integrityFailures,
      head: context.integrity.head,
      cleanup: context.cleanup,
    },
    summary: {
      ...summary,
      controls: context.controls.length,
      controlsDetected: detectedControls,
      graphProblems: graphProblems.length,
      integrityFailures: integrityFailures.length,
      tempRemoved: context.cleanup.removed,
      ready,
    },
    limitations: [...LIMITATIONS],
  };
}

function buildFailureReport(context) {
  return {
    schemaVersion: RESULT_SCHEMA,
    phase: 11,
    gate: 'packed-commonjs-esm-public-declarations',
    status: 'failed',
    mode: context.mode,
    startedAt: context.startedAt,
    finishedAt: new Date().toISOString(),
    toolchain: context.toolchain,
    artifact: context.artifact === null ? null : artifactReport(context.artifact),
    error: {
      name: context.error instanceof Error ? context.error.name : 'Error',
      message: bounded(context.error instanceof Error ? context.error.message : context.error),
    },
    summary: { ready: false },
    limitations: [...LIMITATIONS],
  };
}

function writeResults(file, report) {
  if (existsSync(file)) throw new GateError(`refusing to overwrite existing results: ${relPosix(REPO_ROOT, file)}`);

  const text = `${JSON.stringify(report, null, 2)}\n`;

  try {
    writeFileSync(file, text, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    throw new GateError(`cannot write results: ${bounded(error instanceof Error ? error.message : error)}`);
  }
}

function printSummary(report) {
  const summary = report.summary ?? {};
  const status = String(report.status).toUpperCase();

  console.log(`[phase11] ${status} mode=${String(report.mode)} TypeScript=${String(report.toolchain?.typescript)} Node=${String(report.toolchain?.node)}`);

  if (report.artifact !== null && report.artifact !== undefined) {
    console.log(`[phase11] artifact ${report.artifact.basename} sha256=${report.artifact.sha256} files=${report.artifact.fileCount}`);
  }

  if (report.error !== undefined) console.log(`[phase11] error: ${report.error.message}`);

  for (const result of report.cases ?? []) {
    if (result.status === 'pass') continue;

    console.log(`[phase11] ${result.status.toUpperCase()} ${result.id} (${result.failureKind ?? 'unknown'})`);

    for (const failure of result.failures.slice(0, 4)) console.log(`  - ${failure}`);
  }

  for (const control of report.controls ?? []) {
    if (control.detected) continue;

    console.log(`[phase11] CONTROL NOT DETECTED ${control.id}: expected ${control.expected}, got ${control.actualStatus}/${String(control.actualFailureKind)}`);
  }

  for (const problem of report.graph?.problems ?? []) console.log(`[phase11] GRAPH ${problem}`);

  for (const failure of report.integrity?.failures ?? []) console.log(`[phase11] INTEGRITY ${failure}`);

  if (report.integrity?.cleanup !== undefined && !report.integrity.cleanup.removed) {
    console.log(`[phase11] CLEANUP retained temp root: ${String(report.integrity.cleanup.path)} (${String(report.integrity.cleanup.reason)})`);
  }

  if (summary.cases !== undefined) {
    console.log(
      `[phase11] cases=${summary.cases} positives=${summary.positives} negatives=${summary.negatives} `
      + `passed=${summary.passed} failed=${summary.failed} infrastructure=${summary.infrastructure} `
      + `controls=${summary.controls}/${summary.controlsDetected} graphProblems=${summary.graphProblems} `
      + `integrityFailures=${summary.integrityFailures} tempRemoved=${String(summary.tempRemoved)}`,
    );
  }

  console.log(`[phase11] ${status === 'READY' ? 'READY' : 'NOT READY'} exit=${String(report.status === 'ready' ? EXIT.READY : EXIT.FAIL)}`);
}

/* -------------------------------------------------------------------------- */
/* execution                                                                  */
/* -------------------------------------------------------------------------- */

function buildDocsCases() {
  const cases = [];

  for (const [id, sample] of Object.entries(DOC_SAMPLES)) {
    cases.push({
      id: `${DOC_ENVIRONMENT}/${sample.extension.slice(1)}/${id}`,
      familyId: id,
      kind: 'positive',
      description: `Frozen documentation sample ${id}, compiled verbatim.`,
      environment: DOC_ENVIRONMENT,
      format: sample.extension,
      fileName: `doc-${id}${sample.extension}`,
      allowUnresolved: false,
      source: sample.code,
      isDocs: true,
    });
  }

  return cases;
}

function groupCases(cases) {
  const grouped = new Map();

  for (const caseDefinition of cases) {
    const group = grouped.get(caseDefinition.environment);

    if (group === undefined) grouped.set(caseDefinition.environment, [caseDefinition]);
    else group.push(caseDefinition);
  }

  return grouped;
}

async function runMatrix(artifact, tempRoot, toolchain, peers) {
  const environments = [];
  const installed = new Map();

  for (const definition of Object.values(ENVIRONMENTS)) {
    const environment = await installEnvironment(artifact, definition, tempRoot, toolchain);

    environments.push(environment);
    installed.set(definition.id, environment);
  }

  const docsCases = buildDocsCases();
  const allCases = [...CASES, ...docsCases];
  const grouped = groupCases(allCases);
  const caseResults = [];
  const compiledByEnvironment = new Map();

  for (const definition of Object.values(ENVIRONMENTS)) {
    const environment = installed.get(definition.id);
    const caseDefinitions = grouped.get(definition.id);

    if (environment === undefined || caseDefinitions === undefined || caseDefinitions.length === 0) {
      throw new GateError(`environment ${definition.id} has no compiled consumer cases`);
    }

    for (const caseDefinition of caseDefinitions) {
      writeFileSync(path.join(environment.envDir, caseDefinition.fileName), caseDefinition.source, 'utf8');
    }

    // Ordinary peer cases must NEVER share a program with another format or
    // an intentional mixed-format case: ambient augmentation would mask gaps.
    const batches = definition.id.endsWith('-express') || definition.id.endsWith('-hono')
      ? caseDefinitions.map((caseDefinition) => [caseDefinition])
      : [caseDefinitions];

    const compiled = { diagnostics: [], probes: [] };

    for (const batch of batches) {
      const result = await compileEnvironment(environment, batch);

      compiled.diagnostics.push(...result.diagnostics);
      compiled.probes.push(...result.probes);
    }


    compiledByEnvironment.set(definition.id, compiled);
    console.log(`[phase11] compiled ${definition.id}: ${caseDefinitions.length} cases, ${compiled.diagnostics.length} diagnostics`);
  }

  for (const definition of Object.values(ENVIRONMENTS)) {
    const compiled = compiledByEnvironment.get(definition.id);
    const caseDefinitions = grouped.get(definition.id);

    if (compiled === undefined || caseDefinitions === undefined) continue;

    const caseFileNames = caseDefinitions.map((caseDefinition) => caseDefinition.fileName);

    for (const caseDefinition of caseDefinitions) {
      caseResults.push(evaluateCase(caseDefinition, compiled.diagnostics, compiled.probes, caseFileNames));
    }
  }

  const base = installed.get('nodenext-core');

  if (base === undefined) throw new GateError('nodenext-core environment was not installed');

  const graph = walkDeclarationGraph(base.installedRoot);
  graph.runtime = walkRuntimeGraph(base.installedRoot);

  const controls = await runControls(base, tempRoot);

  return {
    environments,
    caseResults,
    controls,
    graph,
    peers,
    artifact,
  };
}

async function executeRun(options, toolchain, peers, resultsPath) {
  const startedAt = new Date().toISOString();
  const mode = options.tarball === undefined ? 'checkout-pack' : 'candidate-tarball';
  let tempRoot = null;
  let snapshot = null;
  let artifact = null;
  let report;
  let exitCode = EXIT.FAIL;
  let cleanup = { removed: false, path: null };

  try {
    tempRoot = createTempRoot();
    snapshot = await snapshotCheckout();
    artifact = options.tarball === undefined
      ? await packCheckout(tempRoot, toolchain)
      : inspectTarball(path.resolve(process.cwd(), options.tarball));

    validateArtifact(artifact);
    console.log(`[phase11] artifact ${artifact.tarballPath} sha256=${artifact.sha256} files=${artifact.fileCount}`);

    const matrix = await runMatrix(artifact, tempRoot, toolchain, peers);
    const after = await snapshotCheckout();
    const integrity = compareSnapshots(snapshot, after);
    const cleanupResult = cleanupTempRoot(tempRoot);

    cleanup = cleanupResult;

    report = buildReport({
      mode,
      startedAt,
      toolchain,
      peers,
      artifact,
      environments: matrix.environments,
      caseResults: matrix.caseResults,
      controls: matrix.controls,
      graph: matrix.graph,
      integrity,
      cleanup,
    });
    exitCode = report.status === 'ready' ? EXIT.READY : EXIT.FAIL;
    tempRoot = null;
  } catch (error) {
    const cleanupResult = cleanupTempRoot(tempRoot);

    cleanup = cleanupResult;

    report = buildFailureReport({
      mode,
      startedAt,
      toolchain,
      error,
      artifact,
    });
    report.integrity = {
      checkedFiles: 0,
      failures: [],
      head: snapshot?.head ?? null,
      cleanup,
    };
    report.summary = { ready: false, tempRemoved: cleanup.removed };
    exitCode = error instanceof BlockedError ? EXIT.BLOCKED : EXIT.FAIL;
    tempRoot = null;
  }

  if (resultsPath !== undefined) {
    try {
      writeResults(resultsPath, report);
      console.log(`[phase11] results ${relPosix(REPO_ROOT, resultsPath)}`);
    } catch (error) {
      console.error(`[phase11] results failure: ${bounded(error instanceof Error ? error.message : error)}`);
      exitCode = EXIT.FAIL;
    }
  }

  printSummary(report);

  return exitCode;
}

/* -------------------------------------------------------------------------- */
/* self-test                                                                  */
/* -------------------------------------------------------------------------- */

function runSelfTest() {
  const checks = [];

  const check = (id, callback) => {
    try {
      const detail = callback();

      checks.push({ id, pass: true, detail: detail === undefined ? null : detail });
    } catch (error) {
      checks.push({ id, pass: false, detail: bounded(error instanceof Error ? error.message : error) });
    }
  };

  check('markers/multiple', () => {
    const markers = parseMarkers('a // @expect-error TS2322\nb // @expect-error TS2345\n');

    assertCondition(markers.length === 2, 'expected two markers');
    assertCondition(markers[0].code === 2322 && markers[0].line === 1, 'first marker mismatch');
    assertCondition(markers[1].code === 2345 && markers[1].line === 2, 'second marker mismatch');
  });

  check('classifier/positive-clean', () => {
    const result = classifyCase(
      { kind: 'positive', fileName: 'positive.mts' },
      [],
      'const value = 1;\n',
    );

    assertCondition(result.status === 'pass', 'clean positive must pass');
  });

  check('classifier/positive-diagnostic', () => {
    const result = classifyCase(
      { kind: 'positive', fileName: 'positive.mts' },
      [{ code: 2322, file: 'positive.mts', line: 1, character: 1, message: 'x' }],
      'const value = 1;\n',
    );

    assertCondition(result.status === 'fail' && result.failureKind === 'unexpected-diagnostics', 'diagnostic positive must fail');
  });

  check('classifier/negative-exact', () => {
    const result = classifyCase(
      { kind: 'negative', fileName: 'negative.cts' },
      [{ code: 2322, file: 'negative.cts', line: 1, character: 7, message: 'x' }],
      'const value: 1 = 2; // @expect-error TS2322\n',
    );

    assertCondition(result.status === 'pass', `exact marker must pass: ${result.failures.join('; ')}`);
  });

  check('classifier/negative-wrong-line', () => {
    const result = classifyCase(
      { kind: 'negative', fileName: 'negative.cts' },
      [{ code: 2322, file: 'negative.cts', line: 2, character: 7, message: 'x' }],
      'const value: 1 = 2; // @expect-error TS2322\n',
    );

    assertCondition(result.status === 'fail' && result.failureKind === 'mismatch', 'wrong line must be a mismatch');
  });

  check('classifier/negative-silent-success', () => {
    const result = classifyCase(
      { kind: 'negative', fileName: 'negative.cts' },
      [],
      'const value: 1 = 2; // @expect-error TS2322\n',
    );

    assertCondition(result.status === 'fail' && result.failureKind === 'silent-success', 'missing diagnostics must be silent-success');
  });

  check('classifier/negative-outside', () => {
    const result = classifyCase(
      { kind: 'negative', fileName: 'negative.cts' },
      [
        { code: 2322, file: 'negative.cts', line: 1, character: 7, message: 'x' },
        { code: 2459, file: 'node_modules/hooklatch/dist/cjs/index.d.cts', line: 1, character: 1, message: 'y' },
      ],
      'const value: 1 = 2; // @expect-error TS2322\n',
    );

    assertCondition(result.status === 'fail' && result.failureKind === 'mismatch', 'outside diagnostics must fail');
  });

  check('classifier/negative-extra', () => {
    const result = classifyCase(
      { kind: 'negative', fileName: 'negative.cts' },
      [
        { code: 2322, file: 'negative.cts', line: 1, character: 7, message: 'x' },
        { code: 2345, file: 'negative.cts', line: 1, character: 9, message: 'y' },
      ],
      'const value: 1 = 2; // @expect-error TS2322\n',
    );

    assertCondition(result.status === 'fail' && result.failureKind === 'mismatch', 'extra diagnostics must fail');
  });

  check('inventories', () => {
    assertCondition(PUBLIC_ENTRIES.length === 6, 'six public entries');
    assertCondition(new Set(PUBLIC_ENTRIES.map((entry) => entry.subpath)).size === 6, 'unique public subpaths');
    assertCondition(PROVIDER_IDS.length === 21, `21 provider ids, found ${PROVIDER_IDS.length}`);
    assertCondition(new Set(PROVIDER_IDS).size === PROVIDER_IDS.length, 'unique provider ids');
    assertCondition(FAILURE_REASONS.length === 9, `9 failure reasons, found ${FAILURE_REASONS.length}`);
    assertCondition(ERROR_CODES.length === 9, `9 setup error codes, found ${ERROR_CODES.length}`);
    assertCondition(DIAGNOSTIC_CODES.length === 18, `18 diagnostic codes, found ${DIAGNOSTIC_CODES.length}`);
    assertCondition(CASES.some((entry) => entry.familyId === 'positive-inventories'), 'inventory fixture exists');
  });

  check('exports/expected-map', () => {
    const problems = checkExportMap(EXPECTED_EXPORT_MAP);

    assertCondition(problems.length === 0, problems.join('; '));
  });

  check('exports/order', () => {
    const root = EXPECTED_EXPORT_MAP['.'];

    const reordered = Object.fromEntries(Object.keys(EXPECTED_EXPORT_MAP).map((key) => [
      key,
      key === '.'
        ? { types: root.types, import: root.import, default: root.default, node: root.node }
        : EXPECTED_EXPORT_MAP[key],
    ]));

    const problems = checkExportMap(reordered);

    assertCondition(problems.length > 0, 'reordered export keys must be rejected');
  });

  check('exports/missing-entry', () => {
    const clone = JSON.parse(JSON.stringify(EXPECTED_EXPORT_MAP));

    delete clone['./hono'];

    const problems = checkExportMap(clone);

    assertCondition(problems.length > 0, 'missing export subpath must be rejected');
  });

  check('resolution/node-mts', () => {
    const actual = expectedDeclaration('nodenext-core', '.mts', 'index');

    assertCondition(actual === 'dist/node/index.d.ts', `unexpected ${actual}`);
  });

  check('resolution/node-cts', () => {
    const actual = expectedDeclaration('nodenext-core', '.cts', 'index');

    assertCondition(actual === 'dist/cjs/index.d.cts', `unexpected ${actual}`);
  });

  check('resolution/bundler', () => {
    const actual = expectedDeclaration('bundler-worker', '.ts', 'index');

    assertCondition(actual === 'dist/index.d.ts', `unexpected ${actual}`);
  });

  check('temp-guard/valid', () => {
    const root = mkdtempSync(path.join(realpathSync(tmpdir()), TEMP_PREFIX));

    try {
      assertCondition(assertInsideTempRoot(root) === realpathSync(root), 'guard accepts its own temp root');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  check('temp-guard/outside', () => {
    let rejected = false;

    try {
      assertInsideTempRoot(REPO_ROOT);
    } catch {
      rejected = true;
    }

    assertCondition(rejected, 'checkout root must be rejected');
  });

  check('temp-guard/prefix', () => {
    let rejected = false;

    try {
      assertInsideTempRoot(path.join(tmpdir(), 'not-hooklatch-phase11'));
    } catch {
      rejected = true;
    }

    assertCondition(rejected, 'wrong prefix must be rejected');
  });

  check('results-guard/existing', () => {
    let rejected = false;

    try {
      validateResultsPath('package.json');
    } catch {
      rejected = true;
    }

    assertCondition(rejected, 'existing file must be rejected');
  });

  check('results-guard/git', () => {
    let rejected = false;

    try {
      validateResultsPath('.git/phase11-self-test.json');
    } catch {
      rejected = true;
    }

    assertCondition(rejected, '.git target must be rejected');
  });

  check('results-guard/outside', () => {
    let rejected = false;

    try {
      validateResultsPath(path.join(tmpdir(), 'phase11-self-test.json'));
    } catch {
      rejected = true;
    }

    assertCondition(rejected, 'outside checkout must be rejected');
  });

  check('results-guard/valid', () => {
    const resolved = validateResultsPath('tests/types/phase11-commonjs/self-test-not-written.json');

    assertCondition(resolved.endsWith('self-test-not-written.json'), 'valid results path');
  });

  check('tar-path/safe', () => {
    assertCondition(normalizeTarPath('package/dist/index.js') === 'package/dist/index.js', 'safe tar path');

    let rejected = false;

    try {
      normalizeTarPath('../evil');
    } catch {
      rejected = true;
    }

    assertCondition(rejected, 'unsafe tar path must be rejected');
  });

  check('graph-specifier', () => {
    assertCondition(
      mapDeclarationTarget('dist/node/index.d.ts', '../cjs/index.cjs') === 'dist/cjs/index.d.cts',
      'facade edge mapping',
    );
    assertCondition(
      mapDeclarationTarget('dist/cjs/core.d.cts', './types.cjs') === 'dist/cjs/types.d.cts',
      'cjs edge mapping',
    );
  });

  check('docs-samples', () => {
    const entries = Object.entries(DOC_SAMPLES);

    assertCondition(entries.length === 4, 'four documentation samples');
    assertCondition(entries.some(([id]) => id === 'esm-javascript'), 'esm javascript sample');
    assertCondition(entries.some(([id]) => id === 'cjs-typescript'), 'cjs typescript sample');
  });

  check('package-policy', () => {
    const manifest = {
      name: PACKAGE_POLICY.name,
      type: PACKAGE_POLICY.type,
      main: PACKAGE_POLICY.main,
      types: PACKAGE_POLICY.types,
      bin: { hooklatch: PACKAGE_POLICY.bin.hooklatch },
      engines: { node: PACKAGE_POLICY.engines.node },
      peerDependencies: {
        express: PACKAGE_POLICY.peerDependencies.express,
        hono: PACKAGE_POLICY.peerDependencies.hono,
      },
      exports: EXPECTED_EXPORT_MAP,
    };

    const problems = checkManifestPolicy(manifest);

    assertCondition(problems.length === 0, problems.join('; '));
  });

  const failed = checks.filter((entry) => !entry.pass);

  for (const entry of checks) {
    console.log(`[phase11] self-test ${entry.pass ? 'PASS' : 'FAIL'} ${entry.id}${entry.detail === null ? '' : `: ${String(entry.detail)}`}`);
  }

  console.log(`[phase11] self-test ${checks.length - failed.length}/${checks.length} passed`);

  return failed.length === 0 ? EXIT.READY : EXIT.FAIL;
}

/* -------------------------------------------------------------------------- */
/* worker                                                                     */
/* -------------------------------------------------------------------------- */

async function runCompilerWorker() {
  const ts = loadTypeScript();
  const options = compilerOptions(ts, workerData.definition, workerData.envDir);
  const rootNames = workerData.fileNames.map((fileName) => path.join(workerData.envDir, fileName));
  const program = ts.createProgram({ rootNames, options });

  const diagnostics = ts.getPreEmitDiagnostics(program)
    .map((diagnostic) => normalizeDiagnostic(ts, diagnostic, workerData.envDir));

  const installedPath = path.join(workerData.envDir, 'node_modules', 'hooklatch');
  const installedRoot = existsSync(installedPath) ? realpathSync(installedPath) : null;
  const probes = [];

  for (const probe of workerData.probes) {
    const containingFile = path.join(workerData.envDir, probe.fileName);
    const mode = probe.dynamic ? ts.ModuleKind.ESNext : resolutionModeForFile(ts, probe.fileName);

    const resolved = ts.resolveModuleName(
      probe.specifier, containingFile, options, ts.sys, undefined, undefined, mode,
    ).resolvedModule;

    let actual = null;
    let outside = false;

    if (resolved !== undefined) {
      if (installedRoot === null) {
        outside = true;
      } else {
        let resolvedFile = resolved.resolvedFileName;

        try {
          resolvedFile = realpathSync(resolvedFile);
        } catch {
          resolvedFile = path.resolve(resolvedFile);
        }

        if (isInside(installedRoot, resolvedFile)) actual = relPosix(installedRoot, resolvedFile);
        else outside = true;
      }
    }

    probes.push({ ...probe, actual, outside });
  }

  parentPort.postMessage({ ok: true, result: { diagnostics, probes } });
}

if (!isMainThread) {
  runCompilerWorker().catch((error) => {
    parentPort.postMessage({ ok: false, message: bounded(error instanceof Error ? error.message : error) });
  });
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

async function main() {
  let options;

  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`[phase11] ${bounded(error instanceof Error ? error.message : error)}`);
    console.error(USAGE);

    return EXIT.USAGE;
  }

  if (options.help) {
    console.log(USAGE);

    return EXIT.READY;
  }

  if (options.selfTest) return runSelfTest();

  try {
    const resultsPath = options.results === undefined ? undefined : validateResultsPath(options.results);
    const toolchain = readToolchain();

    if (options.tarball !== undefined) {
      const tarballPath = path.resolve(process.cwd(), options.tarball);

      if (!existsSync(tarballPath) || !statSync(tarballPath).isFile()) {
        throw new BlockedError(`explicit tarball does not exist: ${tarballPath}`);
      }
    } else {
      assertProductionReady();
    }

    const peers = readPeerToolchain();

    return await executeRun(options, toolchain, peers, resultsPath);
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`[phase11] ${bounded(error.message)}`);

      return EXIT.USAGE;
    }

    if (error instanceof BlockedError) {
      console.error(`[phase11] BLOCKED: ${bounded(error.message)}`);

      return EXIT.BLOCKED;
    }

    console.error(`[phase11] FAILED: ${bounded(error instanceof Error ? error.message : error)}`);

    return EXIT.FAIL;
  }
}

if (isMainThread) {
  const exitCode = await main();

  process.exitCode = exitCode;
}
