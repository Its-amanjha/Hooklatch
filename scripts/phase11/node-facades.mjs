/**
 * Phase 11 Node ESM facades and export inventory.
 *
 * For each of the six frozen public entries this module generates:
 *
 *   dist/node/<base>.js     an ESM facade that imports the canonical CommonJS
 *                           exports object and re-exports the identical named
 *                           function/class REFERENCES (identity, not shape).
 *   dist/node/<base>.d.ts   a declaration facade that re-exports every
 *                           declaration from the corresponding `.cjs` specifier,
 *                           which NodeNext resolves to the canonical `.d.cts`.
 *
 * The frozen export policy in tasks/phase-11/exports-policy.json is the single
 * source of truth for subpaths, entry modules, runtime export names and the
 * conditional export targets this output must satisfy. Nothing here edits
 * package.json; the coordinator installs the same policy.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { BuildFailure, PrerequisiteError, relativeFiles, sameStrings } from './node-emit.mjs';

export const POLICY_RELATIVE_PATH = 'tasks/phase-11/exports-policy.json';

/** The exact conditional export object each public entry must have. */
export function expectedEntryTargets(base) {
  return {
    node: {
      import: { types: `./dist/node/${base}.d.ts`, default: `./dist/node/${base}.js` },
      require: { types: `./dist/cjs/${base}.d.cts`, default: `./dist/cjs/${base}.cjs` },
    },
    topLevel: { types: `./dist/${base}.d.ts`, import: `./dist/${base}.js`, default: `./dist/${base}.js` },
  };
}

function fail(reason) {
  throw new BuildFailure(`Export policy: ${reason}`);
}

const OBJECT_TAG = '[object Object]';
const STRING_TAG = '[object String]';
const EXPORT_NAME = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * Decode the policy's JSON shape without `typeof` narrowing: JSON.parse already
 * produced domain values, so the boundary check inspects their object tags.
 */
function isPlainObject(value) {
  return value !== null && Object.prototype.toString.call(value) === OBJECT_TAG;
}

function isNonEmptyString(value) {
  return Object.prototype.toString.call(value) === STRING_TAG && value.length > 0;
}

function assertKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);

  const keys = Object.keys(value);

  if (!sameStrings(keys, expected)) fail(`${label} condition order must be [${expected.join(', ')}], found [${keys.join(', ')}]`);
}

function assertTarget(value, expected, label) {
  if (value !== expected) fail(`${label} must be ${expected}, found ${String(value)}`);
}

function validatePolicyEntry(policy, entry) {
  if (!Array.isArray(entry) || entry.length !== 3) fail('every public entry must be [subpath, base, runtimeExports]');

  const [subpath, base, runtimeExports] = entry;

  if (!isNonEmptyString(subpath) || !isNonEmptyString(base)) fail('every public entry needs string subpath and base');

  if (!Array.isArray(runtimeExports) || runtimeExports.length === 0) fail(`${subpath} must list its runtime exports`);

  if (!runtimeExports.every((name) => isNonEmptyString(name) && EXPORT_NAME.test(name))) fail(`${subpath} has an invalid runtime export name`);

  const mapping = policy.exports[subpath];

  if (mapping === undefined) fail(`exports has no ${subpath}`);

  const targets = expectedEntryTargets(base);

  assertKeys(mapping, ['node', 'types', 'import', 'default'], `exports[${subpath}]`);
  assertKeys(mapping.node, ['import', 'require'], `exports[${subpath}].node`);
  assertKeys(mapping.node.import, ['types', 'default'], `exports[${subpath}].node.import`);
  assertKeys(mapping.node.require, ['types', 'default'], `exports[${subpath}].node.require`);

  assertTarget(mapping.node.import.types, targets.node.import.types, `exports[${subpath}].node.import.types`);
  assertTarget(mapping.node.import.default, targets.node.import.default, `exports[${subpath}].node.import.default`);
  assertTarget(mapping.node.require.types, targets.node.require.types, `exports[${subpath}].node.require.types`);
  assertTarget(mapping.node.require.default, targets.node.require.default, `exports[${subpath}].node.require.default`);
  assertTarget(mapping.types, targets.topLevel.types, `exports[${subpath}].types`);
  assertTarget(mapping.import, targets.topLevel.import, `exports[${subpath}].import`);
  assertTarget(mapping.default, targets.topLevel.default, `exports[${subpath}].default`);

  return { subpath, base, runtimeExports: [...runtimeExports] };
}

/**
 * Validate the frozen policy against the frozen architecture, then return the
 * entries this builder must generate. A policy that would not resolve to the
 * generated output is a build failure, not a warning.
 */
export function validateExportPolicy(policy) {
  if (!isPlainObject(policy)) fail('policy must be an object');

  if (policy.version !== 1) fail(`unsupported policy version ${String(policy.version)}`);

  assertTarget(policy.type, 'module', 'type');
  assertTarget(policy.engines?.node, '>=22', 'engines.node');
  assertTarget(policy.main, './dist/cjs/index.cjs', 'main');
  assertTarget(policy.types, './dist/index.d.ts', 'types');
  assertTarget(policy.bin?.hooklatch, './dist/cli/index.js', 'bin.hooklatch');

  if (!Array.isArray(policy.publicEntries) || policy.publicEntries.length !== 6) fail('exactly six public entries are required');

  const entries = policy.publicEntries.map((entry) => validatePolicyEntry(policy, entry));
  const subpaths = entries.map((entry) => entry.subpath);
  const bases = entries.map((entry) => entry.base);

  if (new Set(subpaths).size !== subpaths.length) fail('public subpaths must be unique');

  if (new Set(bases).size !== bases.length) fail('entry modules must be unique');

  if (!sameStrings(Object.keys(policy.exports).sort(), [...subpaths].sort())) fail('exports must contain exactly the six public subpaths');

  for (const key of Object.keys(policy.exports)) {
    const conditions = policy.exports[key];

    if (isPlainObject(conditions) && Object.hasOwn(conditions, 'module-sync')) fail(`exports[${key}] must not declare module-sync`);
  }

  return entries;
}

export function loadExportPolicy(repoRoot) {
  const policyPath = path.join(repoRoot, POLICY_RELATIVE_PATH);

  if (!existsSync(policyPath)) throw new PrerequisiteError(`Frozen export policy missing: ${POLICY_RELATIVE_PATH}`);

  let policy;

  try {
    policy = JSON.parse(readFileSync(policyPath, 'utf8'));
  } catch (error) {
    throw new BuildFailure(`Export policy is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { policyPath, policy, entries: validateExportPolicy(policy) };
}

/* ------------------------------------------------------------------ *
 * Facade sources
 * ------------------------------------------------------------------ */

/** Relative specifier from dist/node/<base>.js to dist/cjs/<base>.cjs. */
export function facadeCommonJsSpecifier(base) {
  const depth = base.split('/').length - 1;

  return `${'../'.repeat(depth + 1)}cjs/${base}.cjs`;
}

export function facadeRuntimeSource(entry) {
  const lines = [
    '/** Phase 11 Node ESM facade: re-exports the canonical CommonJS graph by identity. */',
    `import commonjs from '${facadeCommonJsSpecifier(entry.base)}';`,
    '',
  ];

  for (const name of entry.runtimeExports) lines.push(`export const ${name} = commonjs.${name};`);

  return `${lines.join('\n')}\n`;
}

export function facadeDeclarationSource(entry) {
  const lines = [
    '/** Phase 11 Node ESM declaration facade: resolves to the canonical .d.cts graph. */',
    `export * from '${facadeCommonJsSpecifier(entry.base)}';`,
  ];

  return `${lines.join('\n')}\n`;
}

export function expectedFacadeFiles(entries) {
  const files = [];

  for (const entry of entries) files.push(`${entry.base}.js`, `${entry.base}.d.ts`);

  return files.sort();
}

/** Replace dist/node with exactly six .js facades and six .d.ts facades. */
export function writeFacadeFiles(nodeRoot, entries) {
  rmSync(nodeRoot, { recursive: true, force: true });

  for (const entry of entries) {
    const runtimePath = path.join(nodeRoot, `${entry.base}.js`);
    const declarationPath = path.join(nodeRoot, `${entry.base}.d.ts`);

    mkdirSync(path.dirname(runtimePath), { recursive: true });
    writeFileSync(runtimePath, facadeRuntimeSource(entry));
    writeFileSync(declarationPath, facadeDeclarationSource(entry));
  }

  return relativeFiles(nodeRoot);
}

export function inspectFacadeFiles(nodeRoot, entries) {
  if (!existsSync(nodeRoot)) return { ok: false, present: false, files: [], missing: expectedFacadeFiles(entries), unexpected: [] };

  const files = relativeFiles(nodeRoot);
  const expected = expectedFacadeFiles(entries);
  const missing = expected.filter((file) => !files.includes(file));
  const unexpected = files.filter((file) => !expected.includes(file));
  const runtime = files.filter((file) => file.endsWith('.js')).length;
  const declarations = files.filter((file) => file.endsWith('.d.ts')).length;

  return {
    ok: missing.length === 0 && unexpected.length === 0 && runtime === entries.length && declarations === entries.length,
    present: true,
    files,
    runtime,
    declarations,
    missing,
    unexpected,
  };
}

/**
 * The generated facade must export exactly the frozen runtime names, each bound
 * to the CommonJS export of the same name.
 */
export function compareRuntimeExports(entry, actualNames) {
  const expected = [...entry.runtimeExports].sort();
  const actual = [...actualNames].sort();

  return {
    ok: sameStrings(expected, actual),
    expected,
    actual,
    missing: expected.filter((name) => !actual.includes(name)),
    extra: actual.filter((name) => !expected.includes(name)),
  };
}
