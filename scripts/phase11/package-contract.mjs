#!/usr/bin/env node
/**
 * Phase11 installed-tarball contract gate (offline).
 *
 * Qualifies ONE explicit candidate tarball (`--tarball FILE`) or, in default
 * mode, the ACTUAL built checkout (packed with `npm pack`) against the frozen
 * Phase11 conditional-exports policy. The coordinator seed candidate is
 * design evidence only; qualifying it is never product support.
 *
 * The frozen specification is EMBEDDED below as clearly named literals
 * (`POLICY_PUBLIC_ENTRIES`, `POLICY_PROVIDERS`, `POLICY_MANIFEST_FIELDS`,
 * `EXPECTED_NESTED_EXPORTS`) and cross-checked three ways:
 *  - the pinned nested export literal is re-derived from the six entries and
 *    compared (non-tautological internal consistency);
 *  - the candidate manifest is compared against the pinned literal (exact
 *    structure including condition key order) and re-checked granularly;
 *  - the candidate provider registry and manifest export keys are compared
 *    against the policy in both directions (no silent additions/omissions).
 *
 * Static checks (no installation):
 *  - tarball listing shape (package/ prefix, no traversal/absolute/backslash)
 *    AND member TYPES: `tar -tvf` is paired index-wise with `tar -tf` and any
 *    symlink, hardlink, device or fifo member is rejected BEFORE extraction,
 *    as are duplicate member names. Extraction is aborted when any member
 *    shape/type finding exists, so a rejected archive is never written to
 *    disk by this gate (npm is never handed it either);
 *  - forbidden member paths: src/, tests/, notes/, tasks/, node_modules/,
 *    .git/ top segments plus "credentials"/"source-temp" substrings anywhere;
 *  - manifest fields: type module, engines >=22 (exact policy value), main
 *    canonical CJS, root types, bin, zero runtime dependencies (nonempty
 *    `dependencies`, `optionalDependencies` or `bundledDependencies` are all
 *    rejected), optional peers exactly unchanged;
 *  - every referenced target (six entries x seven targets, main, types, bin)
 *    exists as a tarball member;
 *  - original ESM/CLI baseline pin (SEPARATE check): every tarball member
 *    under dist/ except the additive dist/cjs/** and dist/node/** trees must
 *    byte-match (SHA-256 of extracted content) the host checkout's own
 *    freshly built dist/, and every checkout dist file outside those additive
 *    trees must appear in the tarball. A missing checkout dist is BLOCKED
 *    before temp allocation;
 *  - every dist/cjs (*.cjs) file may contain only relative `.cjs`
 *    specifiers that resolve inside dist/cjs: a bare specifier is a
 *    dependency leak, a `.js` specifier is an unrewritten ESM edge, and a
 *    specifier leaving dist/cjs is a CJS->ESM runtime fallback;
 *  - Node ESM facades (dist/node/**) import exactly the corresponding
 *    dist/cjs/<base>.cjs module and re-export exactly the policy names;
 *  - declarations (dist/node/*.d.ts, dist/cjs/*.d.cts) reference only dist/cjs
 *    members; their only allowed bare specifiers are the optional peers.
 *    `declare module` augmentations are not scanned (bounded scanner limit);
 *  - ALL runtime and declaration edges are collected with the pinned repo
 *    TypeScript parser (real AST nodes, never regex over comments or string
 *    payloads): static require calls, literal dynamic import() calls,
 *    import/export declarations, declaration import-types and
 *    `import x = require(...)` forms. Dynamic edges whose specifier is not a
 *    string literal are REJECTED explicitly (unprovable), as are files with
 *    parse diagnostics. A literal dynamic import() of an in-graph `.cjs`
 *    specifier is validated like any other edge. ESM import/export syntax in
 *    a dist/cjs runtime file is rejected (a .cjs member must be CommonJS).
 *
 * Installed checks (real offline install of the tarball into an isolated
 *  OS-temp consumer with an isolated npm cache):
 *  - import.meta.resolve versus require.resolve for all six entries (exact
 *    dist/node versus dist/cjs targets) and for thirteen forbidden deep
 *    specifiers (must fail ERR_PACKAGE_PATH_NOT_EXPORTED, not unrelated
 *    environment errors, on both resolvers);
 *  - both arms load all six entries with exactly the policy name sets, share
 *    function/class identity across formats, replay the published GitHub
 *    vector end to end, reject tampering without leaking rawBody or identity,
 *    agree on the frozen registry in both graphs, keep a diagnostics canary
 *    private, and load core without any optional peer present;
 *  - the installed CLI prints its usage (exit 0);
 *  - a neutral esbuild bundle (platform neutral, no conditions) must pick the
 *    original dist ESM - path-only check: no dist/node or dist/cjs inputs;
 *  - actual TypeScript module resolution (Node16 with an explicit ESNext
 *    resolution mode for the import arm, CommonJS for the require arm, and
 *    Bundler) resolves the corresponding declaration graph for
 *    all six entries; deep imports stay unresolved. This is resolution only:
 *    full consumer type acceptance is a different owner's deliverable.
 *
 * Candidate code NEVER executes in the gate parent process: the provider
 * registry is imported inside a bounded child (exact report/status
 * validation; a hanging candidate becomes an infrastructure failure with
 * confirmed termination), and the runtime probe is a bounded child that must
 * exit 0 with signal null and no output overflow before its phase report is
 * accepted - a nonzero-exit child that emitted a good report is an
 * infrastructure failure, never a passing semantic control.
 *
 * Exit codes:
 *   0  PASS    - every check passed and cleanup/integrity verified
 *   1  RED     - one or more checks failed (or cleanup/integrity failed)
 *   2  USAGE   - invalid CLI invocation (single stderr line)
 *   3  BLOCKED - required prerequisite absent; reported before any temp
 *                allocation, extraction, packing, installation or runtime
 *                dispatch. A BLOCKED result is never a passing run.
 *
 * Documented limits:
 *  - Content hashes are SHA-256 of extracted tarball content and of real
 *    checkout files; member names and member types come from system `tar`
 *    listings (`-tf` paired index-wise with `-tvf`), so a member `tar`
 *    refuses to list fails the gate instead of being skipped.
 *  - The integrity snapshot is SYMMETRIC: tracked files (`git ls-files`)
 *    plus the FULL built dist/ tree (original and additive) are captured
 *    with identical rules before and after the run, so an unchanged additive
 *    file can never be reported as an addition. node_modules (read-only
 *    junction by policy) is not hashed; the bounded coverage is tracked
 *    files + dist/, not whole-dependency-tree integrity.
 *  - The runtime probe runs on the host Node binary; separate floor runtime
 *    qualification is owned by another deliverable.
 *  - Adapter runtimes must not import express/hono (verified live in the
 *    probe); declarations may type-import the optional peer names.
 *  - `--results` validation rejects existing destinations, symbolic-link
 *    ancestors, tracked paths and claim-file paths, and creates the file
 *    exclusively (`wx`) after final validation; this is a linear check, not
 *    a race-free sandbox, and no hostile-TOCTOU guarantee is claimed.
 *
 * The CLI prints one machine-JSON report on stdout for exits 0/1/3; usage
 * errors print a single line on stderr with exit 2. PASS results are
 * published only after temp cleanup and the checkout integrity re-snapshot.
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const EXIT = { PASS: 0, RED: 1, USAGE: 2, BLOCKED: 3 };

const PROBE_TIMEOUT_MS = 90_000;
const NPM_TIMEOUT_MS = 240_000;
const TAR_TIMEOUT_MS = 60_000;
const GIT_TIMEOUT_MS = 60_000;
const MESSAGE_LIMIT = 400;

class InfrastructureError extends Error {}

/** Caller misuse detected after prerequisites were fine; exits 2. */
class UsageError extends Error {}

/* -------------------------------------------------------------------------- */
/* embedded frozen policy (mirrors tasks/phase-11/exports-policy.json v1)     */
/* -------------------------------------------------------------------------- */

export const POLICY_VERSION = 1;

/**
 * Frozen six-entry policy: [export specifier, dist base path without
 * extension, exact exported runtime names]. The dist base is the SAME
 * relative base used by the original ESM graph, the Node CJS graph
 * (dist/cjs/<base>.cjs) and the Node ESM facade (dist/node/<base>).
 */
export const POLICY_PUBLIC_ENTRIES = Object.freeze([
  Object.freeze(['.', 'index', Object.freeze(['HooklatchError', 'createVerifier', 'verify', 'verifyRequest'])]),
  Object.freeze(['./diagnostics', 'diagnostics/index', Object.freeze(['diagnose'])]),
  Object.freeze(['./express', 'adapters/express', Object.freeze(['createWebhookMiddleware'])]),
  Object.freeze(['./nextjs', 'adapters/nextjs', Object.freeze(['createWebhookHandler'])]),
  Object.freeze(['./cloudflare', 'adapters/cloudflare', Object.freeze(['createWebhookHandler'])]),
  Object.freeze(['./hono', 'adapters/hono', Object.freeze(['createWebhookMiddleware'])]),
]);

/** Frozen provider registry order; compared in both directions. */
export const POLICY_PROVIDERS = Object.freeze([
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
  'razorpay',
  'paddle',
  'lemon-squeezy',
  'dodo-payments',
  'gitlab',
  'replicate',
  'workos',
  'sentry',
  'doppler',
  'sanity',
  'grafana',
  'polar',
  'linear',
  'vercel',
  'fal',
]);

/** Frozen manifest field expectations (engines/type/main/types/bin/peers). */
export const POLICY_MANIFEST_FIELDS = Object.freeze({
  type: 'module',
  engines: Object.freeze({ node: '>=22' }),
  main: './dist/cjs/index.cjs',
  types: './dist/index.d.ts',
  bin: Object.freeze({ hooklatch: './dist/cli/index.js' }),
  /** Zero runtime dependencies: `dependencies` must be absent or empty. */
  dependencies: Object.freeze({}),
  /** Zero runtime dependencies extends to optionalDependencies (absent/empty). */
  optionalDependencies: Object.freeze({}),
  /** No bundled runtime dependencies (absent, empty record or empty array). */
  bundledDependencies: Object.freeze({}),
  peerDependencies: Object.freeze({ express: '^4.18.0 || ^5.0.0', hono: '^4.0.0' }),
  peerDependenciesMeta: Object.freeze({
    express: Object.freeze({ optional: true }),
    hono: Object.freeze({ optional: true }),
  }),
});

/** Exact pinned nested export structure, including condition key order. */
export const EXPECTED_NESTED_EXPORTS = Object.freeze({
  '.': {
    node: {
      import: { types: './dist/node/index.d.ts', default: './dist/node/index.js' },
      require: { types: './dist/cjs/index.d.cts', default: './dist/cjs/index.cjs' },
    },
    types: './dist/index.d.ts',
    import: './dist/index.js',
    default: './dist/index.js',
  },
  './diagnostics': {
    node: {
      import: { types: './dist/node/diagnostics/index.d.ts', default: './dist/node/diagnostics/index.js' },
      require: { types: './dist/cjs/diagnostics/index.d.cts', default: './dist/cjs/diagnostics/index.cjs' },
    },
    types: './dist/diagnostics/index.d.ts',
    import: './dist/diagnostics/index.js',
    default: './dist/diagnostics/index.js',
  },
  './express': {
    node: {
      import: { types: './dist/node/adapters/express.d.ts', default: './dist/node/adapters/express.js' },
      require: { types: './dist/cjs/adapters/express.d.cts', default: './dist/cjs/adapters/express.cjs' },
    },
    types: './dist/adapters/express.d.ts',
    import: './dist/adapters/express.js',
    default: './dist/adapters/express.js',
  },
  './nextjs': {
    node: {
      import: { types: './dist/node/adapters/nextjs.d.ts', default: './dist/node/adapters/nextjs.js' },
      require: { types: './dist/cjs/adapters/nextjs.d.cts', default: './dist/cjs/adapters/nextjs.cjs' },
    },
    types: './dist/adapters/nextjs.d.ts',
    import: './dist/adapters/nextjs.js',
    default: './dist/adapters/nextjs.js',
  },
  './cloudflare': {
    node: {
      import: { types: './dist/node/adapters/cloudflare.d.ts', default: './dist/node/adapters/cloudflare.js' },
      require: { types: './dist/cjs/adapters/cloudflare.d.cts', default: './dist/cjs/adapters/cloudflare.cjs' },
    },
    types: './dist/adapters/cloudflare.d.ts',
    import: './dist/adapters/cloudflare.js',
    default: './dist/adapters/cloudflare.js',
  },
  './hono': {
    node: {
      import: { types: './dist/node/adapters/hono.d.ts', default: './dist/node/adapters/hono.js' },
      require: { types: './dist/cjs/adapters/hono.d.cts', default: './dist/cjs/adapters/hono.cjs' },
    },
    types: './dist/adapters/hono.d.ts',
    import: './dist/adapters/hono.js',
    default: './dist/adapters/hono.js',
  },
});

/** Optional peer names allowed as bare specifiers inside declarations. */
export const POLICY_OPTIONAL_PEERS = Object.freeze(Object.keys(POLICY_MANIFEST_FIELDS.peerDependencies));

/** CLI path inside the package, used for static shebang and runtime checks. */
export const CLI_RELATIVE = 'dist/cli/index.js';

/** Bare package specifier for one policy entry ('.' → 'hooklatch', './x' → 'hooklatch/x'). */
export function packageSpecifierOf(specifier) {
  if (specifier === '.') return 'hooklatch';

  if (!isString(specifier) || !specifier.startsWith('./')) {
    throw new InfrastructureError(`policy entry specifier is not '.' or './subpath': ${boundedText(String(specifier))}`);
  }

  return `hooklatch/${specifier.slice(2)}`;
}

/** Deep specifiers that must stay rejected by the package exports map. */
export const FORBIDDEN_DEEP_SPECS = Object.freeze([
  'hooklatch/dist/index.js',
  'hooklatch/dist/core/index.js',
  'hooklatch/dist/core/errors.js',
  'hooklatch/dist/providers/index.js',
  'hooklatch/dist/providers/stripe.js',
  'hooklatch/dist/adapters/express.js',
  'hooklatch/dist/adapters/nextjs.js',
  'hooklatch/dist/adapters/cloudflare.js',
  'hooklatch/dist/adapters/hono.js',
  'hooklatch/dist/diagnostics/index.js',
  'hooklatch/dist/cli/index.js',
  'hooklatch/package.json',
  'hooklatch/nonexistent-subpath',
]);

/**
 * Internal consistency: the pinned nested literal must be exactly what the
 * six public entries derive to (structure AND key order); the provider list
 * must not duplicate an id. A mismatch is a defect of this gate itself and
 * fails every run that calls this check.
 */
export function assertPolicySelfConsistency() {
  const derived = {};

  for (const [specifier, base] of POLICY_PUBLIC_ENTRIES) {
    derived[specifier] = {
      node: {
        import: { types: `./dist/node/${base}.d.ts`, default: `./dist/node/${base}.js` },
        require: { types: `./dist/cjs/${base}.d.cts`, default: `./dist/cjs/${base}.cjs` },
      },
      types: `./dist/${base}.d.ts`,
      import: `./dist/${base}.js`,
      default: `./dist/${base}.js`,
    };
  }

  if (JSON.stringify(EXPECTED_NESTED_EXPORTS) !== JSON.stringify(derived)) {
    throw new Error('embedded EXPECTED_NESTED_EXPORTS diverges from the structure derived from POLICY_PUBLIC_ENTRIES');
  }

  const keys = Object.keys(EXPECTED_NESTED_EXPORTS);

  if (keys.length !== POLICY_PUBLIC_ENTRIES.length) {
    throw new Error('embedded EXPECTED_NESTED_EXPORTS entry count diverges from POLICY_PUBLIC_ENTRIES');
  }

  for (let index = 0; index < keys.length; index += 1) {
    if (keys[index] !== POLICY_PUBLIC_ENTRIES[index][0]) {
      throw new Error(`embedded EXPECTED_NESTED_EXPORTS key ${index} is ${keys[index]}; policy entry is ${POLICY_PUBLIC_ENTRIES[index][0]}`);
    }
  }

  const seen = new Set();

  for (const id of POLICY_PROVIDERS) {
    if (seen.has(id)) throw new Error(`POLICY_PROVIDERS duplicate id ${id}`);
    seen.add(id);
  }
}

/* -------------------------------------------------------------------------- */
/* small utilities                                                            */
/* -------------------------------------------------------------------------- */

/** JSON boundary kind ("String", "Object", "Array", ...) without typeof. */
function jsonKind(value) {
  return Object.prototype.toString.call(value).slice(8, -1);
}

/** JSON boundary kind ("String", "Object", "Array", ...) without typeof. */
export function isPlainRecord(value) {
  return jsonKind(value) === 'Object';
}

function isString(value) {
  return jsonKind(value) === 'String';
}

function boundedText(value) {
  const text = String(value).replace(/\s+/g, ' ').trim();

  return text.length > MESSAGE_LIMIT ? `${text.slice(0, MESSAGE_LIMIT)}...` : text;
}

function sha256Buffer(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function sequenceEqual(observed, expected) {
  if (!Array.isArray(observed) || observed.length !== expected.length) return false;

  for (let index = 0; index < expected.length; index += 1) {
    if (observed[index] !== expected[index]) return false;
  }

  return true;
}

/** Stable string code of an error object for honest failure classification. */
function errorCodeOf(error) {
  if (error !== null && isPlainRecord(error) && Object.hasOwn(error, 'code') && isString(error.code)) {
    return error.code;
  }

  return String(error);
}

/* -------------------------------------------------------------------------- */
/* tar member validation and forbidden-path checks                            */
/* -------------------------------------------------------------------------- */

/** Validate one raw tar member name; returns `{ok, rel, isDir, skip}`. */
export function normalizeTarMember(rawName) {
  const fail = (reason) => ({ ok: false, reason });

  if (!isString(rawName) || rawName.length === 0) return fail('empty member name');

  if (rawName.includes('\\')) return fail('backslash in member name');

  if (/\s/.test(rawName)) return fail('whitespace in member name');

  if (rawName.startsWith('/') || /^[A-Za-z]:/.test(rawName)) return fail('absolute member name');

  const isDir = rawName.endsWith('/');
  const clean = isDir ? rawName.slice(0, -1) : rawName;
  const segments = clean.split('/');

  if (segments.includes('..') || segments.includes('.')) return fail('traversal segment in member name');

  for (let index = 0; index < segments.length - 1; index += 1) {
    if (segments[index] === '') return fail('empty path segment');
  }

  if (clean === '' || clean === 'package') return { ok: true, rel: '', isDir, skip: true };

  if (!clean.startsWith('package/')) return fail(`member is outside package/: ${rawName}`);

  return { ok: true, rel: clean.slice('package/'.length), isDir, skip: false };
}

export const FORBIDDEN_TOP_SEGMENTS = Object.freeze(['src', 'tests', 'notes', 'tasks', 'node_modules', '.git']);
export const FORBIDDEN_SUBSTRINGS = Object.freeze(['credentials', 'source-temp']);

/** Scan validated member rel paths for private/leaked trees. */
export function runMemberChecks(memberNames) {
  const findings = [];

  for (const rel of memberNames) {
    const top = rel.split('/')[0];

    if (FORBIDDEN_TOP_SEGMENTS.includes(top)) {
      findings.push({ kind: 'tarball-forbidden-path', path: rel, reason: `forbidden top-level segment ${top}` });
      continue;
    }

    const lower = rel.toLowerCase();

    for (const substring of FORBIDDEN_SUBSTRINGS) {
      if (lower.includes(substring)) {
        findings.push({ kind: 'tarball-forbidden-path', path: rel, reason: `forbidden substring ${substring}` });
      }
    }
  }

  return findings;
}

/**
 * Validate member TYPES from the `tar -tvf` listing paired index-wise with
 * the `tar -tf` names. Only plain files and directories are allowed;
 * symlink, hardlink, device and fifo members are rejected (extraction is
 * aborted before any write, so this gate never materializes such members),
 * and textual link indicators are rejected regardless of the type character
 * so a different tar flavor cannot hide a link entry.
 */
export function runMemberTypeChecks(pairs) {
  const findings = [];

  for (const { name, typeChar, linkText } of pairs) {
    if (linkText === true) {
      findings.push({ kind: 'tarball-member-link', path: name });
      continue;
    }

    if (typeChar !== '-' && typeChar !== 'd') {
      findings.push({ kind: 'tarball-member-type', path: name, typeChar });
    }
  }

  return findings;
}

/**
 * Duplicate member names in one archive: extraction is last-wins, so a
 * duplicated member makes the effective content ambiguous. Returns one
 * finding per duplicated name.
 */
export function runMemberDuplicateChecks(memberNames) {
  const counts = new Map();

  for (const name of memberNames) counts.set(name, (counts.get(name) ?? 0) + 1);

  const duplicates = [];

  for (const [name, count] of counts.entries()) {
    if (count > 1) duplicates.push(name);
  }

  return duplicates.map((name) => ({ kind: 'tarball-member-duplicate', path: name }));
}

/* -------------------------------------------------------------------------- */
/* manifest structure, entry shape, sync and field checks (pure)              */
/* -------------------------------------------------------------------------- */

/** Exact pinned structure including key order. */
export function runStructureExactChecks(manifest) {
  if (!isPlainRecord(manifest) || !isPlainRecord(manifest.exports)) {
    return [{ kind: 'exports-structure-exact', detail: 'package exports is missing or not a record' }];
  }

  const observed = JSON.stringify(manifest.exports);
  const expected = JSON.stringify(EXPECTED_NESTED_EXPORTS);

  if (observed === expected) return [];

  let diverge = 0;

  while (diverge < observed.length && diverge < expected.length && observed[diverge] === expected[diverge]) {
    diverge += 1;
  }

  return [{
    kind: 'exports-structure-exact',
    detail: `manifest exports diverge from the pinned nested policy at character ${diverge}`,
    expectedPrefix: expected.slice(Math.max(0, diverge - 40), diverge + 40),
    observedPrefix: observed.slice(Math.max(0, diverge - 40), diverge + 40),
  }];
}

/** Granular per-entry shape derived from POLICY_PUBLIC_ENTRIES (not the pin). */
export function runExportEntryChecks(manifest) {
  const findings = [];

  if (!isPlainRecord(manifest) || !isPlainRecord(manifest.exports)) {
    return [{ kind: 'exports-entry-shape', detail: 'package exports is missing or not a record' }];
  }

  for (const [specifier, base, names] of POLICY_PUBLIC_ENTRIES) {
    const target = manifest.exports[specifier];

    if (!isPlainRecord(target)) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'entry missing or not a record' });
      continue;
    }

    const topKeys = Object.keys(target);

    if (!sequenceEqual(topKeys, ['node', 'types', 'import', 'default'])) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'top-level condition key order', observed: topKeys });
    }

    const nodeKeys = isPlainRecord(target.node) ? Object.keys(target.node) : [];

    if (!sequenceEqual(nodeKeys, ['import', 'require'])) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'node condition key order', observed: nodeKeys });
    }

    const importKeys = isPlainRecord(target.node) && isPlainRecord(target.node.import) ? Object.keys(target.node.import) : [];
    const requireKeys = isPlainRecord(target.node) && isPlainRecord(target.node.require) ? Object.keys(target.node.require) : [];

    if (!sequenceEqual(importKeys, ['types', 'default'])) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'node.import condition key order', observed: importKeys });
    }

    if (!sequenceEqual(requireKeys, ['types', 'default'])) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'node.require condition key order', observed: requireKeys });
    }

    const expectedTargets = [
      ['node.import.types', `./dist/node/${base}.d.ts`],
      ['node.import.default', `./dist/node/${base}.js`],
      ['node.require.types', `./dist/cjs/${base}.d.cts`],
      ['node.require.default', `./dist/cjs/${base}.cjs`],
      ['types', `./dist/${base}.d.ts`],
      ['import', `./dist/${base}.js`],
      ['default', `./dist/${base}.js`],
    ];

    for (const [key, expected] of expectedTargets) {
      const armKeys = key.split('.');
      let observedValue = target;

      for (const armKey of armKeys) {
        observedValue = isPlainRecord(observedValue) ? observedValue[armKey] : undefined;
      }

      if (observedValue !== expected) {
        findings.push({ kind: 'exports-entry-shape', specifier, key, expected, observed: observedValue });
      }
    }

    if (names.length === 0) {
      findings.push({ kind: 'exports-entry-shape', specifier, detail: 'policy entry has no exported names' });
    }
  }

  return findings;
}

/** Export keys versus policy specifiers in both directions. */
export function runPublicEntriesSyncChecks(manifest) {
  if (!isPlainRecord(manifest) || !isPlainRecord(manifest.exports)) {
    return [{ kind: 'public-entries-manifest-only', detail: 'package exports is missing or not a record' }];
  }

  const keys = Object.keys(manifest.exports);
  const findings = [];
  const policyOnly = [];
  const manifestOnly = [];

  for (const [specifier] of POLICY_PUBLIC_ENTRIES) {
    if (!keys.includes(specifier)) policyOnly.push(specifier);
  }

  for (const key of keys) {
    let known = false;

    for (const [specifier] of POLICY_PUBLIC_ENTRIES) {
      if (specifier === key) known = true;
    }

    if (!known) manifestOnly.push(key);
  }

  if (policyOnly.length > 0) findings.push({ kind: 'public-entries-policy-only', specifiers: policyOnly });

  if (manifestOnly.length > 0) findings.push({ kind: 'public-entries-manifest-only', specifiers: manifestOnly });

  return findings;
}

/** Frozen manifest field expectations, including zero dependencies. */
export function runManifestFieldChecks(manifest) {
  const findings = [];

  const expectations = [
    ['type', POLICY_MANIFEST_FIELDS.type],
    ['main', POLICY_MANIFEST_FIELDS.main],
    ['types', POLICY_MANIFEST_FIELDS.types],
  ];

  for (const [field, expected] of expectations) {
    if (manifest[field] !== expected) {
      findings.push({ kind: 'manifest-field', field, expected, observed: manifest[field] });
    }
  }

  if (JSON.stringify(manifest.engines) !== JSON.stringify(POLICY_MANIFEST_FIELDS.engines)) {
    findings.push({ kind: 'manifest-field', field: 'engines', expected: POLICY_MANIFEST_FIELDS.engines, observed: manifest.engines });
  }

  if (JSON.stringify(manifest.bin) !== JSON.stringify(POLICY_MANIFEST_FIELDS.bin)) {
    findings.push({ kind: 'manifest-field', field: 'bin', expected: POLICY_MANIFEST_FIELDS.bin, observed: manifest.bin });
  }

  const observedDependencies = isPlainRecord(manifest.dependencies) ? manifest.dependencies : {};

  if (JSON.stringify(observedDependencies) !== JSON.stringify(POLICY_MANIFEST_FIELDS.dependencies)) {
    findings.push({
      kind: 'manifest-field',
      field: 'dependencies',
      expected: POLICY_MANIFEST_FIELDS.dependencies,
      observed: isPlainRecord(manifest.dependencies) ? manifest.dependencies : errorCodeOf(manifest.dependencies),
      reason: 'runtime dependencies must be exactly zero',
    });
  }

  /**
   * Zero runtime dependencies includes optionalDependencies: npm silently
   * omits a nonexistent optional dependency during offline install, so an
   * empty-observing install is not evidence - the manifest itself must not
   * declare one.
   */
  if (manifest.optionalDependencies !== undefined) {
    const observed = manifest.optionalDependencies;

    if (!(isPlainRecord(observed) && Object.keys(observed).length === 0)) {
      findings.push({
        kind: 'manifest-field',
        field: 'optionalDependencies',
        expected: 'absent or an empty record (zero runtime dependencies)',
        observed,
      });
    }
  }

  /** No bundled runtime dependencies: absent, empty record or empty array. */
  if (manifest.bundledDependencies !== undefined) {
    const observed = manifest.bundledDependencies;

    const empty = (isPlainRecord(observed) && Object.keys(observed).length === 0)
      || (Array.isArray(observed) && observed.length === 0);

    if (!empty) {
      findings.push({
        kind: 'manifest-field',
        field: 'bundledDependencies',
        expected: 'absent, an empty record, or an empty array (no bundled runtime dependencies)',
        observed,
      });
    }
  }

  if (JSON.stringify(manifest.peerDependencies) !== JSON.stringify(POLICY_MANIFEST_FIELDS.peerDependencies)) {
    findings.push({ kind: 'manifest-field', field: 'peerDependencies', expected: POLICY_MANIFEST_FIELDS.peerDependencies, observed: manifest.peerDependencies });
  }

  if (JSON.stringify(manifest.peerDependenciesMeta) !== JSON.stringify(POLICY_MANIFEST_FIELDS.peerDependenciesMeta)) {
    findings.push({ kind: 'manifest-field', field: 'peerDependenciesMeta', expected: POLICY_MANIFEST_FIELDS.peerDependenciesMeta, observed: manifest.peerDependenciesMeta });
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* provider registry checks (pure)                                            */
/* -------------------------------------------------------------------------- */

/** Built SUPPORTED_PROVIDERS array versus the frozen policy, both ways. */
export function runProviderRegistryChecks(registryIds) {
  if (!Array.isArray(registryIds)) {
    return [{ kind: 'provider-registry-import', detail: 'SUPPORTED_PROVIDERS is not an array' }];
  }

  const findings = [];

  for (const id of registryIds) {
    if (!isString(id)) findings.push({ kind: 'provider-registry-shape', observed: String(id) });
  }

  const counts = new Map();

  for (const id of registryIds) {
    if (!isString(id)) continue;

    counts.set(id, (counts.get(id) ?? 0) + 1);
  }

  const duplicates = [];

  for (const [id, count] of counts.entries()) {
    if (count > 1) duplicates.push(id);
  }

  if (duplicates.length > 0) findings.push({ kind: 'provider-registry-duplicate', ids: duplicates });

  const unknown = [];

  for (const id of registryIds) {
    if (!isString(id) || !POLICY_PROVIDERS.includes(id)) unknown.push(String(id));
  }

  if (unknown.length > 0) findings.push({ kind: 'provider-registry-unknown', ids: unknown });

  const missing = [];

  for (const id of POLICY_PROVIDERS) {
    if (!registryIds.includes(id)) missing.push(id);
  }

  if (missing.length > 0) findings.push({ kind: 'provider-registry-missing', ids: missing });

  if (duplicates.length > 0 || unknown.length > 0 || missing.length > 0) return findings;

  const observedOrder = registryIds.slice();

  if (!sequenceEqual(observedOrder, POLICY_PROVIDERS)) {
    findings.push({ kind: 'provider-registry-order', expected: POLICY_PROVIDERS, observed: observedOrder });
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* target presence (pure)                                                     */
/* -------------------------------------------------------------------------- */

/** Every export/main/types/bin target path the policy requires. */
export function referencedTargets() {
  const targets = new Set();

  for (const [, base] of POLICY_PUBLIC_ENTRIES) {
    targets.add(`./dist/node/${base}.d.ts`);
    targets.add(`./dist/node/${base}.js`);
    targets.add(`./dist/cjs/${base}.d.cts`);
    targets.add(`./dist/cjs/${base}.cjs`);
    targets.add(`./dist/${base}.d.ts`);
    targets.add(`./dist/${base}.js`);
  }

  targets.add(POLICY_MANIFEST_FIELDS.main);
  targets.add(POLICY_MANIFEST_FIELDS.types);
  targets.add(POLICY_MANIFEST_FIELDS.bin.hooklatch);

  return [...targets].sort();
}

/** Validated member names must cover every referenced target. */
export function runTargetPresenceChecks(memberNames) {
  const findings = [];
  const present = new Set(memberNames);

  for (const target of referencedTargets()) {
    if (!present.has(target.slice('./'.length))) {
      findings.push({ kind: 'tarball-target-missing', target });
    }
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* graph edge checks (pure; input is [{rel, text}] of package-relative files) */
/* -------------------------------------------------------------------------- */

/** Lazily resolved repo-local TypeScript (pinned parser for edge scans). */
let cachedTypeScript = null;

/**
 * Resolve the pinned repo-local typescript module from the gate's own
 * location (never from the candidate). Pure edge scans parse CANDIDATE TEXT
 * with it; the module itself is a tool dependency of the host checkout.
 */
export function getTypeScript() {
  if (cachedTypeScript !== null) return cachedTypeScript;

  const gateRequire = createRequire(import.meta.url);

  cachedTypeScript = gateRequire('typescript');

  return cachedTypeScript;
}

/**
 * Resolve one relative specifier against a package-relative containing file
 * and require the result to stay inside `rootPrefix` (for example "dist/cjs").
 * No extension mapping: the new graphs must carry exact final extensions.
 * `memberSet` may be empty, in which case only reachability is classified.
 */
export function resolveRelativeWithinRoot(specifier, containingRel, rootPrefix, memberSet) {
  if (!specifier.startsWith('.')) {
    return { ok: false, reason: 'bare-specifier', target: specifier };
  }

  const dir = path.posix.dirname(containingRel);
  const joined = path.posix.normalize(path.posix.join(dir, specifier));

  if (path.posix.isAbsolute(joined) || joined === '..' || joined.startsWith('../')) {
    return { ok: false, reason: 'escapes-root', target: joined };
  }

  if (!joined.startsWith(`${rootPrefix}/`)) {
    return { ok: false, reason: 'outside-root', target: joined };
  }

  if (memberSet.size > 0 && !memberSet.has(joined)) {
    return { ok: false, reason: 'unresolved', target: joined };
  }

  return { ok: true, target: joined };
}

/**
 * Parse candidate text with the pinned TypeScript parser. Returns the
 * source file plus its parse diagnostics; whitespace, comments and ordinary
 * string payloads can never masquerade as edges in the walked tree.
 */
function parseCandidate(ts, rel, text, isDeclaration) {
  const scriptKind = isDeclaration ? ts.ScriptKind.TS : ts.ScriptKind.JS;

  return ts.createSourceFile(rel, text, ts.ScriptTarget.ES2022, /* setParentNodes */ true, scriptKind);
}

const isStringLikeNode = (ts, node) => ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);

/**
 * REAL runtime edges from one parsed file: identifier require() calls with a
 * string-literal argument, dynamic import() calls, and static import/export
 * module declarations. Dynamic calls with a non-literal argument are
 * returned as unprovable so the caller can reject them explicitly; they are
 * never silently skipped.
 */
function collectRuntimeEdges(ts, sourceFile) {
  const edges = [];

  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const target = node.expression;

      if (ts.isIdentifier(target) && target.escapedText === 'require' && node.arguments.length === 1) {
        const argument = node.arguments[0];

        if (isStringLikeNode(ts, argument)) edges.push({ via: 'require', specifier: argument.text });
        else edges.push({ via: 'require', specifier: null, unprovable: true });
      } else if (target.kind === ts.SyntaxKind.ImportKeyword) {
        if (node.arguments.length === 1 && isStringLikeNode(ts, node.arguments[0])) {
          edges.push({ via: 'import', specifier: node.arguments[0].text });
        } else {
          edges.push({ via: 'import', specifier: null, unprovable: true });
        }
      }
    } else if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const moduleSpecifier = node.moduleSpecifier;
      const via = ts.isImportDeclaration(node) ? 'static-import' : 'static-export';

      if (moduleSpecifier === undefined) {
        /* `export { a, b }` without a module clause carries no edge. */
      } else if (ts.isStringLiteral(moduleSpecifier)) {
        edges.push({ via, specifier: moduleSpecifier.text });
      } else {
        edges.push({ via, specifier: null, unprovable: true });
      }
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sourceFile, visit);

  return edges;
}

/**
 * REAL declaration edges from one parsed file: import/export declarations,
 * import-type specifiers (`import("./x.cjs").T`, including under `typeof`)
 * and `import x = require(...)` forms. Non-literal specifiers are surfaced
 * as unprovable for explicit rejection.
 */
function collectDeclarationEdges(ts, sourceFile) {
  const edges = [];

  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const moduleSpecifier = node.moduleSpecifier;

      if (moduleSpecifier === undefined) {
        /* `export { a, b }` without a module clause carries no edge. */
      } else if (ts.isStringLiteral(moduleSpecifier)) {
        edges.push({ via: ts.isImportDeclaration(node) ? 'import' : 'export', specifier: moduleSpecifier.text });
      } else {
        edges.push({ via: ts.isImportDeclaration(node) ? 'import' : 'export', specifier: null, unprovable: true });
      }
    } else if (ts.isImportTypeNode(node)) {
      const argument = node.argument;

      if (ts.isLiteralTypeNode(argument) && ts.isStringLiteral(argument.literal)) {
        edges.push({ via: 'import-type', specifier: argument.literal.text });
      } else {
        edges.push({ via: 'import-type', specifier: null, unprovable: true });
      }
    } else if (ts.isExternalModuleReference(node)) {
      const expression = node.expression;

      if (ts.isStringLiteral(expression)) edges.push({ via: 'require-equals', specifier: expression.text });
      else edges.push({ via: 'require-equals', specifier: null, unprovable: true });
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sourceFile, visit);

  return edges;
}

/** Scan one additive-graph file; returns its edges plus parse diagnostics. */
export function scanGraphFile(rel, text) {
  const ts = getTypeScript();

  const isDeclaration = (rel.startsWith('dist/cjs/') && rel.endsWith('.d.cts'))
    || (rel.startsWith('dist/node/') && rel.endsWith('.d.ts'));

  const sourceFile = parseCandidate(ts, rel, text, isDeclaration);

  const diagnostics = sourceFile.parseDiagnostics
    .map((diagnostic) => ({ message: ts.flattenDiagnosticMessageText(diagnostic.messageText, ' '), line: rel }));

  const edges = isDeclaration ? collectDeclarationEdges(ts, sourceFile) : collectRuntimeEdges(ts, sourceFile);

  return { edges, diagnostics, isDeclaration };
}

/**
 * STRUCTURE edge scan over the ADDITIVE Node graphs (existence is checked
 * separately by runEdgeResolutionChecks). Edges come from the pinned
 * TypeScript parser, so comments and ordinary string payloads can never be
 * misread as edges. Runtime `.cjs` files under dist/cjs and facade `.js`
 * files under dist/node must reference only relative `.cjs` specifiers that
 * stay inside dist/cjs; a literal dynamic import() of an in-graph `.cjs`
 * specifier is validated like any other edge, while non-literal/unprovable
 * edges are rejected explicitly; declarations additionally allow the
 * optional peer names as bare specifiers. ESM import/export module syntax
 * inside a dist/cjs runtime file is rejected (that member must be CommonJS).
 */
export function runGraphEdgeChecks(entries) {
  const findings = [];

  for (const { rel, text } of entries) {
    const scanned = scanGraphFile(rel, text);

    for (const diagnostic of scanned.diagnostics) {
      findings.push({ kind: 'cjs-graph-syntax', file: rel, detail: boundedText(diagnostic.message) });
    }

    if (scanned.isDeclaration) {
      for (const { specifier, via } of scanned.edges) {
        if (specifier === null) {
          findings.push({ kind: 'declaration-edge-unprovable', file: rel, via });
          continue;
        }

        if (specifier.startsWith('.')) {
          const resolved = resolveRelativeWithinRoot(specifier, rel, 'dist/cjs', new Set());

          if (resolved.reason === 'outside-root' || resolved.reason === 'escapes-root') {
            findings.push({ kind: 'declaration-edge-escapes-cjs', file: rel, specifier, via });
          } else if (!specifier.endsWith('.cjs')) {
            findings.push({ kind: 'declaration-edge-non-cjs', file: rel, specifier, via });
          }
        } else if (!POLICY_OPTIONAL_PEERS.includes(specifier)) {
          findings.push({ kind: 'declaration-edge-bare-non-peer', file: rel, specifier, via });
        }
      }

      continue;
    }

    const isCjsRuntime = rel.startsWith('dist/cjs/') && rel.endsWith('.cjs');
    const isFacadeRuntime = rel.startsWith('dist/node/') && rel.endsWith('.js');

    if (!isCjsRuntime && !isFacadeRuntime) continue;

    const prefix = isFacadeRuntime ? 'facade' : 'cjs';

    for (const { specifier, via } of scanned.edges) {
      if (isCjsRuntime && (via === 'static-import' || via === 'static-export')) {
        findings.push({ kind: 'cjs-esm-syntax', file: rel, specifier, via });
        continue;
      }

      if (specifier === null) {
        findings.push({ kind: `${prefix}-edge-unprovable`, file: rel, via });
        continue;
      }

      if (!specifier.startsWith('.')) {
        findings.push({ kind: `${prefix}-edge-bare`, file: rel, specifier, via });
        continue;
      }

      const resolved = resolveRelativeWithinRoot(specifier, rel, 'dist/cjs', new Set());

      if (resolved.reason === 'outside-root' || resolved.reason === 'escapes-root') {
        findings.push({ kind: `${prefix}-edge-escapes-cjs`, file: rel, specifier, via, target: resolved.target });
      } else if (!specifier.endsWith('.cjs')) {
        findings.push({ kind: `${prefix}-edge-js-specifier`, file: rel, specifier, via });
      }
    }
  }

  return findings;
}

/**
 * EXISTENCE edge scan: every relative specifier in the additive graphs must
 * resolve to an actual member of the tarball. Runtime files report
 * `cjs-edge-unresolved`/`facade-edge-unresolved`; declarations report
 * `declaration-edge-unresolved`. Escapes are reported by the structure scan;
 * unprovable (non-literal) edges are rejected there and carry no specifier
 * to resolve here.
 */
export function runEdgeResolutionChecks(entries, memberNames) {
  const findings = [];
  const memberSet = new Set(memberNames);

  for (const { rel, text } of entries) {
    const scanned = scanGraphFile(rel, text);

    for (const { specifier } of scanned.edges) {
      if (specifier === null || !specifier.startsWith('.')) continue;

      const resolved = resolveRelativeWithinRoot(specifier, rel, 'dist/cjs', memberSet);

      if (resolved.ok || resolved.reason !== 'unresolved') continue;

      const kind = scanned.isDeclaration
        ? 'declaration-edge-unresolved'
        : (rel.startsWith('dist/node/') ? 'facade-edge-unresolved' : 'cjs-edge-unresolved');

      findings.push({ kind, file: rel, specifier, target: resolved.target });
    }
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* facade module shape (pure)                                                 */
/* -------------------------------------------------------------------------- */

/** Exact facade shapes for the six entries. Input is Map rel -> content. */
export function runFacadeModuleChecks(texts) {
  const findings = [];

  for (const [, base, names] of POLICY_PUBLIC_ENTRIES) {
    const jsRel = `dist/node/${base}.js`;
    const dtsRel = `dist/node/${base}.d.ts`;

    const expectedSpecifier = path.posix.relative(
      path.posix.dirname(jsRel),
      `dist/cjs/${base}.cjs`,
    );

    const jsText = texts.get(jsRel);

    if (jsText === undefined) {
      findings.push({ kind: 'facade-shape-missing', file: jsRel });
      continue;
    }

    const lines = jsText.split('\n').map((line) => line.trim()).filter((line) => line !== '');
    const importLine = `import implementation from "${expectedSpecifier}";`;

    if (lines.length === 0 || lines[0] !== importLine) {
      findings.push({ kind: 'facade-shape-import-line', file: jsRel, expected: importLine, observed: lines[0] ?? '' });
    }

    const expectedExports = names.map((name) => `export const ${name} = implementation.${name};`);
    const exportLines = lines.slice(1);

    if (exportLines.length !== expectedExports.length) {
      findings.push({ kind: 'facade-shape-extra-line', file: jsRel, expectedCount: expectedExports.length, observedCount: exportLines.length });
    }

    const remaining = [...exportLines];

    for (const expected of expectedExports) {
      const index = remaining.indexOf(expected);

      if (index === -1) {
        findings.push({ kind: 'facade-shape-export-line', file: jsRel, expected });
        continue;
      }

      remaining.splice(index, 1);
    }

    for (const unexpected of remaining) {
      findings.push({ kind: 'facade-shape-extra-line', file: jsRel, observed: unexpected });
    }

    const dtsText = texts.get(dtsRel);
    const expectedDecl = `export * from "${expectedSpecifier}";`;

    if (dtsText === undefined) {
      findings.push({ kind: 'facade-decl-shape', file: dtsRel, detail: 'missing' });
    } else if (dtsText.trim() !== expectedDecl) {
      findings.push({ kind: 'facade-decl-shape', file: dtsRel, expected: expectedDecl, observed: boundedText(dtsText.trim()) });
    }
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* CLI shebang (pure)                                                         */
/* -------------------------------------------------------------------------- */

export function runCliShebangCheck(text) {
  if (!text.startsWith('#!/usr/bin/env node')) {
    return [{
      kind: 'cli-shebang',
      file: CLI_RELATIVE,
      detail: 'installed CLI must start with #!/usr/bin/env node',
      observed: boundedText(text.slice(0, 80)),
    }];
  }

  return [];
}

/* -------------------------------------------------------------------------- */
/* baseline pin comparator (pure)                                             */
/* -------------------------------------------------------------------------- */

/**
 * Compare sorted [{rel, sha256}] lists of the tarball original-ESM portion
 * and the checkout dist portion (both excluding dist/cjs/** and dist/node/**)
 * in both directions.
 */
export function compareBaselinePins(tarballFiles, checkoutFiles) {
  const findings = [];
  const tarballMap = new Map(tarballFiles.map((entry) => [entry.rel, entry.sha256]));
  const checkoutMap = new Map(checkoutFiles.map((entry) => [entry.rel, entry.sha256]));

  for (const [rel, sha] of tarballMap.entries()) {
    const observed = checkoutMap.get(rel);

    if (observed === undefined) {
      findings.push({ kind: 'baseline-pin-missing-in-checkout', path: rel });
    } else if (observed !== sha) {
      findings.push({ kind: 'baseline-pin-hash-mismatch', path: rel });
    }
  }

  for (const rel of checkoutMap.keys()) {
    if (!tarballMap.has(rel)) {
      findings.push({ kind: 'baseline-pin-missing-in-tarball', path: rel });
    }
  }

  return findings;
}

/** True when a dist-relative path is part of the pinned original portion. */
export function isOriginalDistPath(rel) {
  return rel.startsWith('dist/') && !rel.startsWith('dist/cjs/') && !rel.startsWith('dist/node/');
}

/* -------------------------------------------------------------------------- */
/* bounded subprocess plumbing                                                */
/* -------------------------------------------------------------------------- */

/** npm is not guaranteed to expose npm_execpath when run under plain node. */
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

  return found === undefined ? null : found;
}

const lifecycle = { cleanupSafe: true };

/**
 * Run a bounded child and CAPTURE the outcome without treating a nonzero
 * status as infrastructure failure (the caller decides the verdict). Rejects
 * InfrastructureError only when the child cannot start or when termination
 * after a timeout cannot be confirmed (which preserves the temp root).
 */
function runCapture(command, args, options) {
  return new Promise((resolve, reject) => {
    let child;

    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        windowsHide: true,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: options.env,
      });
    } catch (spawnError) {
      reject(new InfrastructureError(`${options.label} could not start: ${boundedText(spawnError)}`));

      return;
    }

    let stdout = '';
    let stderr = '';
    let outputOverflow = false;
    let timedOut = false;
    let terminationTimer;
    const limit = 16 * 1024 * 1024;

    /** Accumulate output and TRACK overflow instead of silently truncating. */
    const appendCapped = (current, chunk) => {
      if (current.length >= limit) {
        outputOverflow = true;

        return current;
      }

      if (current.length + chunk.length > limit) {
        outputOverflow = true;

        return current + chunk.slice(0, limit - current.length);
      }

      return current + chunk;
    };

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
        reject(new InfrastructureError(`${options.label} termination could not be confirmed; temp files retained.`));
      }, 5000);
    }, options.timeout);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout = appendCapped(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = appendCapped(stderr, chunk); });
    child.on('error', (spawnError) => {
      clearTimeout(timer);
      clearTimeout(terminationTimer);
      reject(new InfrastructureError(`${options.label} could not start: ${boundedText(spawnError)}`));
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      clearTimeout(terminationTimer);
      resolve({ status: code, signal, stdout, stderr, timedOut, outputOverflow });
    });
  });
}

/** Run one tar operation; returns the captured result. */
function runTar(args, label) {
  return runCapture('tar', args, { cwd: process.cwd(), timeout: TAR_TIMEOUT_MS, label });
}

/* -------------------------------------------------------------------------- */
/* runtime probe source (generated child; executed only after install)        */
/* -------------------------------------------------------------------------- */

const PROBE_TEMPLATE = `import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const ESM_TARGETS = ${JSON.stringify('__ESM_TARGETS__')};
const CJS_TARGETS = ${JSON.stringify('__CJS_TARGETS__')};
const ENTRY_NAMES = ${JSON.stringify('__ENTRY_NAMES__')};
const EXPECTED_REGISTRY = ${JSON.stringify('__EXPECTED_REGISTRY__')};
const FORBIDDEN_SPECS = ${JSON.stringify('__FORBIDDEN_SPECS__')};
const CLI_RELATIVE = ${JSON.stringify('__CLI_RELATIVE__')};
const CANARY = ${JSON.stringify('__CANARY__')};

const phases = {};

function runPhase(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then((evidence) => {
      phases[name] = { verdict: 'pass', detail: '', evidence };
    }, (error) => {
      const message = Object.prototype.toString.call(error) === '[object Error]'
        ? String(error.message)
        : String(error);
      phases[name] = { verdict: 'fail', detail: message, evidence: null };
    });
}

const toPosix = (value) => value.split(path.sep).join('/');

let pkgRoot = null;

await runPhase('load', () => {
  const cjsIndex = require.resolve('hooklatch');
  /* require.resolve('hooklatch') lands on dist/cjs/index.cjs (pinned by the
   * exports policy); the package root is exactly two directories up. */
  pkgRoot = path.resolve(path.dirname(cjsIndex), '..', '..');
  const manifest = JSON.parse(readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  return { cjsIndex: toPosix(path.relative(pkgRoot, cjsIndex)), binHooklatch: manifest.bin.hooklatch };
});

function requirePkgRoot() {
  if (pkgRoot === null) throw new Error('skipped: load phase failed');
  return pkgRoot;
}

await runPhase('resolutions', () => {
  const root = requirePkgRoot();
  const observations = { esm: [], cjs: [] };

  for (const { spec, rel } of ESM_TARGETS) {
    const file = fileURLToPath(import.meta.resolve(spec));
    const actual = toPosix(path.relative(root, file));

    assert.ok(existsSync(file), 'resolved file exists: ' + spec);
    assert.equal(actual, rel, 'ESM resolution target for ' + spec);
    observations.esm.push({ spec, expected: rel, actual });
  }

  for (const { spec, rel } of CJS_TARGETS) {
    const file = require.resolve(spec);
    const actual = toPosix(path.relative(root, file));

    assert.ok(existsSync(file), 'resolved file exists: ' + spec);
    assert.equal(actual, rel, 'require resolution target for ' + spec);
    observations.cjs.push({ spec, expected: rel, actual });
  }

  return observations;
});

await runPhase('forbidden', () => {
  requirePkgRoot();
  const observations = [];

  for (const spec of FORBIDDEN_SPECS) {
    let esmCode = null;
    let cjsCode = null;

    try {
      import.meta.resolve(spec);
      esmCode = 'RESOLVED_UNEXPECTEDLY';
    } catch (error) {
      esmCode = errorCodeOfProbe(error);
    }

    try {
      require.resolve(spec);
      cjsCode = 'RESOLVED_UNEXPECTEDLY';
    } catch (error) {
      cjsCode = errorCodeOfProbe(error);
    }

    assert.equal(esmCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ESM deep import rejected: ' + spec);
    assert.equal(cjsCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'CJS deep import rejected: ' + spec);
    observations.push({ spec, esmCode, cjsCode });
  }

  return observations;
});

function errorCodeOfProbe(error) {
  if (Object.prototype.toString.call(error) === '[object Error]' && Object.hasOwn(error, 'code') && typeof error.code === 'string') {
    return error.code;
  }
  return String(error);
}

await runPhase('identity-functional', async () => {
  const root = requirePkgRoot();
  const observations = { entries: [], registry: null, diagnostics: null, peerIsolation: null };

  for (const { spec, names } of ENTRY_NAMES) {
    const esm = await import(spec);
    const cjs = require(spec);

    assert.deepEqual(Object.keys(esm).sort(), names.slice().sort(), spec + ' ESM namespace keys');
    assert.deepEqual(Object.keys(cjs).sort(), names.slice().sort(), spec + ' CJS export keys');

    for (const name of names) {
      assert.equal(esm[name], cjs[name], spec + ' identity of ' + name);
      assert.ok(esm[name] instanceof Function, spec + ' ' + name + ' is a function or class');
    }

    observations.entries.push({ spec, names, ok: true });
  }

  const facade = await import('hooklatch');
  const cjs = require('hooklatch');

  assert.ok(new facade.HooklatchError('invalid-input', 'x') instanceof cjs.HooklatchError, 'facade instance instanceof CJS HooklatchError');
  assert.ok(new cjs.HooklatchError('invalid-input', 'x') instanceof facade.HooklatchError, 'CJS instance instanceof facade HooklatchError');

  const encoder = new TextEncoder();
  const githubOptions = { provider: 'github', secrets: ["It's a Secret to Everybody"] };
  const githubHeaders = { 'x-hub-signature-256': 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17' };
  const rawBody = new Uint8Array(encoder.encode('Hello, World!'));

  const viaFacade = await facade.verify({ rawBody, headers: githubHeaders }, githubOptions);
  assert.equal(viaFacade.ok, true, 'facade verify github vector');
  assert.deepEqual([...viaFacade.rawBody], [...rawBody], 'facade rawBody bytes');

  const viaCjs = await cjs.verify({ rawBody, headers: githubHeaders }, githubOptions);
  assert.equal(viaCjs.ok, true, 'CJS verify github vector');
  assert.deepEqual([...viaCjs.rawBody], [...rawBody], 'CJS rawBody bytes');

  const verifierCjs = await cjs.createVerifier(githubOptions)({ rawBody, headers: githubHeaders });
  assert.equal(verifierCjs.ok, true, 'CJS createVerifier');
  const verifierFacade = await facade.createVerifier(githubOptions)({ rawBody, headers: githubHeaders });
  assert.equal(verifierFacade.ok, true, 'facade createVerifier');

  const wrappedCjs = await cjs.verifyRequest(new Request('https://example.test', {
    method: 'POST', headers: githubHeaders, body: 'Hello, World!',
  }), githubOptions);
  assert.equal(wrappedCjs.ok, true, 'CJS verifyRequest');

  const wrappedFacade = await facade.verifyRequest(new Request('https://example.test', {
    method: 'POST', headers: githubHeaders, body: 'Hello, World!',
  }), githubOptions);
  assert.equal(wrappedFacade.ok, true, 'facade verifyRequest');

  const tampered = await cjs.verify({ rawBody: encoder.encode('tampered'), headers: githubHeaders }, githubOptions);
  assert.equal(tampered.ok, false, 'tampered rejected');
  assert.equal(tampered.reason, 'invalid-signature', 'tamper reason');
  assert.equal(Object.hasOwn(tampered, 'rawBody'), false, 'failure carries no rawBody');
  assert.equal(Object.hasOwn(tampered, 'identity'), false, 'failure carries no identity');

  const esmRegistry = (await import(pathToFileURL(path.join(root, 'dist', 'providers', 'index.js')).href)).SUPPORTED_PROVIDERS;
  const cjsRegistry = require(path.join(root, 'dist', 'cjs', 'providers', 'index.cjs')).SUPPORTED_PROVIDERS;

  assert.deepEqual(cjsRegistry, EXPECTED_REGISTRY, 'CJS registry matches frozen policy');
  assert.deepEqual(esmRegistry, EXPECTED_REGISTRY, 'ESM registry matches frozen policy');

  const diagnosticsEsm = await import('hooklatch/diagnostics');
  const diagnosticsCjs = require('hooklatch/diagnostics');

  assert.equal(diagnosticsEsm.diagnose, diagnosticsCjs.diagnose, 'diagnose identity across arms');

  const diagnostic = diagnosticsEsm.diagnose({ ok: false, provider: 'clerk', reason: 'invalid-signature', message: CANARY }, { verbose: true });

  assert.equal(diagnostic.code, 'invalid-signature', 'diagnostic code');
  assert.ok(diagnostic.detail.expectedHeaders.includes('svix-signature'), 'diagnostic expected headers');
  assert.ok(!JSON.stringify(diagnostic).includes(CANARY), 'diagnostic output keeps the private canary private');

  const peerIsolation = {};

  for (const peer of ['express', 'hono']) {
    let cjsAbsent = false;

    try {
      require(peer);
    } catch (error) {
      cjsAbsent = errorCodeOfProbe(error) === 'MODULE_NOT_FOUND';
    }

    await assert.rejects(() => import(peer), (error) => errorCodeOfProbe(error) === 'ERR_MODULE_NOT_FOUND');

    peerIsolation[peer] = { cjsAbsent, esmRejected: true };
    assert.ok(cjsAbsent, peer + ' is absent on the require side');
  }

  observations.peerIsolation = peerIsolation;
  observations.registry = { esm: EXPECTED_REGISTRY.length, cjs: EXPECTED_REGISTRY.length, agreed: true };
  observations.diagnostics = { privacy: true };

  return observations;
});

await runPhase('cli', () => {
  const root = requirePkgRoot();
  const installedCli = path.join(root, CLI_RELATIVE);

  assert.ok(existsSync(installedCli), 'installed CLI file exists');

  const help = execFileSync(process.execPath, [installedCli, '--help'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], cwd: root,
  });

  assert.ok(help.includes('Usage: hooklatch'), 'installed CLI prints usage');

  return { helpStart: help.slice(0, 120) };
});

const failed = Object.keys(phases).filter((name) => phases[name].verdict !== 'pass');

console.log(JSON.stringify({ phases, failed }, null, 2));

/* The probe is a REPORTER: it always exits 0 once its complete phase report
 * is on stdout, and the gate classifies the phase verdicts. The gate refuses
 * to accept phases from any child that did not exit 0 cleanly, so a process
 * whose exit code was hijacked (for example by a loaded module registering
 * process.on('beforeExit', ...) with a nonzero code) can never smuggle a
 * passing report through. */
process.exitCode = 0;
`;

/* -------------------------------------------------------------------------- */
/* bounded candidate-registry child (candidate code never runs in the parent) */
/* -------------------------------------------------------------------------- */

const REGISTRY_CHILD_TEMPLATE = `/* Phase11 registry probe child: imports ONE candidate registry module and
 * prints a JSON report. This child ALWAYS exits 0 when its report is
 * emitted (even for a candidate that threw); the gate classifies the report
 * and refuses any child that did not exit cleanly. Candidate module code
 * therefore never executes in the gate parent process. */
import { pathToFileURL } from 'node:url';

const REGISTRY_PATH = ${JSON.stringify('__REGISTRY_PATH__')};

let report = { providers: null, error: null, shape: null };

try {
  const imported = await import(pathToFileURL(REGISTRY_PATH).href);
  const candidates = [imported.SUPPORTED_PROVIDERS, imported.default?.SUPPORTED_PROVIDERS];
  const providers = candidates.find((value) => value !== undefined) ?? null;

  report = { providers, error: null, shape: providers === null ? 'no SUPPORTED_PROVIDERS export' : 'ok' };
} catch (error) {
  const message = Object.prototype.toString.call(error) === '[object Error]'
    ? String(error.message)
    : String(error);

  report = { providers: null, error: message, shape: 'import-threw' };
}

console.log(JSON.stringify(report));

process.exitCode = 0;
`;

const REGISTRY_TIMEOUT_MS = 60_000;

/* -------------------------------------------------------------------------- */
/* neutral bundler + declaration resolution (in-process, after install)       */
/* -------------------------------------------------------------------------- */

/** Path-only check: a neutral esbuild bundle must pick original dist ESM. */
async function runEsbuildNeutralCheck(installRoot, repoRequire) {
  const esbuild = repoRequire('esbuild');
  const entryPath = path.join(installRoot, 'hooklatch-neutral-entry.mjs');

  await writeFile(entryPath, "import { verify } from 'hooklatch';\nimport { diagnose } from 'hooklatch/diagnostics';\nvoid verify; void diagnose;\n", { encoding: 'utf8' });

  const result = await esbuild.build({
    absWorkingDir: installRoot,
    entryPoints: [entryPath],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'neutral',
    metafile: true,
    conditions: [],
    logLevel: 'silent',
  });

  const inputs = Object.keys(result.metafile.inputs).map((input) => input.split(path.sep).join('/'));
  const hooklatchInputs = inputs.filter((input) => input.includes('hooklatch/dist/'));
  const findings = [];

  if (hooklatchInputs.length === 0) {
    findings.push({ kind: 'esbuild-neutral-original-esm', detail: 'neutral bundle did not include any hooklatch dist input', observed: boundedText(JSON.stringify(inputs)) });

    return findings;
  }

  const foreign = [];

  for (const input of hooklatchInputs) {
    if (!input.startsWith('node_modules/hooklatch/dist/') || input.includes('/dist/node/') || input.includes('/dist/cjs/')) {
      foreign.push(input);
    }
  }

  if (foreign.length > 0) {
    findings.push({ kind: 'esbuild-neutral-original-esm', detail: 'neutral bundle selected Node-distribution inputs', observed: foreign });
  }

  let picksIndex = false;

  for (const input of hooklatchInputs) {
    if (input.endsWith('hooklatch/dist/index.js')) picksIndex = true;
  }

  if (!picksIndex) {
    findings.push({ kind: 'esbuild-neutral-original-esm', detail: 'neutral bundle did not pick dist/index.js', observed: hooklatchInputs });
  }

  return findings;
}

/** Actual compiler resolution of declaration targets for one entry/arm. */
function resolveDeclarationArm(ts, specifier, containingFile, arm) {
  const options = arm === 'bundler'
    ? { module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, target: ts.ScriptTarget.ES2022 }
    : { module: ts.ModuleKind.Node16, moduleResolution: ts.ModuleResolutionKind.Node16, target: ts.ScriptTarget.ES2022 };

  /* Node16 standalone resolution does NOT infer the import/require arm from
   * the containing file extension (measured on typescript 6.0.3: an .mts
   * consumer still resolves the require-arm types). Pass the resolution mode
   * explicitly: ESNext for the import arm, CommonJS for the require arm. */
  const resolutionMode = arm === 'import'
    ? ts.ModuleKind.ESNext
    : arm === 'require' ? ts.ModuleKind.CommonJS : undefined;

  const result = ts.resolveModuleName(specifier, containingFile, options, ts.sys, undefined, undefined, resolutionMode);

  if (result.resolvedModule === undefined) return null;

  return result.resolvedModule.resolvedFileName;
}

/** Actual compiler resolution checks over the installed tree. */
function runDeclarationResolutionChecks(installRoot, repoRequire) {
  const ts = repoRequire('typescript');
  const findings = [];
  const installedPkg = path.join(installRoot, 'node_modules', 'hooklatch');

  for (const [specifier, base] of POLICY_PUBLIC_ENTRIES) {
    const packageSpec = packageSpecifierOf(specifier);

    const expectedByArm = [
      ['import', path.join(installedPkg, 'dist', 'node', `${base}.d.ts`)],
      ['require', path.join(installedPkg, 'dist', 'cjs', `${base}.d.cts`)],
      ['bundler', path.join(installedPkg, 'dist', `${base}.d.ts`)],
    ];

    for (const [arm, expectedAbsolute] of expectedByArm) {
      const containingFile = path.join(installRoot, arm === 'require' ? 'consumer.cts' : 'consumer.mts');
      const observed = resolveDeclarationArm(ts, packageSpec, containingFile, arm);
      const expectedPosix = expectedAbsolute.split(path.sep).join('/');
      const observedPosix = observed === null ? null : observed.split(path.sep).join('/');

      if (observedPosix !== expectedPosix) {
        findings.push({ kind: 'declaration-resolution', arm, specifier: packageSpec, expected: expectedPosix, observed: observedPosix });
      }
    }
  }

  for (const arm of ['import', 'bundler']) {
    const containingFile = path.join(installRoot, 'consumer.mts');
    const observed = resolveDeclarationArm(ts, 'hooklatch/dist/index.js', containingFile, arm);

    if (observed !== null) {
      findings.push({ kind: 'declaration-resolution', arm, specifier: 'hooklatch/dist/index.js', expected: 'unresolved', observed });
    }
  }

  return findings;
}

/* -------------------------------------------------------------------------- */
/* integrity snapshot (tracked files + dist)                                  */
/* -------------------------------------------------------------------------- */

function listTrackedFiles(repoRoot) {
  const result = spawnSync('git', ['ls-files', '-z'], {
    cwd: repoRoot, encoding: 'buffer', timeout: GIT_TIMEOUT_MS, windowsHide: true,
  });

  if (result.error !== undefined || result.status !== 0) {
    throw new InfrastructureError(`git ls-files failed: ${boundedText(String(result.stderr ?? result.error ?? ''))}`);
  }

  const names = [];

  for (const chunk of result.stdout.toString('utf8').split('\0')) {
    if (chunk !== '') names.push(chunk.split(path.sep).join('/'));
  }

  return names;
}

function walkFiles(rootDir, prefix) {
  const names = [];

  for (const entry of readdirSync(rootDir, { withFileTypes: true })) {
    const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;

    if (entry.isDirectory()) {
      names.push(...walkFiles(path.join(rootDir, entry.name), rel));
      continue;
    }

    if (entry.isFile()) names.push(rel);
  }

  return names;
}

function snapshotHashes(repoRoot, relList) {
  const snapshot = new Map();

  for (const rel of relList) {
    const absolute = path.join(repoRoot, rel);

    if (!existsSync(absolute) || !statSync(absolute).isFile()) {
      snapshot.set(rel, '<absent>');
      continue;
    }

    snapshot.set(rel, sha256Buffer(readFileSync(absolute)));
  }

  return snapshot;
}

function diffSnapshots(before, after) {
  const changes = [];

  for (const [rel, sha] of before.entries()) {
    const observed = after.get(rel);

    if (observed === sha) continue;

    /* snapshotHashes records a listed file that vanished from disk as an
     * '<absent>' marker, so a deletion of a tracked file arrives as
     * '<absent>' (git ls-files still lists it) rather than as a missing
     * key. Both forms are a REMOVAL, never a modification: the file no
     * longer has the bytes it had. A file that APPEARS during the run
     * (before '<absent>' or not listed) is an addition. */
    if (observed === undefined || observed === '<absent>') {
      if (sha !== '<absent>') changes.push({ path: rel, change: 'removed' });

      continue;
    }

    if (sha === '<absent>') {
      changes.push({ path: rel, change: 'added' });

      continue;
    }

    changes.push({ path: rel, change: 'modified' });
  }

  for (const rel of after.keys()) {
    if (!before.has(rel)) changes.push({ path: rel, change: 'added' });
  }

  return changes;
}

/* -------------------------------------------------------------------------- */
/* CLI usage                                                                  */
/* -------------------------------------------------------------------------- */

function usageText() {
  return `package-contract: Phase11 conditional-exports and installed-tarball contract gate

Usage:
  node scripts/phase11/package-contract.mjs --help
  node scripts/phase11/package-contract.mjs --self-test
  node scripts/phase11/package-contract.mjs --tarball FILE [--results FILE]
  node scripts/phase11/package-contract.mjs [--results FILE]

Flags:
  --help          print this message (exit 0)
  --self-test     run embedded policy/parser/shape controls only; no tarball,
                  temp allocation, install or runtime dispatch (exit 0 on
                  success; the output is labeled controls-only)
  --tarball FILE  qualify exactly that candidate tarball
  --results FILE  additionally write the machine report to FILE. Refused
                  (exit 2) when the destination already exists, an ancestor
                  is a symbolic link, the path is a tracked file, or it
                  matches the session-claim pattern
                  notes/**/*-session.json; the final write is exclusive (wx)
                  and happens only for PASS results, after cleanup and
                  integrity verification.

Default (no --tarball): pack the ACTUAL built checkout with
npm pack --json --ignore-scripts --offline --cache <isolated-temp-cache>
(pack lifecycle scripts cannot run) and qualify that tarball; the seed
candidate is never used implicitly. Missing canonical dist/cjs + dist/node
graphs or missing conditional exports in package.json is BLOCKED (exit 3)
before temp allocation, packing, installation or runtime dispatch. A BLOCKED
result is never a pass.

Exit codes: 0 PASS, 1 RED (check findings), 2 USAGE, 3 BLOCKED prerequisites.

Preparation: run \`npm run build\` first so the checkout dist tree exists for
the original-ESM baseline pin. Host tools must include git, system tar, the
npm CLI, and repo-local typescript + esbuild (this gate installs nothing).`;
}

/* -------------------------------------------------------------------------- */
/* guarded CLI                                                                */
/* -------------------------------------------------------------------------- */

const invokedDirectly = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

function parseFlags(argv) {
  const parsed = { help: false, selfTest: false, tarball: null, results: null, error: null };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];

    if (flag === '--help') {
      parsed.help = true;
      continue;
    }

    if (flag === '--self-test') {
      parsed.selfTest = true;
      continue;
    }

    if (flag === '--tarball') {
      const value = argv[index + 1];

      if (value === undefined) {
        parsed.error = '--tarball requires a FILE argument';

        return parsed;
      }

      parsed.tarball = value;
      index += 1;
      continue;
    }

    if (flag === '--results') {
      const value = argv[index + 1];

      if (value === undefined) {
        parsed.error = '--results requires a FILE argument';

        return parsed;
      }

      parsed.results = value;
      index += 1;
      continue;
    }

    parsed.error = `unknown argument ${JSON.stringify(flag)}`;

    return parsed;
  }

  if (parsed.selfTest && parsed.tarball !== null) {
    parsed.error = '--self-test cannot be combined with --tarball';
  }

  return parsed;
}

/** Run the embedded self-test battery (controls-only; no I/O side effects). */
function runSelfTest() {
  const controls = [];

  const record = (name, fn) => {
    try {
      fn();
      controls.push({ name, verdict: 'pass', detail: '' });
    } catch (error) {
      controls.push({ name, verdict: 'fail', detail: boundedText(error instanceof Error ? error.message : error) });
    }
  };

  const clone = (value) => JSON.parse(JSON.stringify(value));

  const validManifest = {
    type: 'module',
    engines: { node: '>=22' },
    main: './dist/cjs/index.cjs',
    types: './dist/index.d.ts',
    bin: { hooklatch: './dist/cli/index.js' },
    dependencies: {},
    peerDependencies: { express: '^4.18.0 || ^5.0.0', hono: '^4.0.0' },
    peerDependenciesMeta: { express: { optional: true }, hono: { optional: true } },
    exports: clone(EXPECTED_NESTED_EXPORTS),
  };

  record('policy-self-consistency', () => {
    assertPolicySelfConsistency();
  });

  record('structure-exact-green', () => {
    const findings = runStructureExactChecks(validManifest);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('structure-exact-detects-top-order-swap', () => {
    const drifted = clone(validManifest);

    drifted.exports['.'] = {
      types: './dist/index.d.ts',
      node: {
        import: { types: './dist/node/index.d.ts', default: './dist/node/index.js' },
        require: { types: './dist/cjs/index.d.cts', default: './dist/cjs/index.cjs' },
      },
      import: './dist/index.js',
      default: './dist/index.js',
    };

    const findings = runStructureExactChecks(drifted);

    if (findings.length !== 1 || findings[0].kind !== 'exports-structure-exact') {
      throw new Error(`expected one exports-structure-exact finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('structure-exact-detects-import-key-swap', () => {
    const drifted = clone(validManifest);

    drifted.exports['.'].node.import = {
      default: './dist/node/index.js',
      types: './dist/node/index.d.ts',
    };

    const findings = runStructureExactChecks(drifted);

    if (findings.length !== 1 || findings[0].kind !== 'exports-structure-exact') {
      throw new Error(`expected one exports-structure-exact finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('entry-shape-green', () => {
    const findings = runExportEntryChecks(validManifest);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('entry-shape-detects-missing-dcts-target', () => {
    const drifted = clone(validManifest);

    drifted.exports['./express'].node.require.types = './dist/cjs/adapters/express.d.ts';

    const findings = runExportEntryChecks(drifted);
    const matched = findings.some((finding) => finding.kind === 'exports-entry-shape' && finding.key === 'node.require.types');

    if (!matched) throw new Error(`expected node.require.types finding, got ${JSON.stringify(findings)}`);
  });

  record('entry-shape-detects-node-types-shadow', () => {
    const drifted = clone(validManifest);

    drifted.exports['.'].node = {
      types: './dist/index.d.ts',
      import: { types: './dist/node/index.d.ts', default: './dist/node/index.js' },
      require: { types: './dist/cjs/index.d.cts', default: './dist/cjs/index.cjs' },
    };

    const findings = runExportEntryChecks(drifted);

    if (findings.length < 1) throw new Error(`expected findings for shadowed node condition, got ${JSON.stringify(findings)}`);
  });

  record('entries-sync-green', () => {
    const findings = runPublicEntriesSyncChecks(validManifest);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('entries-sync-detects-additional-subpath', () => {
    const drifted = clone(validManifest);

    drifted.exports['./secret'] = clone(validManifest.exports['./diagnostics']);

    const findings = runPublicEntriesSyncChecks(drifted);

    if (findings.length !== 1 || findings[0].kind !== 'public-entries-manifest-only' || findings[0].specifiers[0] !== './secret') {
      throw new Error(`expected public-entries-manifest-only ['./secret'], got ${JSON.stringify(findings)}`);
    }
  });

  record('entries-sync-detects-omitted-entry', () => {
    const drifted = clone(validManifest);

    delete drifted.exports['./hono'];

    const findings = runPublicEntriesSyncChecks(drifted);

    if (findings.length !== 1 || findings[0].kind !== 'public-entries-policy-only' || findings[0].specifiers[0] !== './hono') {
      throw new Error(`expected public-entries-policy-only ['./hono'], got ${JSON.stringify(findings)}`);
    }
  });

  record('manifest-fields-green', () => {
    const findings = runManifestFieldChecks(validManifest);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('manifest-fields-detects-wrong-main', () => {
    const drifted = clone(validManifest);

    drifted.main = './dist/index.js';

    const findings = runManifestFieldChecks(drifted);

    if (findings.length !== 1 || findings[0].field !== 'main') {
      throw new Error(`expected one main finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('manifest-fields-detects-dependency', () => {
    const drifted = clone(validManifest);

    drifted.dependencies = { express: '^4.0.0' };

    const findings = runManifestFieldChecks(drifted);

    if (findings.length !== 1 || findings[0].field !== 'dependencies') {
      throw new Error(`expected one dependencies finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('manifest-fields-detects-peer-meta-leak', () => {
    const drifted = clone(validManifest);

    drifted.peerDependenciesMeta.express.optional = false;

    const findings = runManifestFieldChecks(drifted);

    if (findings.length !== 1 || findings[0].field !== 'peerDependenciesMeta') {
      throw new Error(`expected one peerDependenciesMeta finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('registry-checks-green', () => {
    const findings = runProviderRegistryChecks([...POLICY_PROVIDERS]);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('registry-checks-detects-omitted-fal', () => {
    const findings = runProviderRegistryChecks(POLICY_PROVIDERS.slice(0, 20));

    if (findings.length !== 1 || findings[0].kind !== 'provider-registry-missing' || findings[0].ids[0] !== 'fal') {
      throw new Error(`expected provider-registry-missing ['fal'], got ${JSON.stringify(findings)}`);
    }
  });

  record('registry-checks-detects-duplicated-polar', () => {
    const drifted = [...POLICY_PROVIDERS];

    drifted.splice(drifted.indexOf('polar'), 0, 'polar');

    const findings = runProviderRegistryChecks(drifted);

    if (findings.length !== 1 || findings[0].kind !== 'provider-registry-duplicate' || findings[0].ids[0] !== 'polar') {
      throw new Error(`expected provider-registry-duplicate ['polar'], got ${JSON.stringify(findings)}`);
    }
  });

  record('registry-checks-detects-unknown-provider', () => {
    const findings = runProviderRegistryChecks([...POLICY_PROVIDERS, 'acme']);

    if (findings.length !== 1 || findings[0].kind !== 'provider-registry-unknown' || findings[0].ids[0] !== 'acme') {
      throw new Error(`expected provider-registry-unknown ['acme'], got ${JSON.stringify(findings)}`);
    }
  });

  record('targets-presence-green', () => {
    const findings = runTargetPresenceChecks(referencedTargets().map((target) => target.slice('./'.length)));

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('targets-presence-detects-missing-member', () => {
    const members = referencedTargets().map((target) => target.slice('./'.length)).filter((rel) => rel !== 'dist/cjs/adapters/express.d.cts');
    const findings = runTargetPresenceChecks(members);

    if (findings.length !== 1 || findings[0].target !== './dist/cjs/adapters/express.d.cts') {
      throw new Error(`expected one missing-target finding, got ${JSON.stringify(findings)}`);
    }
  });

  record('member-checks-green', () => {
    const findings = runMemberChecks(['package.json', 'README.md', 'dist/index.js', 'dist/cjs/index.cjs', 'dist/node/index.js']);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('member-checks-detects-forbidden-paths', () => {
    const seeded = ['src/index.ts', 'tests/unit.js', 'notes/x.md', 'tasks/y.md', 'dist/internal/credentials.json', 'source-temp/a.js', 'node_modules/express/index.js', '.git/config'];
    const findings = runMemberChecks(seeded);

    if (findings.length !== seeded.length) {
      throw new Error(`expected ${seeded.length} findings, got ${JSON.stringify(findings)}`);
    }
  });

  record('pin-comparator-green', () => {
    const findings = compareBaselinePins(
      [{ rel: 'dist/index.js', sha256: 'aa' }, { rel: 'dist/cli/index.js', sha256: 'bb' }],
      [{ rel: 'dist/index.js', sha256: 'aa' }, { rel: 'dist/cli/index.js', sha256: 'bb' }],
    );

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('pin-comparator-detects-drift', () => {
    const findings = compareBaselinePins(
      [{ rel: 'dist/index.js', sha256: 'aa' }, { rel: 'dist/cli/index.js', sha256: 'bb' }],
      [{ rel: 'dist/index.js', sha256: 'cc' }, { rel: 'dist/core.js', sha256: 'dd' }],
    );

    const kinds = findings.map((finding) => finding.kind).sort();

    if (JSON.stringify(kinds) !== JSON.stringify([
      'baseline-pin-hash-mismatch',
      'baseline-pin-missing-in-checkout',
      'baseline-pin-missing-in-tarball',
    ])) {
      throw new Error(`expected mismatch plus both missing-direction findings, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-green', () => {
    const entries = [
      { rel: 'dist/cjs/index.cjs', text: 'const core = require("./core.cjs");\nconst errors = require("./errors.cjs");\n' },
      { rel: 'dist/cjs/core.cjs', text: 'const errors = require("./errors.cjs");\n' },
      { rel: 'dist/node/index.js', text: 'import implementation from "../cjs/index.cjs";\nexport const verify = implementation.verify;\n' },
      { rel: 'dist/cjs/adapters/express.d.cts', text: "import type { RequestHandler } from 'express';\nimport type { VerifyOptions } from '../types.cjs';\n" },
    ];

    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('graph-edges-detects-bare-require', () => {
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'require("express");\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-bare') {
      throw new Error(`expected cjs-edge-bare, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-detects-esm-fallback', () => {
    const entries = [{ rel: 'dist/cjs/index.cjs', text: 'require("../index.js");\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-escapes-cjs') {
      throw new Error(`expected cjs-edge-escapes-cjs, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-detects-js-specifier', () => {
    const entries = [{ rel: 'dist/cjs/index.cjs', text: 'require("./core.js");\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-js-specifier') {
      throw new Error(`expected cjs-edge-js-specifier, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-dynamic-import-js-specifier', () => {
    /* The blanket cjs-dynamic-import kind is REMOVED: a literal dynamic
     * import() of an in-graph-relative specifier is validated like any other
     * edge; a .js specifier is still an unrewritten ESM edge. */
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'await import("./missing.js");\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-js-specifier') {
      throw new Error(`expected cjs-edge-js-specifier for a literal dynamic import, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-spaced-require-detected', () => {
    /* `require ( 'express' )` with whitespace must still be caught: the
     * scanner walks real AST call nodes, not a `require\(` regex. */
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'require ( \'express\' );\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-bare') {
      throw new Error(`expected cjs-edge-bare for spaced require, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-spaced-dynamic-import-detected', () => {
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'await import ( "./core.js" );\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-js-specifier') {
      throw new Error(`expected cjs-edge-js-specifier for spaced dynamic import, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-detects-unprovable-dynamic-import', () => {
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'const name = "./x.cjs";\nawait import(name);\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-unprovable' || findings[0].specifier !== undefined) {
      throw new Error(`expected one cjs-edge-unprovable finding without a specifier, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-no-comment-or-string-false-positives', () => {
    const entries = [{
      rel: 'dist/cjs/core.cjs',
      text: '/* require("./absent.cjs"); */\nconst hint = "require(\\"./absent.cjs\\")";\n// await import("./absent.cjs")\nconst edge = `import("./absent.cjs")`;\nconst real = require("./core.cjs");\n',
    }];

    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 0) {
      throw new Error(`expected zero findings for commented/string payloads, got ${JSON.stringify(findings)}`);
    }
  });

  record('graph-edges-detects-esm-syntax-in-cjs', () => {
    const entries = [{ rel: 'dist/cjs/core.cjs', text: 'import extra from "./extra.cjs";\nmodule.exports = {};\n' }];
    const findings = runGraphEdgeChecks(entries);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-esm-syntax') {
      throw new Error(`expected cjs-esm-syntax for an import declaration in a .cjs file, got ${JSON.stringify(findings)}`);
    }
  });

  record('edge-resolution-detects-missing-import-type', () => {
    /* Declaration edges collected from real ImportTypeNodes: a dynamic
     * import-type of an absent .cjs member must be unresolved. */
    const members = ['dist/cjs/index.cjs', 'dist/cjs/internal/provider.cjs'];

    const entries = [{
      rel: 'dist/cjs/providers/demo.d.cts',
      text: 'type P = import("../internal/provider.cjs").ProviderDescriptor;\ntype Q = import("../internal/absent.cjs").Other;\n',
    }];

    const findings = runEdgeResolutionChecks(entries, members);

    if (findings.length !== 1 || findings[0].kind !== 'declaration-edge-unresolved' || findings[0].specifier !== '../internal/absent.cjs') {
      throw new Error(`expected declaration-edge-unresolved for the absent import-type, got ${JSON.stringify(findings)}`);
    }
  });

  record('member-type-checks-detect-links-devices-fifos', () => {
    const pairs = [
      { name: 'package/file.txt', typeChar: '-', linkText: false },
      { name: 'package', typeChar: 'd', linkText: false },
      { name: 'package/link.txt', typeChar: 'l', linkText: true },
      { name: 'package/hard.txt', typeChar: 'h', linkText: true },
      { name: 'package/quiet-link.txt', typeChar: '-', linkText: true },
      { name: 'package/dev.txt', typeChar: 'c', linkText: false },
      { name: 'package/fifo.txt', typeChar: 'p', linkText: false },
    ];

    const findings = runMemberTypeChecks(pairs);
    const kinds = findings.map((finding) => finding.kind).sort();

    if (JSON.stringify(kinds) !== JSON.stringify([
      'tarball-member-link',
      'tarball-member-link',
      'tarball-member-link',
      'tarball-member-type',
      'tarball-member-type',
    ])) {
      throw new Error(`expected three link and two type findings, got ${JSON.stringify(findings)}`);
    }
  });

  record('member-type-checks-green-plain-members', () => {
    const pairs = [
      { name: 'package/file.txt', typeChar: '-', linkText: false },
      { name: 'package/sub', typeChar: 'd', linkText: false },
    ];

    const findings = runMemberTypeChecks(pairs);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('member-duplicate-checks-detect-duplicates', () => {
    const findings = runMemberDuplicateChecks(['package/a.txt', 'package/b.txt', 'package/a.txt', 'package/a.txt']);

    if (findings.length !== 1 || findings[0].path !== 'package/a.txt') {
      throw new Error(`expected one duplicate finding for package/a.txt, got ${JSON.stringify(findings)}`);
    }
  });

  record('manifest-fields-reject-optional-and-bundled-deps', () => {
    const withOptional = { ...validManifest, optionalDependencies: { lodash: '^4.0.0' } };
    const withBundled = { ...validManifest, bundledDependencies: ['lodash'] };
    const emptyOptional = { ...validManifest, optionalDependencies: {} };
    const emptyBundledArray = { ...validManifest, bundledDependencies: [] };

    const optionalFindings = runManifestFieldChecks(withOptional);
    const bundledFindings = runManifestFieldChecks(withBundled);
    const emptyFindings = [...runManifestFieldChecks(emptyOptional), ...runManifestFieldChecks(emptyBundledArray)];

    if (optionalFindings.length !== 1 || optionalFindings[0].field !== 'optionalDependencies') {
      throw new Error(`expected one optionalDependencies finding, got ${JSON.stringify(optionalFindings)}`);
    }

    if (bundledFindings.length !== 1 || bundledFindings[0].field !== 'bundledDependencies') {
      throw new Error(`expected one bundledDependencies finding, got ${JSON.stringify(bundledFindings)}`);
    }

    if (emptyFindings.length !== 0) {
      throw new Error(`expected empty optional/bundled declarations to pass, got ${JSON.stringify(emptyFindings)}`);
    }
  });

  record('declaration-edges-allow-peers-only', () => {
    const entries = [
      { rel: 'dist/cjs/adapters/other.d.cts', text: "import type { Thing } from 'lodash';\n" },
      { rel: 'dist/node/index.d.ts', text: "export * from \"../cjs/index.cjs\";\nimport type {X} from '../index.js';\n" },
      { rel: 'dist/cjs/index.d.cts', text: 'export * from "./core.js";\n' },
    ];

    const findings = runGraphEdgeChecks(entries);

    const kinds = findings.map((finding) => finding.kind).sort();

    if (JSON.stringify(kinds) !== JSON.stringify([
      'declaration-edge-bare-non-peer',
      'declaration-edge-escapes-cjs',
      'declaration-edge-non-cjs',
    ])) {
      throw new Error(`expected bare-non-peer, escapes-cjs and non-cjs findings, got ${JSON.stringify(findings)}`);
    }
  });

  record('edge-resolution-detects-missing-target', () => {
    const members = ['dist/cjs/index.cjs', 'dist/cjs/core.cjs'];
    const entries = [{ rel: 'dist/cjs/index.cjs', text: 'require("./absent.cjs");\n' }];
    const findings = runEdgeResolutionChecks(entries, members);

    if (findings.length !== 1 || findings[0].kind !== 'cjs-edge-unresolved') {
      throw new Error(`expected cjs-edge-unresolved, got ${JSON.stringify(findings)}`);
    }
  });

  record('facade-shape-green', () => {
    const texts = new Map();

    /* Root facade uses a hand-pinned specifier literal; the nested facades
     * (adapters/...) derive theirs. Both shapes must be accepted exactly. */
    for (const [, base, names] of POLICY_PUBLIC_ENTRIES) {
      const specifier = base === 'index'
        ? '../cjs/index.cjs'
        : path.posix.relative(path.posix.dirname(`dist/node/${base}.js`), `dist/cjs/${base}.cjs`);

      texts.set(`dist/node/${base}.js`, `import implementation from "${specifier}";\n${names.map((name) => `export const ${name} = implementation.${name};`).join('\n')}\n`);
      texts.set(`dist/node/${base}.d.ts`, `export * from "${specifier}";\n`);
    }

    const findings = runFacadeModuleChecks(texts);

    if (findings.length !== 0) throw new Error(`expected zero findings, got ${JSON.stringify(findings)}`);
  });

  record('facade-shape-detects-broken-export', () => {
    const texts = new Map();
    const expectedSpecifier = path.posix.join(path.posix.relative('dist/node', 'dist/cjs'), 'index.cjs');

    texts.set('dist/node/index.js', `import implementation from "${expectedSpecifier}";\nexport const HooklatchError = implementation.HooklatchError;\n`);
    texts.set('dist/node/index.d.ts', `export * from "${expectedSpecifier}";\n`);

    const findings = runFacadeModuleChecks(texts);
    const missingNames = findings.filter((finding) => finding.kind === 'facade-shape-export-line');

    if (missingNames.length !== 3) {
      throw new Error(`expected three missing export-line findings, got ${JSON.stringify(findings)}`);
    }
  });

  record('cli-shebang-check', () => {
    const good = runCliShebangCheck('#!/usr/bin/env node\nrest');
    const bad = runCliShebangCheck('node -e');

    if (good.length !== 0 || bad.length !== 1) {
      throw new Error(`expected shebang pass and one failure, got ${JSON.stringify(good)} / ${JSON.stringify(bad)}`);
    }
  });

  const failed = controls.filter((control) => control.verdict !== 'pass');

  return { controls, failedCount: failed.length };
}

/* -------------------------------------------------------------------------- */
/* main (guarded CLI)                                                         */
/* -------------------------------------------------------------------------- */

function statOrNull(p) {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}

/**
 * Validate the --results destination BEFORE any measurement (caller misuse
 * exits 2). The final entry must not exist; every existing ancestor must be
 * a real directory, never a symbolic link (lstat walk, so a link ancestor
 * cannot redirect the write); the destination must not be a tracked file;
 * and it must not match the session-claim pattern notes/(...)-session.json
 * (any depth under notes/ whose name ends with -session.json). Every
 * rejection is a thrown UsageError. The final write is still created
 * exclusively (`wx`), making this a linear check rather than a race-free
 * sandbox; that limit is documented.
 */
function validateResultsDestination(rawResults, repoRoot) {
  const dest = path.resolve(rawResults);
  const finalStat = statOrNull(dest);

  if (finalStat !== null) {
    throw new UsageError(finalStat.isSymbolicLink()
      ? `destination exists and is a symbolic link: ${dest}`
      : `destination already exists: ${dest}`);
  }

  let ancestor = path.dirname(dest);

  while (ancestor !== path.dirname(ancestor)) {
    const ancestorStat = statOrNull(ancestor);

    if (ancestorStat !== null) {
      if (ancestorStat.isSymbolicLink()) {
        throw new UsageError(`results ancestor is a symbolic link: ${ancestor}`);
      }

      if (!ancestorStat.isDirectory()) {
        throw new UsageError(`results ancestor is not a directory: ${ancestor}`);
      }
    }

    ancestor = path.dirname(ancestor);
  }

  let trackedNames;

  try {
    trackedNames = new Set(listTrackedFiles(repoRoot));
  } catch (trackedError) {
    throw new UsageError(`cannot verify tracked state (${boundedText(trackedError instanceof Error ? trackedError.message : trackedError)})`);
  }

  const repoPrefix = repoRoot.endsWith(path.sep) ? repoRoot : `${repoRoot}${path.sep}`;
  const insideRepo = dest.startsWith(repoPrefix);

  if (!insideRepo && path.dirname(dest) !== path.resolve(repoRoot)) return null;

  const relative = insideRepo
    ? dest.slice(repoPrefix.length).split(path.sep).join('/')
    : path.basename(dest);

  if (trackedNames.has(relative)) {
    throw new UsageError(`results destination is a tracked file: ${relative}`);
  }

  if (relative.startsWith('notes/') && relative.endsWith('-session.json')) {
    throw new UsageError(`results destination matches the session-claim pattern (notes/(...)-session.json): ${relative}`);
  }

  return null;
}

async function main() {
  const args = parseFlags(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(`${usageText()}\n`);
    process.exitCode = EXIT.PASS;

    return;
  }

  if (args.error !== null) {
    process.stderr.write(`package-contract: ${args.error}\n`);
    process.exitCode = EXIT.USAGE;

    return;
  }

  if (args.selfTest) {
    const selfTest = runSelfTest();
    const status = selfTest.failedCount === 0 ? 'pass' : 'fail';

    console.log(JSON.stringify({
      schemaVersion: 1,
      gate: 'phase11-package-contract',
      mode: 'self-test',
      controlsOnly: true,
      status,
      exit: status === 'pass' ? EXIT.PASS : EXIT.RED,
      summary: {
        controls: selfTest.controls.length,
        passed: selfTest.controls.length - selfTest.failedCount,
        failed: selfTest.failedCount,
        note: 'controls-only: no tarball, temp allocation, installation or runtime dispatch was performed',
      },
      controls: selfTest.controls,
    }, null, 2));

    process.exitCode = status === 'pass' ? EXIT.PASS : EXIT.RED;

    return;
  }

  const repoRoot = path.resolve(import.meta.dirname, '..', '..');
  const blockedReasons = [];

  const npmCli = locateNpmCli();

  if (npmCli === null) {
    blockedReasons.push('npm CLI unavailable: neither npm_execpath nor the node installation provides npm-cli.js');
  }

  let repoRequire = null;

  try {
    repoRequire = createRequire(pathToFileURL(path.join(repoRoot, 'package.json')).href);
    repoRequire('typescript');
    repoRequire('esbuild');
  } catch {
    blockedReasons.push('repo-local typescript or esbuild is not resolvable from package.json; run npm install in a normal checkout (this gate installs nothing)');
  }

  try {
    listTrackedFiles(repoRoot);
  } catch (error) {
    blockedReasons.push(`git is unavailable or the checkout is not a git tree: ${boundedText(error instanceof Error ? error.message : error)}`);
  }

  try {
    await runCapture('tar', ['--version'], { cwd: repoRoot, timeout: TAR_TIMEOUT_MS, label: 'tar --version (prerequisite)' });
  } catch (error) {
    blockedReasons.push(`system tar is unavailable: ${boundedText(error instanceof Error ? error.message : error)}`);
  }

  if (!existsSync(path.join(repoRoot, 'dist', 'index.js'))) {
    blockedReasons.push('missing host checkout dist/index.js; run npm run build first (baseline-pin prerequisite)');
  }

  let tarballPath = args.tarball;
  let tarballIdentity = null;
  const explicitTarballMode = tarballPath !== null;

  if (tarballPath !== null) {
    const tarballStat = statOrNull(tarballPath);

    if (tarballStat === null || !tarballStat.isFile()) {
      process.stderr.write(`package-contract: --tarball path is not an existing file: ${tarballPath}\n`);
      process.exitCode = EXIT.USAGE;

      return;
    }

    tarballIdentity = { path: tarballPath, sha256: sha256Buffer(readFileSync(tarballPath)), bytes: tarballStat.size };
  } else {
    const manifestPath = path.join(repoRoot, 'package.json');

    if (!existsSync(manifestPath)) {
      blockedReasons.push('host checkout has no package.json');
    } else {
      let defaultManifest = null;

      try {
        defaultManifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      } catch (parseError) {
        defaultManifest = null;
        blockedReasons.push(`host package.json does not parse: ${boundedText(parseError instanceof Error ? parseError.message : parseError)}`);
      }

      const rootEntry = defaultManifest !== null && isPlainRecord(defaultManifest.exports) ? defaultManifest.exports['.'] : undefined;

      const hasConditional = isPlainRecord(rootEntry)
        && isPlainRecord(rootEntry.node)
        && isPlainRecord(rootEntry.node.import)
        && isPlainRecord(rootEntry.node.require);

      if (!hasConditional) {
        blockedReasons.push('host package.json does not yet declare the conditional exports["."] with node import/require arms (integration pending)');
      }

      if (!existsSync(path.join(repoRoot, 'dist', 'cjs', 'index.cjs'))) {
        blockedReasons.push('missing dist/cjs/index.cjs (canonical Node CJS graph not built yet)');
      }

      if (!existsSync(path.join(repoRoot, 'dist', 'node', 'index.js'))) {
        blockedReasons.push('missing dist/node/index.js (Node ESM facade not built yet)');
      }
    }
  }

  if (args.results !== null) {
    try {
      validateResultsDestination(args.results, repoRoot);
    } catch (resultsError) {
      if (!(resultsError instanceof UsageError)) throw resultsError;

      process.stderr.write(`package-contract: --results rejected: ${resultsError.message}\n`);
      process.exitCode = EXIT.USAGE;

      return;
    }

    if (tarballPath !== null && path.resolve(args.results) === path.resolve(tarballPath)) {
      process.stderr.write('package-contract: --results must not point at the tarball being qualified\n');
      process.exitCode = EXIT.USAGE;

      return;
    }
  }

  if (blockedReasons.length > 0) {
    console.log(JSON.stringify({
      schemaVersion: 1,
      gate: 'phase11-package-contract',
      mode: tarballPath === null ? 'default' : 'tarball',
      controlsOnly: false,
      status: 'blocked',
      exit: EXIT.BLOCKED,
      reason: blockedReasons.join('; '),
      note: 'no temp allocation, extraction, packing, installation or runtime dispatch was performed',
      checks: [],
      cleanup: { attempted: false, verified: true, cleanupSafe: true },
      integrity: { sampled: false, note: 'blocked before measurement' },
    }, null, 2));

    process.exitCode = EXIT.BLOCKED;

    return;
  }

  /* ------------------------- measured run ------------------------------- */

  const checks = [];
  const findings = [];

  const recordCheck = async (id, fn) => {
    try {
      const outcome = await fn();

      if (outcome !== undefined && outcome !== null && outcome.notRun === true) {
        checks.push({ id, verdict: 'not-run', detail: outcome.detail ?? '', evidence: outcome.finding ?? null });

        return;
      }

      const granular = Array.isArray(outcome) ? outcome : [];

      if (granular.length > 0) {
        checks.push({ id, verdict: 'fail', detail: `${granular.length} finding(s)`, evidence: granular });
        findings.push(...granular);

        return;
      }

      checks.push({ id, verdict: 'pass', detail: '' });
    } catch (error) {
      const isError = error instanceof Error;
      const notRun = isError && Object.hasOwn(error, 'notRun');

      const finding = isError && Object.hasOwn(error, 'finding') && isPlainRecord(error.finding)
        ? error.finding
        : { kind: id, detail: boundedText(isError ? error.message : error) };

      checks.push({ id, verdict: notRun ? 'not-run' : 'fail', detail: notRun ? `not run: ${boundedText(finding.detail ?? '')}` : boundedText(error instanceof Error ? error.message : error), evidence: finding });
      findings.push(finding);
    }
  };

  let before = null;
  let tempRoot = null;
  let cleanupVerified = false;
  let infraError = null;

  try {
    /* SYMMETRIC integrity scope (fix for the asymmetric presnapshot): the
     * BEFORE snapshot covers tracked files plus the FULL built dist tree
     * (original ESM and additive dist/cjs + dist/node) with exactly the
     * same rules as the AFTER snapshot, so an unchanged additive file can
     * never be misreported as an addition in a ready checkout. The
     * original-ESM baseline comparison remains a SEPARATE check
     * (original-esm-baseline-pin). */
    const trackedList = listTrackedFiles(repoRoot);
    const distList = walkFiles(path.join(repoRoot, 'dist'), 'dist');
    before = snapshotHashes(repoRoot, [...new Set([...trackedList, ...distList])]);
  } catch (snapshotError) {
    infraError = `integrity presnapshot failed: ${boundedText(snapshotError instanceof Error ? snapshotError.message : snapshotError)}`;
  }

  if (before !== null) {
    try {
      tempRoot = await mkdtemp(path.join(tmpdir(), 'hooklatch-phase11-contract-'));

      const extractDir = path.join(tempRoot, 'extract');
      const packageDir = path.join(extractDir, 'package');
      const installRoot = path.join(tempRoot, 'consumer');
      const npmCacheDir = path.join(tempRoot, 'npm-cache');

      await mkdir(extractDir, { recursive: true });
      await mkdir(installRoot, { recursive: true });

      if (tarballPath === null) {
        /* Default mode packs the REAL checkout with the hardened command:
         * lifecycle scripts (prepack/postpack/prepare) cannot run and the
         * pack cache is isolated inside the run's own temp root, so a
         * candidate cannot execute code or reuse a shared cache during
         * packing. The command is recorded in report.environment. */
        const packCacheDir = path.join(tempRoot, 'pack-cache');

        await mkdir(packCacheDir, { recursive: true });

        const packOutput = await runCapture(process.execPath, [npmCli, 'pack', '--json', '--ignore-scripts', '--offline', '--cache', packCacheDir, '--pack-destination', tempRoot], {
          cwd: repoRoot, timeout: NPM_TIMEOUT_MS, label: 'npm pack (default mode)',
          env: { ...process.env, npm_config_cache: packCacheDir },
        });

        if (packOutput.status !== 0) {
          throw new InfrastructureError(`npm pack failed (${packOutput.status}): ${boundedText(packOutput.stderr)}`);
        }

        const packed = JSON.parse(packOutput.stdout);
        tarballPath = path.join(tempRoot, packed[0].filename);
        tarballIdentity = { path: tarballPath, sha256: sha256Buffer(readFileSync(tarballPath)), bytes: statSync(tarballPath).size };
      }

      let listing = null;
      let memberPairs = [];

      await recordCheck('tarball-read', async () => {
        const listed = await runTar(['-tf', tarballPath], 'tar -tf');
        const verbose = await runTar(['-tvf', tarballPath], 'tar -tvf');

        if (listed.status !== 0 || listed.timedOut) {
          throw Object.assign(new Error(`tar -tf failed (${listed.status})`), { finding: { kind: 'tarball-listing', detail: boundedText(listed.stderr) } });
        }

        if (verbose.status !== 0 || verbose.timedOut) {
          throw Object.assign(new Error(`tar -tvf failed (${verbose.status})`), { finding: { kind: 'tarball-listing', detail: boundedText(verbose.stderr) } });
        }

        const cleanLines = (text) => text.split('\n')
          .map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line))
          .filter((line) => line !== '');

        const lines = cleanLines(listed.stdout);
        const verboseLines = cleanLines(verbose.stdout);

        if (lines.length === 0) {
          throw Object.assign(new Error('tar -tf listed no members'), { finding: { kind: 'tarball-listing', detail: 'tarball contains no members' } });
        }

        /* Member TYPES are only meaningful when the two listings can be
         * paired index-wise; a disagreement is an infrastructure failure
         * because member types could not be proven. */
        if (lines.length !== verboseLines.length) {
          throw new InfrastructureError(`tar -tf and tar -tvf disagree on member count (${lines.length} versus ${verboseLines.length}); member types cannot be paired`);
        }

        listing = lines;
        memberPairs = verboseLines.map((line, index) => ({
          name: lines[index],
          typeChar: line.length > 0 ? line[0] : ' ',
          /* Link indicators are detected textually with surrounding spaces so
           * a different tar flavor cannot hide a link entry behind an
           * unrecognized type character. */
          linkText: line.includes(' -> ') || line.includes(' link to '),
        }));

        return { members: lines.length };
      });

      let memberNames = [];
      let memberAbortFindings = null;

      await recordCheck('tarball-member-shape', () => {
        if (listing === null) {
          throw Object.assign(new Error('tar listing unavailable'), { notRun: true, finding: { kind: 'tarball-member-shape', detail: 'tar listing failed' } });
        }

        const findingsHere = [];
        const names = [];

        for (const line of listing) {
          const normalized = normalizeTarMember(line);

          if (!normalized.ok) {
            findingsHere.push({ kind: 'tarball-member-shape', path: line, reason: normalized.reason });
            continue;
          }

          if (!normalized.skip && !normalized.isDir) names.push(normalized.rel);
        }

        if (names.length === 0) {
          findingsHere.push({ kind: 'tarball-member-shape', detail: 'tarball contains no package files' });
        }

        findingsHere.push(...runMemberChecks(names));
        findingsHere.push(...runMemberTypeChecks(memberPairs));
        findingsHere.push(...runMemberDuplicateChecks(listing));

        memberNames = names;
        memberAbortFindings = findingsHere;

        return findingsHere;
      });

      /* Extraction (and therefore installation) is ABORTED when any member
       * shape/type/link/duplicate finding exists: a rejected archive is never
       * written to disk by this gate, and npm is never handed it. */
      let extractionReady = false;
      let extractionNotRunDetail = listing === null ? 'tar listing failed' : null;

      if (listing !== null) {
        if (memberAbortFindings !== null && memberAbortFindings.length === 0) {
          const extraction = await runTar(['-xf', tarballPath, '-C', extractDir], 'tar -xf');

          if (extraction.status !== 0) {
            throw new InfrastructureError(`tar -xf failed (${extraction.status}): ${boundedText(extraction.stderr)}`);
          }

          if (!existsSync(path.join(packageDir, 'package.json'))) {
            throw new InfrastructureError('tarball extraction did not produce package/package.json');
          }

          extractionReady = true;
        } else {
          extractionNotRunDetail = `extraction and install aborted: ${memberAbortFindings.length} tarball member shape/type/duplicate finding(s) exist; the archive was never written to disk and npm was never handed it`;
        }
      }

      let manifest = null;

      await recordCheck('manifest-load', () => {
        if (!extractionReady) {
          throw Object.assign(new Error('extraction not performed'), { notRun: true, finding: { kind: 'manifest-load', detail: `not run: ${extractionNotRunDetail ?? 'extraction unavailable'}` } });
        }

        const parsed = JSON.parse(readFileSync(path.join(packageDir, 'package.json'), 'utf8'));

        if (!isPlainRecord(parsed)) {
          throw Object.assign(new Error('package manifest is not an object'), { finding: { kind: 'manifest-load', detail: 'not an object' } });
        }

        manifest = parsed;

        return { name: manifest.name ?? null };
      });

      await recordCheck('policy-self-consistency', () => {
        assertPolicySelfConsistency();
      });

      await recordCheck('tarball-target-presence', () => {
        if (listing === null) {
          throw Object.assign(new Error('tar listing unavailable'), { notRun: true, finding: { kind: 'tarball-target-presence', detail: 'tar listing failed' } });
        }

        /* Runs on the LISTING only: target presence never needs the
         * extracted tree, so it still runs when extraction is blocked. */
        const findingsHere = runTargetPresenceChecks(memberNames);

        return findingsHere.length === 0 ? { referenced: referencedTargets().length } : findingsHere;
      });

      if (manifest !== null) {
        await recordCheck('public-entries-sync', () => runPublicEntriesSyncChecks(manifest));
        await recordCheck('exports-structure-exact', () => runStructureExactChecks(manifest));
        await recordCheck('exports-entry-shape', () => runExportEntryChecks(manifest));
        await recordCheck('manifest-fields', () => runManifestFieldChecks(manifest));

        await recordCheck('provider-registry-sync', async () => {
          const registryPath = path.join(packageDir, 'dist', 'providers', 'index.js');

          if (!existsSync(registryPath)) {
            throw Object.assign(new Error('built provider registry missing from tarball'), { finding: { kind: 'provider-registry-import', detail: 'dist/providers/index.js absent' } });
          }

          /* Candidate registry code is evaluated ONLY inside the bounded
           * child; the parent never imports candidate modules. */
          let childReport = null;

          try {
            childReport = await executeRegistryChild(tempRoot, registryPath);
          } catch (childError) {
            throw Object.assign(new Error(boundedText(childError instanceof Error ? childError.message : childError)), { notRun: true, finding: { kind: 'provider-registry-child', detail: `not run: candidate registry child infrastructure failure (${boundedText(childError instanceof Error ? childError.message : childError)})` } });
          }

          if (childReport.error !== null || !Array.isArray(childReport.providers)) {
            throw Object.assign(
              new Error('built registry could not be evaluated'),
              { finding: { kind: 'provider-registry-import', detail: boundedText(childReport.error ?? childReport.shape ?? 'no providers in child report') } },
            );
          }

          const registryIds = childReport.providers;

          const findingsHere = runProviderRegistryChecks(registryIds);

          return findingsHere.length === 0 ? { providers: registryIds.length } : findingsHere;
        });

        const graphEntries = [];

        for (const rel of memberNames) {
          if (!rel.startsWith('dist/cjs/') && !rel.startsWith('dist/node/')) continue;

          if (rel.endsWith('.cjs') || rel.endsWith('.d.cts') || rel.endsWith('.js') || rel.endsWith('.d.ts')) {
            graphEntries.push({ rel, text: readFileSync(path.join(packageDir, rel.split('/').join(path.sep)), 'utf8') });
          }
        }

        const cjsRuntimeEntries = graphEntries.filter((entry) => entry.rel.startsWith('dist/cjs/') && entry.rel.endsWith('.cjs'));
        const facadeRuntimeEntries = graphEntries.filter((entry) => entry.rel.startsWith('dist/node/') && entry.rel.endsWith('.js'));
        const declarationEntries = graphEntries.filter((entry) => entry.rel.endsWith('.d.cts') || entry.rel.endsWith('.d.ts'));

        await recordCheck('cjs-graph-edges', () => {
          if (cjsRuntimeEntries.length === 0) {
            throw Object.assign(new Error('no dist/cjs runtime members scanned'), { finding: { kind: 'cjs-graph-edges', detail: 'tarball contains no dist/cjs *.cjs members' } });
          }

          const findingsHere = [
            ...runGraphEdgeChecks(cjsRuntimeEntries),
            ...runEdgeResolutionChecks(cjsRuntimeEntries, memberNames),
          ];

          return findingsHere.length === 0 ? { scannedCjsRuntime: cjsRuntimeEntries.length } : findingsHere;
        });

        await recordCheck('facade-graph-edges', () => {
          if (facadeRuntimeEntries.length === 0) {
            throw Object.assign(new Error('no dist/node facade members scanned'), { finding: { kind: 'facade-graph-edges', detail: 'tarball contains no dist/node *.js members' } });
          }

          const findingsHere = [
            ...runGraphEdgeChecks(facadeRuntimeEntries),
            ...runEdgeResolutionChecks(facadeRuntimeEntries, memberNames),
          ];

          return findingsHere.length === 0 ? { scannedFacadeRuntime: facadeRuntimeEntries.length } : findingsHere;
        });

        await recordCheck('declaration-edges', () => {
          if (declarationEntries.length === 0) {
            throw Object.assign(new Error('no declaration members scanned'), { finding: { kind: 'declaration-edges', detail: 'tarball contains no *.d.cts or *.d.ts members under dist/cjs and dist/node' } });
          }

          const findingsHere = [
            ...runGraphEdgeChecks(declarationEntries),
            ...runEdgeResolutionChecks(declarationEntries, memberNames),
          ];

          return findingsHere.length === 0 ? { scannedDeclarations: declarationEntries.length } : findingsHere;
        });

        await recordCheck('facade-module-shape', () => {
          const texts = new Map();

          for (const entry of graphEntries) {
            if (entry.rel.startsWith('dist/node/')) texts.set(entry.rel, entry.text);
          }

          return runFacadeModuleChecks(texts);
        });
      } else {
        /* No silent skips: every manifest/extraction-dependent check is
         * explicitly not-run when the manifest never loaded. */
        for (const kind of ['public-entries-sync', 'exports-structure-exact', 'exports-entry-shape', 'manifest-fields', 'provider-registry-sync', 'cjs-graph-edges', 'facade-graph-edges', 'declaration-edges', 'facade-module-shape']) {
          await recordCheck(kind, () => {
            throw Object.assign(new Error('manifest unavailable'), { notRun: true, finding: { kind, detail: `not run: ${extractionNotRunDetail ?? 'manifest load did not produce a manifest'}` } });
          });
        }
      }

      await recordCheck('cli-shebang', () => {
        if (!extractionReady) {
          throw Object.assign(new Error('extraction not performed'), { notRun: true, finding: { kind: 'cli-shebang', detail: `not run: ${extractionNotRunDetail ?? 'extraction unavailable'}` } });
        }

        const cliPath = path.join(packageDir, CLI_RELATIVE.split('/').join(path.sep));

        if (!existsSync(cliPath)) {
          throw Object.assign(new Error('CLI file missing'), { finding: { kind: 'cli-shebang', detail: 'dist/cli/index.js absent from tarball' } });
        }

        return runCliShebangCheck(readFileSync(cliPath, 'utf8'));
      });

      await recordCheck('original-esm-baseline-pin', () => {
        if (!extractionReady) {
          throw Object.assign(new Error('extraction not performed'), { notRun: true, finding: { kind: 'original-esm-baseline-pin', detail: `not run: ${extractionNotRunDetail ?? 'extraction unavailable'}` } });
        }

        const tarballOriginal = [];

        for (const rel of memberNames) {
          if (!isOriginalDistPath(rel)) continue;

          tarballOriginal.push({ rel, sha256: sha256Buffer(readFileSync(path.join(packageDir, rel.split('/').join(path.sep)))) });
        }

        const checkoutOriginal = [];

        for (const rel of before.keys()) {
          if (!isOriginalDistPath(rel)) continue;

          checkoutOriginal.push({ rel, sha256: before.get(rel) });
        }

        const findingsHere = compareBaselinePins(tarballOriginal, checkoutOriginal);

        return findingsHere.length === 0
          ? { tarballOriginal: tarballOriginal.length, checkoutOriginal: checkoutOriginal.length }
          : findingsHere;
      });

      /* ------------------- installed runtime checks ------------------- */

      let installRootReady = false;

      await recordCheck('install-offline', async () => {
        if (!extractionReady) {
          throw Object.assign(new Error('extraction not performed'), { notRun: true, finding: { kind: 'install-offline', detail: `not run: ${extractionNotRunDetail ?? 'extraction unavailable'}` } });
        }

        const install = await runCapture(process.execPath, [npmCli, 'install', tarballPath, '--ignore-scripts', '--legacy-peer-deps', '--offline', '--no-audit', '--no-fund'], {
          cwd: installRoot,
          timeout: NPM_TIMEOUT_MS,
          label: 'npm install (candidate tarball)',
          env: { ...process.env, npm_config_cache: npmCacheDir },
        });

        if (install.status !== 0) {
          throw Object.assign(new Error(`npm install failed (${install.status}): ${boundedText(install.stderr)}`), { finding: { kind: 'install-offline', detail: boundedText(install.stderr) } });
        }

        if (!existsSync(path.join(installRoot, 'node_modules', 'hooklatch', 'package.json'))) {
          throw Object.assign(new Error('hooklatch did not land under node_modules'), { finding: { kind: 'install-offline', detail: 'node_modules/hooklatch/package.json absent after install' } });
        }

        installRootReady = true;

        return { consumer: 'isolated temp consumer' };
      });

      let probePhases = null;
      let probeInfra = null;

      if (installRootReady) {
        try {
          probePhases = await executeProbe(installRoot);
        } catch (probeError) {
          probeInfra = boundedText(probeError instanceof Error ? probeError.message : probeError);
        }
      }

      const recordRuntimePhase = (id, phaseName) => recordCheck(id, () => {
        if (probeInfra !== null || probePhases === null) {
          throw Object.assign(new Error('probe infrastructure failure'), { notRun: true, finding: { kind: id, detail: `not run: probe infrastructure failure (${probeInfra ?? 'no report'})` } });
        }

        const phase = probePhases[phaseName];

        if (phase === undefined) {
          throw Object.assign(new Error('probe phase absent'), { notRun: true, finding: { kind: id, detail: `not run: phase ${phaseName} absent from probe report (probe terminated early)` } });
        }

        if (phase.verdict !== 'pass') {
          throw Object.assign(new Error(`${phaseName}: ${phase.detail}`), { finding: { kind: id, detail: `${phaseName}: ${boundedText(phase.detail)}` } });
        }

        return { phase: phaseName };
      });

      await recordRuntimePhase('runtime-resolutions', 'resolutions');
      await recordRuntimePhase('runtime-forbidden-deep', 'forbidden');
      await recordRuntimePhase('runtime-identity-functional', 'identity-functional');
      await recordRuntimePhase('runtime-cli', 'cli');

      if (!installRootReady) {
        await recordCheck('esbuild-neutral-original-esm', async () => {
          throw Object.assign(new Error('install did not succeed'), { notRun: true, finding: { kind: 'esbuild-neutral-original-esm', detail: 'not run: install did not succeed' } });
        });

        await recordCheck('declaration-resolution', () => {
          throw Object.assign(new Error('install did not succeed'), { notRun: true, finding: { kind: 'declaration-resolution', detail: 'not run: install did not succeed' } });
        });
      } else {
        await recordCheck('esbuild-neutral-original-esm', async () => {
          const findingsHere = await runEsbuildNeutralCheck(installRoot, repoRequire);

          return findingsHere.length === 0 ? { inputs: 'original dist ESM only' } : findingsHere;
        });

        await recordCheck('declaration-resolution', () => {
          const findingsHere = runDeclarationResolutionChecks(installRoot, repoRequire);

          return findingsHere.length === 0 ? { arms: 'import/require/bundler plus negative deep imports' } : findingsHere;
        });
      }
    } catch (measuredError) {
      infraError = infraError ?? boundedText(measuredError instanceof Error ? measuredError.message : measuredError);

      if (!(measuredError instanceof InfrastructureError)) {
        findings.push({ kind: 'measured-run-unexpected', detail: infraError });
      }
    }

    /* ------------------------- cleanup phase ------------------------- */

    if (tempRoot !== null && lifecycle.cleanupSafe) {
      try {
        const checked = path.resolve(tempRoot);
        const tempBase = path.resolve(tmpdir());

        if (!checked.startsWith(tempBase + path.sep) || checked === tempBase) {
          throw new Error(`refusing to remove unexpected temp root ${checked}`);
        }

        await rm(checked, { recursive: true, force: false });
      } catch (cleanupError) {
        lifecycle.cleanupSafe = false;
        findings.push({ kind: 'cleanup-failure', detail: boundedText(cleanupError instanceof Error ? cleanupError.message : cleanupError), root: tempRoot });
      }
    }

    if (tempRoot === null) {
      cleanupVerified = true;
    } else if (lifecycle.cleanupSafe) {
      cleanupVerified = !existsSync(tempRoot);
    } else {
      cleanupVerified = false;
    }

    if (!cleanupVerified) {
      findings.push({ kind: 'cleanup-unverified', detail: `temp root was not removed: ${tempRoot}` });
    }

    /* ------------------------ integrity phase ------------------------ */

    let integrityChanged = [];
    let integrityNote = 'tracked files + built dist tree';

    try {
      const afterList = [...new Set([...listTrackedFiles(repoRoot), ...walkFiles(path.join(repoRoot, 'dist'), 'dist')])];
      const after = snapshotHashes(repoRoot, afterList);

      integrityChanged = diffSnapshots(before, after);
    } catch (integrityError) {
      integrityNote = `integrity resnapshot failed: ${boundedText(integrityError instanceof Error ? integrityError.message : integrityError)}`;
      findings.push({ kind: 'integrity-verification-failure', detail: integrityNote });
    }

    if (integrityChanged.length > 0) {
      findings.push({ kind: 'integrity-change', detail: JSON.stringify(integrityChanged) });
    }

    /* ---------------------------- publish ---------------------------- */

    const failedChecks = checks.filter((check) => check.verdict === 'fail');
    const notRunChecks = checks.filter((check) => check.verdict === 'not-run');

    const passedAll = failedChecks.length === 0 && notRunChecks.length === 0 && findings.length === 0
      && cleanupVerified && integrityChanged.length === 0 && infraError === null;

    const status = passedAll ? 'pass' : 'fail';

    const report = {
      schemaVersion: 1,
      gate: 'phase11-package-contract',
      mode: explicitTarballMode ? 'tarball' : 'default',
      controlsOnly: false,
      status,
      exit: status === 'pass' ? EXIT.PASS : EXIT.RED,
      environment: {
        node: process.version,
        platform: process.platform,
        repoRoot,
        tarball: tarballIdentity,
        packCommand: explicitTarballMode
          ? 'not run (explicit --tarball mode; the named candidate was qualified as-is)'
          : 'node <npm-cli> pack --json --ignore-scripts --offline --cache <tempRoot>/pack-cache --pack-destination <tempRoot> (env npm_config_cache=<tempRoot>/pack-cache; pack lifecycle scripts cannot execute)',
        installCommand: 'node <npm-cli> install <candidate-tarball> --ignore-scripts --legacy-peer-deps --offline --no-audit --no-fund (cwd <tempRoot>/consumer, env npm_config_cache=<tempRoot>/npm-cache)',
      },
      summary: {
        checks: checks.length,
        passed: checks.length - failedChecks.length - notRunChecks.length,
        failed: failedChecks.length,
        notRun: notRunChecks.length,
        failedCheckIds: failedChecks.map((check) => check.id),
        notRunCheckIds: notRunChecks.map((check) => check.id),
        findingKinds: [...new Set(findings.map((finding) => finding.kind))].sort(),
      },
      checks,
      findings,
      cleanup: {
        attempted: tempRoot !== null,
        verified: cleanupVerified,
        cleanupSafe: lifecycle.cleanupSafe,
        tempRoot: tempRoot === null ? null : (cleanupVerified ? tempRoot : `${tempRoot} (preserved)`),
      },
      integrity: { sampled: true, trackedFiles: before === null ? 0 : before.size, changed: integrityChanged, note: integrityNote },
      limitations: [
        'sha256 of extracted tarball content and checkout files; member names listed via system tar before extraction',
        'integrity snapshot covers tracked files + dist/; node_modules junction not hashed',
        'runtime probe ran on the host Node binary; floor-runtime qualification is a separate deliverable',
        'declaration checks are resolution-only; consumer type acceptance is a different owner deliverable',
      ],
    };

    if (infraError !== null) {
      report.infrastructureError = infraError;
    }

    if (args.results !== null && status === 'pass') {
      try {
        /* Ancestors were validated as real directories before the run; the
         * exclusive `wx` flag refuses to overwrite anything that appeared
         * at the destination since validation. */
        await mkdir(path.dirname(path.resolve(args.results)), { recursive: true });
        await writeFile(args.results, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
        report.resultsWritten = args.results;
      } catch (writeError) {
        report.status = 'fail';
        report.exit = EXIT.RED;
        report.resultsWriteError = boundedText(writeError instanceof Error ? writeError.message : writeError);
        findings.push({ kind: 'results-write-failure', detail: report.resultsWriteError });
        report.findings = findings;
        report.summary.findingKinds = [...new Set(findings.map((finding) => finding.kind))].sort();
      }
    } else if (args.results !== null) {
      report.resultsNotWrittenReason = 'results are written only for PASS runs';
    }

    console.log(JSON.stringify(report, null, 2));

    process.exitCode = report.exit;

    return;
  }

  /* Presnapshot failure path: nothing was measured or allocated. */
  console.log(JSON.stringify({
    schemaVersion: 1,
    gate: 'phase11-package-contract',
    mode: 'tarball',
    controlsOnly: false,
    status: 'fail',
    exit: EXIT.RED,
    infrastructureError: infraError,
    checks: [],
    findings: [{ kind: 'integrity-presnapshot-failure', detail: infraError }],
    cleanup: { attempted: false, verified: true, cleanupSafe: lifecycle.cleanupSafe },
    integrity: { sampled: false, note: infraError },
  }, null, 2));

  process.exitCode = EXIT.RED;
}

/** Execute the generated runtime probe child; returns parsed phases. */
async function executeProbe(installRoot) {
  const esmTargets = [];
  const cjsTargets = [];

  for (const [specifier, base] of POLICY_PUBLIC_ENTRIES) {
    const packageSpec = packageSpecifierOf(specifier);
    esmTargets.push({ spec: packageSpec, rel: `dist/node/${base}.js` });
    cjsTargets.push({ spec: packageSpec, rel: `dist/cjs/${base}.cjs` });
  }

  const probePath = path.join(installRoot, 'hooklatch-package-probe.mjs');

  const probeSource = PROBE_TEMPLATE
    .replace('"__ESM_TARGETS__"', JSON.stringify(esmTargets))
    .replace('"__CJS_TARGETS__"', JSON.stringify(cjsTargets))
    .replace('"__ENTRY_NAMES__"', JSON.stringify(POLICY_PUBLIC_ENTRIES.map(([spec, , names]) => ({ spec: packageSpecifierOf(spec), names }))))
    .replace('"__EXPECTED_REGISTRY__"', JSON.stringify([...POLICY_PROVIDERS]))
    .replace('"__FORBIDDEN_SPECS__"', JSON.stringify([...FORBIDDEN_DEEP_SPECS]))
    .replace('"__CLI_RELATIVE__"', JSON.stringify(CLI_RELATIVE))
    .replace('"__CANARY__"', JSON.stringify('HOOKLATCH_PHASE11_PRIVATE_CANARY'));

  await writeFile(probePath, probeSource, { encoding: 'utf8' });

  const probe = await runCapture(process.execPath, [probePath], {
    cwd: installRoot, timeout: PROBE_TIMEOUT_MS, label: 'runtime probe',
  });

  if (probe.timedOut) {
    throw new InfrastructureError('runtime probe timed out (termination confirmed via process-tree kill); phase report refused');
  }

  if (probe.outputOverflow) {
    throw new InfrastructureError(`runtime probe output overflow (capture limit exceeded, status ${probe.status}); refusing to accept a partial report`);
  }

  /* Phases are accepted only from a child that exited cleanly: a nonzero
   * status or a signal means the emitted report cannot be trusted even if
   * it parses. This is an infrastructure failure, never a semantic pass. */
  if (probe.status !== 0 || probe.signal !== null) {
    throw new InfrastructureError(`runtime probe terminated abnormally (status ${JSON.stringify(probe.status)}, signal ${JSON.stringify(probe.signal)}); refusing phases from a nonzero-exit child`);
  }

  let probeReport = null;

  if (probe.stdout !== '') {
    try {
      probeReport = JSON.parse(probe.stdout);
    } catch {
      probeReport = null;
    }
  }

  if (probeReport === null || !isPlainRecord(probeReport.phases)) {
    throw new InfrastructureError(`runtime probe produced no parsable report (status ${probe.status}): ${boundedText(probe.stderr)}`);
  }

  return probeReport.phases;
}

/**
 * Evaluate ONE candidate provider registry inside a bounded child and
 * return the parsed child report. The child always exits 0 when its report
 * is emitted; anything else (timeout, overflow, signal, nonzero status,
 * unparsable output) is an infrastructure failure with confirmed
 * termination. A child that reports an import failure is a SEMANTIC
 * candidate defect (returned as a report, not thrown).
 */
async function executeRegistryChild(tempRoot, registryPath) {
  const childPath = path.join(tempRoot, 'hooklatch-registry-probe.mjs');

  const childSource = REGISTRY_CHILD_TEMPLATE.replace('"__REGISTRY_PATH__"', JSON.stringify(registryPath));

  await writeFile(childPath, childSource, { encoding: 'utf8' });

  const child = await runCapture(process.execPath, [childPath], {
    cwd: tempRoot, timeout: REGISTRY_TIMEOUT_MS, label: 'candidate registry child',
  });

  if (child.timedOut) {
    throw new InfrastructureError('candidate registry child timed out (never-settling candidate evaluation; termination confirmed via process-tree kill); report refused');
  }

  if (child.outputOverflow) {
    throw new InfrastructureError(`candidate registry child output overflow (status ${child.status}); refusing a partial report`);
  }

  if (child.status !== 0 || child.signal !== null) {
    throw new InfrastructureError(`candidate registry child terminated abnormally (status ${JSON.stringify(child.status)}, signal ${JSON.stringify(child.signal)}); refusing its output`);
  }

  let childReport = null;

  if (child.stdout !== '') {
    try {
      childReport = JSON.parse(child.stdout);
    } catch {
      childReport = null;
    }
  }

  if (childReport === null || !isPlainRecord(childReport)
    || !Object.hasOwn(childReport, 'providers')
    || !Object.hasOwn(childReport, 'error')
    || !(childReport.error === null || isString(childReport.error))) {
    throw new InfrastructureError(`candidate registry child produced an invalid report (status ${child.status}): ${boundedText(child.stderr)}`);
  }

  return childReport;
}

if (invokedDirectly) {
  await main();
}
