#!/usr/bin/env node
/**
 * Phase 12 read-only release-readiness checker (Codebuff DeepSeek owner).
 *
 * Inspects ONE checkout without changing it: package identity/engines/runtime
 * dependencies, the six-entry import + require + neutral ESM + declaration
 * layout, main/types/bin targets, the built 21-provider registry (imported in a
 * bounded child, never in this process) and the README/CHANGELOG unreleased
 * state.
 *
 * LOCAL READINESS IS NOT RELEASE AUTHORIZATION. Every report always lists the
 * external prerequisites - private security reporting, npm ownership/auth/2FA,
 * an exact-SHA CI run, final tarball review and the release/tag/publication
 * decision - as `manual-required` or `not-checked`. Historical receipts, prior
 * CI runs and self-asserted booleans are never upgraded to external readiness
 * by this checker.
 *
 * Constraints: no network, no npm authentication or account query, no packing,
 * no installing, no file writes and no shell/environment dumps. Deep package,
 * type and runtime qualification stay with the existing gates listed under
 * `notRunHere`; this checker only inspects structure and presence and never
 * executes package code in its own process.
 *
 * Exit: 0 locally ready, 1 local defect, 2 usage, 3 missing build.
 */
import { spawn } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const EXIT = Object.freeze({ READY: 0, DEFECT: 1, USAGE: 2, BLOCKED: 3 });

export const PACKAGE_NAME = 'hooklatch';
export const EXPECTED_VERSION = '1.0.0';
export const EXPECTED_NODE_ENGINE = '>=22';
export const REGISTRY_RELATIVE = 'dist/providers/index.js';

const PROBE_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const FIELD_LIMIT = 120;

const USAGE = [
  'Usage: node scripts/phase12/release-readiness.mjs [--help] [--self-test] [--root DIR]',
  '',
  'Read-only local release readiness for one package checkout. Never writes,',
  'packs, installs, authenticates or uses the network.',
  '',
  'Options:',
  '  --help        Show this help and exit 0.',
  '  --self-test   Run the built-in control checks only (no build inspection);',
  '                exits 0 only when every control passes.',
  '  --root DIR    Inspect DIR instead of this checkout (read-only; used by the',
  '                negative controls against OS-temp fixtures).',
  '',
  'Exit: 0 locally ready, 1 local defect, 2 usage, 3 missing build (dist/ is',
  'not built; run `npm run build` first).',
  '',
  'Local readiness is NOT release authorization. npm ownership/auth/2FA, private',
  'security reporting, exact-SHA CI, final tarball review and the release, tag',
  'and publication decision are always reported as not-checked or',
  'manual-required.',
].join('\n');

/** Frozen public entry policy: subpath plus its dist base path. */
export const PUBLIC_ENTRIES = Object.freeze([
  Object.freeze({ subpath: '.', base: 'index' }),
  Object.freeze({ subpath: './diagnostics', base: 'diagnostics/index' }),
  Object.freeze({ subpath: './express', base: 'adapters/express' }),
  Object.freeze({ subpath: './nextjs', base: 'adapters/nextjs' }),
  Object.freeze({ subpath: './cloudflare', base: 'adapters/cloudflare' }),
  Object.freeze({ subpath: './hono', base: 'adapters/hono' }),
]);

/** Frozen 21-provider registry order at the accepted base. */
export const EXPECTED_PROVIDERS = Object.freeze([
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

/**
 * External prerequisites this checker can never establish locally. They are
 * listed on every report, including blocked and defect runs.
 */
export const EXTERNAL_REQUIREMENTS = Object.freeze([
  Object.freeze({
    id: 'security-private-reporting',
    status: 'manual-required',
    reason: 'Confirm an actual private vulnerability-reporting channel (for example an enabled GitHub private advisory flow) before releasing. SECURITY.md describes an unconfigured policy; an offline check cannot verify a live setting.',
  }),
  Object.freeze({
    id: 'npm-ownership-auth-2fa',
    status: 'not-checked',
    reason: 'Package ownership, publish rights, account access and 2FA cannot be verified without account actions. A registry 404 is not evidence of ownership or reservation.',
  }),
  Object.freeze({
    id: 'exact-sha-ci',
    status: 'not-checked',
    reason: 'A green CI run must be obtained on the exact release SHA. No earlier run, branch or partner result is inherited.',
  }),
  Object.freeze({
    id: 'final-tarball-review',
    status: 'not-checked',
    reason: 'Review the packed tarball contents and hashes from the real release build. This checker never packs, installs or lists an archive.',
  }),
  Object.freeze({
    id: 'release-tag-publication',
    status: 'not-checked',
    reason: 'Maintainer authorization, version/tag creation and npm publication are a separate decision; nothing here authorizes or performs them.',
  }),
]);

/** Existing gates that own deep qualification; deliberately not rebuilt here. */
export const NOT_RUN_HERE = Object.freeze([
  'npm run verify',
  'npm run test:package',
  'npm run test:compat-package',
  'npm run test:compat-types',
  'npm run test:compat-runtime',
  'npm run test:compat-frameworks',
  'npm run test:node-distribution',
  'npm run test:docs-contract',
  'npm run test:public-contracts',
]);

export const LIMITATIONS = Object.freeze([
  'Structure and presence only: this is not behavioural, type-compatibility, performance or version-support evidence.',
  'The built registry is imported by a separate bounded child; this checker never packs, installs or runs package code in its own process.',
  'No network, registry, npm authentication, 2FA, account or environment query is performed or represented.',
  'Historical receipts, prior CI runs and self-asserted booleans are never converted into external readiness.',
  'Documentation claims are matched with a bounded pattern list; a match or absence is not proof of publication state.',
  'The unreleased check encodes the pre-first-publication convention (`## Unreleased`); a real publication requires updating this checker deliberately, not silencing it.',
  'One checkout is inspected; branch comparison and verification that CI ran on this exact SHA are out of scope.',
]);

/** Unambiguous assertions of a completed release; conditional/pending text is fine. */
export const PUBLICATION_CLAIM_PATTERNS = Object.freeze([
  Object.freeze({ id: 'published-to-npm', pattern: /\bis (?:now )?published to npm\b/i }),
  Object.freeze({ id: 'available-on-npm', pattern: /\bis (?:now )?available on npm\b/i }),
  Object.freeze({ id: 'registry-package-page', pattern: /npmjs\.com\/package\/hooklatch\b/i }),
  Object.freeze({ id: 'released-version', pattern: /\bversion 1\.0\.0 (?:has been|was) released\b/i }),
  Object.freeze({ id: 'release-tag', pattern: /\bgit tag v?1\.0\.0 (?:has been|was) (?:created|pushed)\b/i }),
]);

const REGISTRY_PROBE = [
  'const target = process.argv.at(-1);',
  "const { pathToFileURL } = await import('node:url');",
  'const loaded = await import(pathToFileURL(target).href);',
  'process.stdout.write(JSON.stringify({ providers: loaded.SUPPORTED_PROVIDERS ?? null }));',
].join('\n');

export class UsageError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'UsageError';
  }
}

/* ------------------------------------------------------------------ *
 * Value boundary helpers
 * ------------------------------------------------------------------ */

function kindOf(value) {
  return Object.prototype.toString.call(value).slice(8, -1);
}

function isRecord(value) {
  return kindOf(value) === 'Object';
}

function isText(value) {
  return kindOf(value) === 'String';
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function describeField(value) {
  if (value === undefined) return 'absent';

  const text = JSON.stringify(value) ?? 'undefined';

  return text.length > FIELD_LIMIT ? `${text.slice(0, FIELD_LIMIT)}...` : text;
}

function sameStrings(observed, expected) {
  if (!Array.isArray(observed) || observed.length !== expected.length) return false;

  for (let index = 0; index < expected.length; index += 1) {
    if (observed[index] !== expected[index]) return false;
  }

  return true;
}

function boundedText(value) {
  const text = String(value).replace(/\s+/g, ' ').trim();

  return text.length > FIELD_LIMIT ? `${text.slice(0, FIELD_LIMIT)}...` : text;
}

function isRegularFile(file) {
  try {
    return lstatSync(file).isFile();
  } catch {
    return false;
  }
}

/** Declared targets must stay inside the package's own dist/ tree. */
export function isInsidePackage(target) {
  return isText(target)
    && target.startsWith('./dist/')
    && !target.includes('..')
    && !target.includes('\\');
}

/* ------------------------------------------------------------------ *
 * Manifest, export-map and entry-point checks (pure)
 * ------------------------------------------------------------------ */

/**
 * The frozen per-entry target set: node ESM facade, node CJS graph, neutral
 * ESM graph and both declaration flavours. The neutral arm must NOT point into
 * dist/node or dist/cjs, which is what retains the three-way split.
 */
export function expectedTargets(entry) {
  const { base } = entry;

  return [
    { arm: 'node.import.types', target: `./dist/node/${base}.d.ts` },
    { arm: 'node.import.default', target: `./dist/node/${base}.js` },
    { arm: 'node.require.types', target: `./dist/cjs/${base}.d.cts` },
    { arm: 'node.require.default', target: `./dist/cjs/${base}.cjs` },
    { arm: 'types', target: `./dist/${base}.d.ts` },
    { arm: 'import', target: `./dist/${base}.js` },
    { arm: 'default', target: `./dist/${base}.js` },
  ];
}

function armValue(entryMap, arm) {
  let current = entryMap;

  for (const key of arm.split('.')) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }

  return current;
}

/** Package identity, module scope, engines and zero runtime dependencies. */
export function validateManifest(manifest) {
  if (!isRecord(manifest)) {
    return [{ kind: 'malformed-package', detail: 'package.json is not a JSON object' }];
  }

  const findings = [];

  if (manifest.name !== PACKAGE_NAME) {
    findings.push({ kind: 'package-identity', field: 'name', expected: PACKAGE_NAME, observed: describeField(manifest.name) });
  }

  if (manifest.version !== EXPECTED_VERSION) {
    findings.push({ kind: 'package-identity', field: 'version', expected: EXPECTED_VERSION, observed: describeField(manifest.version) });
  }

  if (manifest.type !== 'module') {
    findings.push({ kind: 'module-scope', field: 'type', expected: 'module', observed: describeField(manifest.type) });
  }

  const engines = isRecord(manifest.engines) ? manifest.engines : {};

  if (engines.node !== EXPECTED_NODE_ENGINE) {
    findings.push({ kind: 'manifest-engines', field: 'engines.node', expected: EXPECTED_NODE_ENGINE, observed: describeField(engines.node) });
  }

  for (const field of ['dependencies', 'optionalDependencies']) {
    const declared = manifest[field];

    if (isRecord(declared) && Object.keys(declared).length > 0) {
      findings.push({ kind: 'runtime-dependencies', field, observed: Object.keys(declared).sort() });
    } else if (declared !== undefined && !isRecord(declared)) {
      findings.push({ kind: 'runtime-dependencies', field, detail: 'must be absent or an empty object', observed: describeField(declared) });
    }
  }

  return findings;
}

/** Six entries, exact condition arms and the retained ESM/CJS/neutral split. */
export function validateExportMap(manifest) {
  if (!isRecord(manifest) || !isRecord(manifest.exports)) {
    return [{ kind: 'malformed-package', detail: 'package.json exports is missing or not a JSON object' }];
  }

  const findings = [];
  const declared = Object.keys(manifest.exports).sort();
  const expectedKeys = PUBLIC_ENTRIES.map((entry) => entry.subpath).sort();

  if (!sameStrings(declared, expectedKeys)) {
    findings.push({ kind: 'exports-sync', expected: expectedKeys, observed: declared });
  }

  for (const entry of PUBLIC_ENTRIES) {
    const entryMap = manifest.exports[entry.subpath];

    if (!isRecord(entryMap)) {
      findings.push({ kind: 'export-entry', subpath: entry.subpath, detail: 'missing or not a JSON object' });
      continue;
    }

    for (const expected of expectedTargets(entry)) {
      const observed = armValue(entryMap, expected.arm);

      if (observed !== expected.target) {
        findings.push({
          kind: 'export-target', subpath: entry.subpath, arm: expected.arm,
          expected: expected.target, observed: describeField(observed),
        });
      }
    }
  }

  return findings;
}

/** main, root types and bin, including containment inside the package. */
export function validateEntryPoints(manifest) {
  if (!isRecord(manifest)) {
    return [{ kind: 'malformed-package', detail: 'package.json is not a JSON object' }];
  }

  const findings = [];

  checkContainedEntry(findings, 'main', manifest.main, './dist/cjs/index.cjs');
  checkContainedEntry(findings, 'types', manifest.types, './dist/index.d.ts');

  const bin = isRecord(manifest.bin) ? manifest.bin : {};

  checkContainedEntry(findings, 'bin.hooklatch', bin.hooklatch, './dist/cli/index.js');

  return findings;
}

function checkContainedEntry(findings, field, observed, expected) {
  if (!isInsidePackage(observed)) {
    findings.push({ kind: 'target-outside-package', field, expected: 'a path inside ./dist/', observed: describeField(observed) });

    return;
  }

  if (observed !== expected) {
    findings.push({ kind: 'entry-point', field, expected, observed: describeField(observed) });
  }
}

/** Every declared target path (exports arms, main, root types, bin). */
export function declaredTargets(manifest) {
  const targets = [];

  if (!isRecord(manifest)) return targets;

  if (isText(manifest.main)) targets.push({ field: 'main', target: manifest.main });

  if (isText(manifest.types)) targets.push({ field: 'types', target: manifest.types });

  const bin = isRecord(manifest.bin) ? manifest.bin : {};

  for (const name of Object.keys(bin)) {
    if (isText(bin[name])) targets.push({ field: `bin.${name}`, target: bin[name] });
  }

  if (isRecord(manifest.exports)) {
    for (const entry of PUBLIC_ENTRIES) {
      const entryMap = manifest.exports[entry.subpath];

      if (!isRecord(entryMap)) continue;

      for (const expected of expectedTargets(entry)) {
        const observed = armValue(entryMap, expected.arm);

        if (isText(observed)) targets.push({ subpath: entry.subpath, field: expected.arm, target: observed });
      }
    }
  }

  return targets;
}

/**
 * Absent or non-file targets are defects, never silent passes. Targets that
 * escape the package are reported by validateEntryPoints/validateExportMap and
 * skipped here.
 */
export function checkDeclaredTargets(manifest, existsAt) {
  const findings = [];
  const seen = new Set();
  const resolved = [];

  for (const declared of declaredTargets(manifest)) {
    if (!isInsidePackage(declared.target)) continue;

    const relative = declared.target.slice('./'.length);
    const key = `${declared.subpath ?? ''}|${declared.field}|${relative}`;

    if (seen.has(key)) continue;
    seen.add(key);
    resolved.push(relative);

    if (existsAt(relative) !== true) {
      findings.push({ kind: 'missing-target', subpath: declared.subpath ?? null, field: declared.field, target: relative });
    }
  }

  return { findings, resolved };
}

/* ------------------------------------------------------------------ *
 * Registry and docs checks (pure comparison)
 * ------------------------------------------------------------------ */

/** Exactly the frozen 21 ids, in registry order, with no duplicates. */
export function compareProviders(observed) {
  if (!Array.isArray(observed)) {
    return [{ kind: 'registry-unreadable', detail: 'SUPPORTED_PROVIDERS is not an array' }];
  }

  const findings = [];
  const ids = [];

  for (const value of observed) {
    if (!isText(value) || value.length === 0) {
      findings.push({ kind: 'registry-entry', detail: 'provider id is not a non-empty string' });
      continue;
    }

    ids.push(value);
  }

  if (findings.length > 0) return findings;

  if (!sameStrings(ids, EXPECTED_PROVIDERS)) {
    findings.push({
      kind: 'registry-mismatch',
      expectedCount: EXPECTED_PROVIDERS.length,
      observedCount: ids.length,
      missing: EXPECTED_PROVIDERS.filter((id) => !ids.includes(id)),
      unexpected: ids.filter((id) => !EXPECTED_PROVIDERS.includes(id)),
      orderDiffers: ids.length === EXPECTED_PROVIDERS.length,
    });
  }

  return findings;
}

/** Unreleased state in the changelog plus no unqualified publication claims. */
export function validateDocs(files) {
  const findings = [];
  const changelog = files['CHANGELOG.md'];

  if (!isText(changelog)) {
    findings.push({ kind: 'missing-doc', file: 'CHANGELOG.md' });
  } else if (!/^##\s+Unreleased\s*$/m.test(changelog)) {
    findings.push({
      kind: 'changelog-unreleased-section',
      file: 'CHANGELOG.md',
      detail: 'expected a `## Unreleased` section while no publication is recorded',
    });
  }

  for (const file of Object.keys(files)) {
    const text = files[file];

    for (const claim of PUBLICATION_CLAIM_PATTERNS) {
      if (claim.pattern.test(text)) {
        findings.push({ kind: 'publication-claim', file, pattern: claim.id });
      }
    }
  }

  return findings;
}

/* ------------------------------------------------------------------ *
 * External prerequisites and verdict
 * ------------------------------------------------------------------ */

/** Fresh copy on every call so no caller can mutate the shared policy. */
export function externalEvidence() {
  return EXTERNAL_REQUIREMENTS.map((requirement) => ({
    id: requirement.id,
    status: requirement.status,
    reason: requirement.reason,
  }));
}

/** Local verdict: manifest defect wins, then a missing build, then check failures. */
export function resolveVerdict(manifestFindingCount, buildPresent, failedCheckCount) {
  if (manifestFindingCount > 0) return EXIT.DEFECT;

  if (!buildPresent) return EXIT.BLOCKED;

  return failedCheckCount > 0 ? EXIT.DEFECT : EXIT.READY;
}

function statusFor(exit) {
  if (exit === EXIT.READY) return 'ready';

  if (exit === EXIT.BLOCKED) return 'blocked';

  return 'defect';
}

/* ------------------------------------------------------------------ *
 * Bounded child (registry probe)
 * ------------------------------------------------------------------ */

/**
 * Run one bounded child and return evidence instead of throwing. A timeout,
 * signal, output overflow or unconfirmed close is recorded, so a probe that
 * cannot be fully observed can never be reported as a pass.
 */
export function runBoundedChild(args, cwd, timeoutMs) {
  return new Promise((done) => {
    const started = Date.now();

    const evidence = {
      exitCode: null, signal: null, stdout: '', stderr: '',
      timedOut: false, outputLimitExceeded: false, spawnError: null, closeConfirmed: false,
    };

    let bytes = 0;
    let settled = false;
    let closeDeadline;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(closeDeadline);
      evidence.durationMs = Date.now() - started;
      evidence.ok = evidence.exitCode === 0 && evidence.signal === null
        && !evidence.timedOut && !evidence.outputLimitExceeded
        && evidence.spawnError === null && evidence.closeConfirmed;
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
      }, 5000);
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

    const child = spawn(process.execPath, args, {
      cwd, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));
    child.on('error', (error) => {
      evidence.spawnError = error.message;
      finish();
    });
    child.on('close', (code, signal) => {
      evidence.exitCode = code;
      evidence.signal = signal;
      evidence.closeConfirmed = true;
      finish();
    });
  });
}

function summarizeProbe(evidence) {
  return {
    exitCode: evidence.exitCode,
    signal: evidence.signal,
    timedOut: evidence.timedOut,
    outputLimitExceeded: evidence.outputLimitExceeded,
    spawnError: evidence.spawnError,
    closeConfirmed: evidence.closeConfirmed,
    stderr: boundedText(evidence.stderr),
  };
}

async function probeRegistry(repoRoot, timeoutMs) {
  const target = path.join(repoRoot, REGISTRY_RELATIVE);

  const evidence = await runBoundedChild(
    ['--input-type=module', '-e', REGISTRY_PROBE, target],
    repoRoot,
    timeoutMs,
  );

  if (!evidence.closeConfirmed) {
    return { providers: null, finding: { kind: 'registry-probe', detail: 'registry probe child close was not confirmed', evidence: summarizeProbe(evidence) } };
  }

  if (!evidence.ok) {
    return { providers: null, finding: { kind: 'registry-probe', detail: 'built registry could not be imported by a bounded child', evidence: summarizeProbe(evidence) } };
  }

  let parsed;

  try {
    parsed = JSON.parse(evidence.stdout);
  } catch (error) {
    return { providers: null, finding: { kind: 'registry-probe', detail: `registry probe output is not JSON: ${messageOf(error)}`, evidence: summarizeProbe(evidence) } };
  }

  return { providers: isRecord(parsed) ? parsed.providers : null, finding: null, evidence: summarizeProbe(evidence) };
}

/* ------------------------------------------------------------------ *
 * Checkout reading and report
 * ------------------------------------------------------------------ */

function readJson(source) {
  let text;

  try {
    text = readFileSync(source, 'utf8');
  } catch (error) {
    return { ok: false, reason: boundedText(`unreadable: ${messageOf(error)}`) };
  }

  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (error) {
    return { ok: false, reason: boundedText(`invalid JSON: ${messageOf(error)}`) };
  }
}

function readDocs(repoRoot) {
  const files = {};

  for (const name of ['README.md', 'CHANGELOG.md']) {
    const file = path.join(repoRoot, name);

    if (isRegularFile(file)) files[name] = readFileSync(file, 'utf8');
  }

  return files;
}

function makeCheck(id, status, findings, summary) {
  return { id, status, summary, findings };
}

/**
 * Inspect one checkout and return the report. `repoRoot` is never written to;
 * `options.rootSource` only labels how the root was chosen (no absolute paths
 * are reported, so a pasted report cannot leak a workspace path).
 */
export async function runReadiness(repoRoot, options) {
  const settings = isRecord(options) ? options : {};
  const started = Date.now();
  const rootSource = settings.rootSource === 'explicit' ? 'explicit' : 'script-location';
  const timeoutMs = Number.isInteger(settings.probeTimeoutMs) ? settings.probeTimeoutMs : PROBE_TIMEOUT_MS;

  const manifestRead = readJson(path.join(repoRoot, 'package.json'));
  const docsFiles = readDocs(repoRoot);
  const buildPresent = isRegularFile(path.join(repoRoot, REGISTRY_RELATIVE));
  const checks = [];

  const manifestFindings = manifestRead.ok
    ? validateManifest(manifestRead.value)
    : [{ kind: 'malformed-package', detail: `package.json could not be read: ${manifestRead.reason}` }];

  checks.push(makeCheck('manifest', manifestFindings.length === 0 ? 'passed' : 'failed', manifestFindings,
    manifestFindings.length === 0 ? 'name hooklatch, version 1.0.0, type module, engines >=22, zero runtime dependencies' : `${manifestFindings.length} manifest finding(s)`));

  const docsFindings = validateDocs(docsFiles);

  checks.push(makeCheck('docs-unreleased', docsFindings.length === 0 ? 'passed' : 'failed', docsFindings,
    docsFindings.length === 0 ? 'changelog records Unreleased; no unqualified publication claim' : `${docsFindings.length} documentation finding(s)`));

  if (manifestRead.ok) {
    const layoutFindings = [...validateExportMap(manifestRead.value), ...validateEntryPoints(manifestRead.value)];

    checks.push(makeCheck('module-layout', layoutFindings.length === 0 ? 'passed' : 'failed', layoutFindings,
      layoutFindings.length === 0 ? 'six entries retain neutral ESM, node ESM facade and node CJS arms; main/types/bin inside dist/' : `${layoutFindings.length} layout finding(s)`));

    if (buildPresent) {
      const targetReport = checkDeclaredTargets(manifestRead.value, (relative) => isRegularFile(path.join(repoRoot, relative)));

      checks.push(makeCheck('targets-present', targetReport.findings.length === 0 ? 'passed' : 'failed', targetReport.findings,
        targetReport.findings.length === 0 ? `${targetReport.resolved.length} declared target(s) present in the built tree` : `${targetReport.findings.length} missing or escaping target(s)`));
    } else {
      checks.push(makeCheck('targets-present', 'blocked', [], 'not evaluated: dist/ is not built'));
    }
  } else {
    checks.push(makeCheck('module-layout', 'blocked', [], 'not evaluated: package.json is unreadable'));
    checks.push(makeCheck('targets-present', 'blocked', [], 'not evaluated: package.json is unreadable'));
  }

  if (!buildPresent) {
    checks.push(makeCheck('built-registry', 'blocked', [], `not evaluated: ${REGISTRY_RELATIVE} is absent; run \`npm run build\` first`));
  } else {
    const probe = await probeRegistry(repoRoot, timeoutMs);
    const registryFindings = probe.finding === null ? compareProviders(probe.providers) : [probe.finding];

    checks.push(makeCheck('built-registry', registryFindings.length === 0 ? 'passed' : 'failed', registryFindings,
      registryFindings.length === 0
        ? `built registry exposes the exact ${EXPECTED_PROVIDERS.length} provider ids in order`
        : 'built registry could not be confirmed as the exact 21-provider set'));
  }

  const failedChecks = checks.filter((check) => check.status === 'failed').length;
  const exit = resolveVerdict(manifestFindings.length, buildPresent, failedChecks);

  let findingCount = 0;

  for (const check of checks) findingCount += check.findings.length;

  return {
    schemaVersion: 1,
    phase: '12 release readiness',
    checker: 'scripts/phase12/release-readiness.mjs',
    rootSource,
    status: statusFor(exit),
    exit,
    localReadiness: {
      ready: exit === EXIT.READY,
      checks,
      findings: findingCount,
    },
    localReadinessIsReleaseAuthorization: false,
    releaseAuthorized: false,
    external: externalEvidence(),
    notRunHere: {
      note: 'Existing gates own deep package, type, runtime and documentation qualification; this checker only inspects structure and presence and neither rebuilds nor replaces them.',
      commands: [...NOT_RUN_HERE],
    },
    limitations: [...LIMITATIONS],
    elapsedMs: Date.now() - started,
  };
}

/* ------------------------------------------------------------------ *
 * Self-test (pure controls only; no build inspection, no writes)
 * ------------------------------------------------------------------ */

/** The frozen shape the accepted manifest must have; also used by the controls. */
export function expectedExports() {
  const exportsMap = {};

  for (const entry of PUBLIC_ENTRIES) {
    const arms = {};

    for (const expected of expectedTargets(entry)) {
      arms[expected.arm] = expected.target;
    }

    exportsMap[entry.subpath] = {
      node: {
        import: { types: arms['node.import.types'], default: arms['node.import.default'] },
        require: { types: arms['node.require.types'], default: arms['node.require.default'] },
      },
      types: arms.types,
      import: arms.import,
      default: arms.default,
    };
  }

  return exportsMap;
}

export function baseManifest() {
  return {
    name: PACKAGE_NAME,
    version: EXPECTED_VERSION,
    type: 'module',
    engines: { node: EXPECTED_NODE_ENGINE },
    main: './dist/cjs/index.cjs',
    types: './dist/index.d.ts',
    bin: { hooklatch: './dist/cli/index.js' },
    exports: expectedExports(),
  };
}

function allTargetsExist() {
  const files = new Set();

  for (const entry of PUBLIC_ENTRIES) {
    for (const expected of expectedTargets(entry)) files.add(expected.target.slice('./'.length));
  }

  files.add('dist/cjs/index.cjs');
  files.add('dist/index.d.ts');
  files.add('dist/cli/index.js');

  return (relative) => files.has(relative);
}

export function runSelfTest() {
  const controls = [];

  const record = (id, run) => {
    try {
      const detail = run();

      controls.push({ id, passed: detail.passed, detail: detail.detail });
    } catch (error) {
      controls.push({ id, passed: false, detail: messageOf(error) });
    }
  };

  record('baseline-manifest-accepted', () => {
    const manifest = baseManifest();

    const findings = [
      ...validateManifest(manifest),
      ...validateExportMap(manifest),
      ...validateEntryPoints(manifest),
    ];

    const targets = checkDeclaredTargets(manifest, allTargetsExist());

    return { passed: findings.length === 0 && targets.findings.length === 0, detail: { findings, resolved: targets.resolved.length } };
  });

  record('manifest-mutations-detected', () => {
    const mutations = [
      (copy) => { copy.name = 'other-package'; },
      (copy) => { copy.version = '1.0.1'; },
      (copy) => { delete copy.type; },
      (copy) => { copy.engines = { node: '>=20' }; },
      (copy) => { copy.dependencies = { 'left-pad': '1.0.0' }; },
      (copy) => { copy.optionalDependencies = { fsevents: '2.0.0' }; },
    ];

    const missed = [];

    for (const mutate of mutations) {
      const copy = structuredClone(baseManifest());

      mutate(copy);

      if (validateManifest(copy).length === 0) missed.push(mutate.toString());
    }

    return { passed: missed.length === 0, detail: { mutations: mutations.length, missed } };
  });

  record('export-map-mutations-detected', () => {
    const cases = [
      (copy) => { delete copy.exports['./hono']; },
      (copy) => { copy.exports['./extra'] = copy.exports['.']; },
      (copy) => { copy.exports['.'].node.require.default = './dist/index.js'; },
      (copy) => { copy.exports['./express'].import = './dist/node/adapters/express.js'; },
      (copy) => { copy.exports['./diagnostics'].types = '../outside.d.ts'; },
      (copy) => { copy.main = '../package-escape.cjs'; },
      (copy) => { copy.bin = { hooklatch: './dist/cli/index.mjs' }; },
    ];

    const missed = [];

    for (const mutate of cases) {
      const copy = structuredClone(baseManifest());

      mutate(copy);

      const findings = [...validateExportMap(copy), ...validateEntryPoints(copy)];

      if (findings.length === 0) missed.push(mutate.toString());
    }

    return { passed: missed.length === 0, detail: { cases: cases.length, missed } };
  });

  record('missing-target-detected', () => {
    const manifest = baseManifest();
    const missing = 'dist/cjs/adapters/hono.cjs';
    const existsAt = allTargetsExist();
    const present = checkDeclaredTargets(manifest, existsAt);
    const absent = checkDeclaredTargets(manifest, (relative) => relative !== missing && existsAt(relative));

    return {
      passed: present.findings.length === 0
        && absent.findings.length === 1
        && absent.findings[0].target === missing,
      detail: { present: present.findings.length, absent: absent.findings },
    };
  });

  record('registry-comparison', () => {
    const exact = compareProviders([...EXPECTED_PROVIDERS]);
    const shortSet = compareProviders(EXPECTED_PROVIDERS.slice(0, EXPECTED_PROVIDERS.length - 1));
    const reordered = [...EXPECTED_PROVIDERS];
    const duplicated = [...EXPECTED_PROVIDERS, EXPECTED_PROVIDERS[0]];

    reordered[0] = EXPECTED_PROVIDERS[1];
    reordered[1] = EXPECTED_PROVIDERS[0];

    return {
      passed: exact.length === 0
        && shortSet.length === 1 && shortSet[0].kind === 'registry-mismatch' && shortSet[0].observedCount === EXPECTED_PROVIDERS.length - 1
        && compareProviders(reordered).length === 1
        && compareProviders(duplicated).length === 1
        && compareProviders(null).length === 1
        && EXPECTED_PROVIDERS.length === 21,
      detail: { expected: EXPECTED_PROVIDERS.length },
    };
  });

  record('documentation-claims-detected', () => {
    const unreleased = validateDocs({
      'README.md': 'Publication to npm is pending. For a published release: npm install hooklatch',
      'CHANGELOG.md': '# Changelog\n\n## Unreleased\n\nNo npm release or Git tag is recorded.\n',
    });

    const claimed = validateDocs({
      'README.md': 'Hooklatch is published to npm.',
      'CHANGELOG.md': '# Changelog\n\n## Unreleased\n',
    });

    const noHeading = validateDocs({ 'CHANGELOG.md': '# Changelog\n\n## 1.0.0\n' });

    return {
      passed: unreleased.length === 0
        && claimed.length === 1 && claimed[0].kind === 'publication-claim'
        && noHeading.length === 1 && noHeading[0].kind === 'changelog-unreleased-section',
      detail: { unreleased, claimed, noHeading },
    };
  });

  record('external-requirements-never-pass', () => {
    const first = externalEvidence();

    first[0].status = 'passed';

    const second = externalEvidence();

    return {
      passed: second.length === 5
        && second.every((item) => item.status === 'manual-required' || item.status === 'not-checked')
        && second.some((item) => item.status === 'manual-required'),
      detail: { ids: second.map((item) => item.id), statuses: second.map((item) => item.status) },
    };
  });

  record('verdict-mapping', () => {
    const mapping = [
      [resolveVerdict(1, true, 0), EXIT.DEFECT],
      [resolveVerdict(1, false, 0), EXIT.DEFECT],
      [resolveVerdict(0, false, 0), EXIT.BLOCKED],
      [resolveVerdict(0, true, 1), EXIT.DEFECT],
      [resolveVerdict(0, true, 0), EXIT.READY],
    ];

    return { passed: mapping.every(([observed, expected]) => observed === expected), detail: mapping };
  });

  const passed = controls.every((control) => control.passed === true);

  return {
    status: passed ? 'CONTROLS-PASS' : 'CONTROLS-FAILED',
    controlsOnly: true,
    note: 'Pure checker-function controls only; not product, build or release evidence.',
    controls,
  };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

export function parseArguments(argv) {
  const options = { help: false, selfTest: false, root: null };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else if (argument === '--self-test') {
      options.selfTest = true;
    } else if (argument === '--root') {
      const value = argv[index + 1];

      if (value === undefined || value.startsWith('--')) throw new UsageError('--root requires a directory path.');

      options.root = value;
      index += 1;
    } else if (argument.startsWith('--root=')) {
      const value = argument.slice('--root='.length);

      if (value.length === 0) throw new UsageError('--root requires a directory path.');

      options.root = value;
    } else {
      throw new UsageError(`unknown argument: ${argument}`);
    }
  }

  return options;
}

export function defaultRepoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

export async function main(argv) {
  let parsed;

  try {
    parsed = parseArguments(argv);
  } catch (error) {
    console.error(`${messageOf(error)}\n\n${USAGE}`);

    return EXIT.USAGE;
  }

  if (parsed.help) {
    console.log(USAGE);

    return EXIT.READY;
  }

  if (parsed.selfTest) {
    const report = runSelfTest();

    console.log(JSON.stringify(report, null, 2));

    return report.status === 'CONTROLS-PASS' ? EXIT.READY : EXIT.DEFECT;
  }

  const repoRoot = parsed.root === null ? defaultRepoRoot() : path.resolve(parsed.root);
  const report = await runReadiness(repoRoot, { rootSource: parsed.root === null ? 'script-location' : 'explicit' });

  console.log(JSON.stringify(report, null, 2));

  return report.exit;
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = await main(process.argv.slice(2));
}
