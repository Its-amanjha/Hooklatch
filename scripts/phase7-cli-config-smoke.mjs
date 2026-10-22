/**
 * Phase 7 configured generated-handler qualification.
 *
 *   node scripts/phase7-cli-config-smoke.mjs            # normal run
 *   node scripts/phase7-cli-config-smoke.mjs --self-test # harness controls only
 *   node scripts/phase7-cli-config-smoke.mjs --help     # usage
 *
 * Run AFTER `npm run build`.
 *
 * WHAT THIS PROVES
 *   When the coordinator has integrated the 18-provider registry and the new
 *   configuration CLI flags, this script packs the local tarball, installs it
 *   offline into a checked OS-temp consumer, and drives the INSTALLED bin to
 *   generate every primary provider/framework combination plus the configured
 *   Grafana and Polar variants. Each generated file is checked structurally
 *   (comment-stripped providerOptions, never bare value substrings) for its exact
 *   location, byte determinism across two runs, forwarded provider options,
 *   secret-env placeholders and body limit, and is then compiled by an
 *   independent strict NodeNext program against the installed exports and the
 *   pinned peer trees. The tracked checkout bytes are snapshotted before and
 *   after to prove the run did not mutate the repository.
 *
 * WHAT THIS DOES NOT PROVE
 *   At the 16-provider base the readiness gate exits 3 (BLOCKED) BEFORE any temp
 *   allocation, install, generation, or self-test control work. The `--self-test`
 *   controls prove only that this harness can detect its own failure modes and
 *   that the shared helpers work against real generated artifacts. They are NOT
 *   evidence of SDK support for Grafana or Polar. Nothing here claims provider,
 *   runtime or platform support.
 *
 * Exit codes:
 *   0  All selected real checks and cleanup passed.
 *   1  A real qualification check failed.
 *   2  Invalid invocation.
 *   3  Not ready (upstream dependency missing); no temp was allocated.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const IS_WINDOWS = process.platform === 'win32';
const TS_MODULE_PATH = path.join(REPO_ROOT, 'node_modules', 'typescript', 'lib', 'typescript.js');

// Pinned TypeScript compiler API, used only for static binding of generated
// handlers. Loaded from the repo toolchain; null when the tree is unprepared.
const tsModule = existsSync(TS_MODULE_PATH) ? await import(pathToFileURL(TS_MODULE_PATH).href) : null;
const ts = tsModule === null ? null : tsModule.default ?? tsModule;

const EXIT_PASS = 0;
const EXIT_FAIL = 1;
const EXIT_USAGE = 2;
const EXIT_NOT_READY = 3;

const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'];
const EXISTING_PROVIDER_COUNT = 16;
const TARGET_PROVIDERS = 18;
const NEW_PROVIDERS = ['grafana', 'polar'];

const BODY_LIMIT = 4242;
const TEMP_PREFIX = 'hooklatch-phase7-cli-config-';
const TARGET_PREFIX = 'hooklatch-phase7-target-';
const MAX_CAPTURE_BYTES = 20000;

/**
 * Exact expected 18-provider order: the existing 16 (registry order at this base)
 * followed by grafana and polar, per notes/phase-7/contract.md.
 */
const EXPECTED_PROVIDER_ORDER = [
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
];

/**
 * Exhaustive, independent secret-env expectation for all 18 providers. The 16
 * existing values mirror src/cli/args.ts DEFAULT_SECRET_ENV; grafana/polar are
 * the Stage B names from notes/phase-7/contract.md. This table is intentionally
 * duplicated here so the harness never trusts the production map it is checking.
 */
const EXPECTED_SECRET_ENV = {
  stripe: 'STRIPE_WEBHOOK_SECRET',
  github: 'GITHUB_WEBHOOK_SECRET',
  shopify: 'SHOPIFY_WEBHOOK_SECRET',
  'standard-webhooks': 'STANDARD_WEBHOOKS_SECRET',
  clerk: 'CLERK_WEBHOOK_SIGNING_SECRET',
  svix: 'SVIX_WEBHOOK_SECRET',
  razorpay: 'RAZORPAY_WEBHOOK_SECRET',
  paddle: 'PADDLE_WEBHOOK_SECRET',
  'lemon-squeezy': 'LEMON_SQUEEZY_WEBHOOK_SECRET',
  'dodo-payments': 'DODO_WEBHOOK_SECRET',
  gitlab: 'GITLAB_WEBHOOK_SECRET',
  replicate: 'REPLICATE_WEBHOOK_SECRET',
  workos: 'WORKOS_WEBHOOK_SECRET',
  sentry: 'SENTRY_WEBHOOK_SECRET',
  doppler: 'DOPPLER_WEBHOOK_SECRET',
  sanity: 'SANITY_WEBHOOK_SECRET',
  grafana: 'GRAFANA_WEBHOOK_SECRET',
  polar: 'POLAR_WEBHOOK_SECRET',
};

/** Flags the coordinator adds in Stage B; readiness requires help to advertise them. */
const REQUIRED_CLI_FLAGS = ['--grafana-mode', '--signature-header', '--timestamp-header', '--polar-secret-mode'];

/**
 * An RFC 9110 field-name token that is legal as a config value but contains
 * characters a careless emitter could mishandle (apostrophe, backtick, plus).
 * The CLI must accept it and the generator must emit it as a safe literal.
 */
const HOSTILE_VALID_HEADER = "x-weird'`+inj";

/**
 * Primary matrix: every registered provider × four frameworks (18 × 4 = 72).
 * Grafana needs an explicit body mode and its providerOptions must carry it.
 */
function primaryCases(providers) {
  const cases = [];

  for (const provider of providers) {
    for (const framework of FRAMEWORKS) {
      const args = ['--provider', provider, '--framework', framework];

      if (provider === 'grafana') args.push('--grafana-mode', 'body');

      cases.push({
        id: `${provider}/${framework}`,
        provider,
        framework,
        args,
        expect: { providerOptions: primaryProviderOptions(provider) },
      });
    }
  }

  return cases;
}

/** Expected providerOptions for a primary case (absent, explicit, or either). */
function primaryProviderOptions(provider) {
  if (provider === 'grafana') return { mode: 'body' };

  if (provider === 'polar') return { anyOf: [null, { secretMode: 'current' }] };

  return null;
}

/**
 * Configured variants: timestamped Grafana with custom headers, timestamped
 * Grafana with a hostile-but-valid header token, and Polar legacy. Each runs on
 * all four frameworks so providerOptions forwarding is proven per framework.
 */
function configuredCases() {
  const cases = [];

  for (const framework of FRAMEWORKS) {
    cases.push({
      id: `grafana-timestamped/${framework}`,
      provider: 'grafana',
      framework,
      args: [
        '--provider', 'grafana',
        '--framework', framework,
        '--grafana-mode', 'timestamped',
        '--signature-header', 'x-custom-signature',
        '--timestamp-header', 'x-custom-timestamp',
      ],
      expect: {
        providerOptions: { mode: 'timestamped', signatureHeader: 'x-custom-signature', timestampHeader: 'x-custom-timestamp' },
      },
    });

    cases.push({
      id: `grafana-hostile-token/${framework}`,
      provider: 'grafana',
      framework,
      args: [
        '--provider', 'grafana',
        '--framework', framework,
        '--grafana-mode', 'timestamped',
        '--signature-header', HOSTILE_VALID_HEADER,
        '--timestamp-header', 'x-custom-timestamp',
      ],
      expect: {
        providerOptions: { mode: 'timestamped', signatureHeader: HOSTILE_VALID_HEADER, timestampHeader: 'x-custom-timestamp' },
      },
    });

    cases.push({
      id: `polar-legacy/${framework}`,
      provider: 'polar',
      framework,
      args: ['--provider', 'polar', '--framework', framework, '--polar-secret-mode', 'legacy'],
      expect: { providerOptions: { secretMode: 'legacy' } },
    });
  }

  return cases;
}

/** Expected target file name per framework (mirrors src/cli/filesystem.ts targetFileName). */
function expectedFileName(provider, framework) {
  if (framework === 'nextjs') return 'route.ts';

  if (framework === 'cloudflare') return `${provider}.cloudflare.ts`;

  if (framework === 'hono') return `${provider}.hono.ts`;

  return `${provider}.express.ts`;
}

function fail(message) {
  throw new Error(message);
}

/* ------------------------------------------------------------------ *
 * Bounded child processes and redacted diagnostics
 * ------------------------------------------------------------------ */

function redact(value) {
  return String(value)
    .replace(/whsec_[A-Za-z0-9_.-]+/g, 'whsec_[REDACTED]')
    .replace(/CANARY_[A-Za-z0-9_]+/g, '[REDACTED_CANARY]')
    .replace(/\b[a-f0-9]{64}\b/gi, '[REDACTED_HEX_64]')
    .slice(0, MAX_CAPTURE_BYTES);
}

/**
 * Process-health ledger. A child that timed out or was signaled may still have
 * descendants running, so recursive scratch deletion is withheld.
 */
const processHealth = { uncertain: false, reasons: [] };

function resetProcessHealth() {
  processHealth.uncertain = false;
  processHealth.reasons = [];
}

function markTerminationUncertain(reason) {
  processHealth.uncertain = true;

  if (!processHealth.reasons.includes(reason)) processHealth.reasons.push(reason);
}

/** Synchronous bounded run; returns { status, stdout, stderr, timedOut } without throwing on nonzero. */
function runSync(command, args, cwd, options = {}) {
  const { timeoutMs = 180000, env } = options;

  const base = {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: timeoutMs,
    maxBuffer: MAX_CAPTURE_BYTES * 4,
  };

  try {
    const stdout = execFileSync(command, args, env === undefined ? base : { ...base, env });

    return { status: 0, stdout, stderr: '', timedOut: false };
  } catch (error) {
    const timedOut = childTimedOut(error);

    if (timedOut) markTerminationUncertain(`${command} timed out`);
    else if (childWasSignaled(error)) markTerminationUncertain(`${command} was signaled`);

    return {
      status: childExitStatus(error),
      stdout: redact(error.stdout ?? ''),
      stderr: redact(error.stderr ?? String(error.message ?? '')),
      timedOut,
    };
  }
}

/** Extract a numeric process exit status from an execFileSync rejection. */
function childExitStatus(error) {
  const carrier = Object(error);
  const status = Object.hasOwn(carrier, 'status') ? carrier.status : -1;

  return Number.isInteger(status) ? status : -1;
}

/** Detect a timeout kill so it is always treated as infrastructure failure. */
function childTimedOut(error) {
  const carrier = Object(error);

  if (Object.hasOwn(carrier, 'signal') && carrier.signal) return true;

  return Object.hasOwn(carrier, 'code') && carrier.code === 'ETIMEDOUT';
}

/** Detect any signaled/killed child, not only a timeout. */
function childWasSignaled(error) {
  const carrier = Object(error);

  if (Object.hasOwn(carrier, 'signal') && carrier.signal) return true;

  return Object.hasOwn(carrier, 'killed') && carrier.killed === true;
}

/** Assert an expected exit; a timeout or any other code is a real failure. */
function expectExit(result, expected, label) {
  if (result.timedOut) fail(`${label} timed out (infrastructure failure).`);

  if (result.status !== expected) {
    fail(`${label} exited ${result.status}; expected ${expected}. ${result.stderr || result.stdout}`);
  }
}

/* ------------------------------------------------------------------ *
 * Checked temp workspace with an authoritative junction ledger
 * ------------------------------------------------------------------ */

function assertInsideTemp(target) {
  const tempRoot = path.resolve(os.tmpdir());
  const resolved = path.resolve(target);
  const relative = path.relative(tempRoot, resolved);

  assert(relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    `Refusing to operate on a path outside OS temp: ${resolved}`);
}

function assertExpectedName(resolved, expectedPrefix) {
  assert(path.basename(resolved).startsWith(expectedPrefix),
    `Refusing to operate on a temp path without the expected prefix: ${resolved}`);
}

/**
 * Create a workspace with an OUTER authoritative ledger. Every link is tracked
 * immediately at (before) creation, so a mid-control failure can never leave the
 * ledger empty while a junction exists.
 */
function createWorkspace(prefix = TEMP_PREFIX) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));

  assertInsideTemp(root);
  assertExpectedName(root, prefix);

  return { root, links: [] };
}

/** Track a link inside the workspace root (call BEFORE creating the link). */
function trackLink(workspace, linkPath) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(workspace.root, resolved);

  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    fail(`Refusing to track a link outside the workspace: ${resolved}`);
  }

  workspace.links.push(resolved);
}

/** Create a junction/symlink and track it immediately, even if creation fails. */
function createTrackedJunction(workspace, target, linkPath) {
  const resolved = path.resolve(linkPath);

  mkdirSync(path.dirname(resolved), { recursive: true });
  trackLink(workspace, resolved);
  symlinkSync(target, resolved, IS_WINDOWS ? 'junction' : 'dir');

  return resolved;
}

/** Unlink a dependency junction/symlink; fail closed on an ordinary directory. */
function safeUnlinkLink(linkPath, expectedParent) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(path.resolve(expectedParent), resolved);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Refusing to remove a link outside its expected parent: ${resolved}`);
  }

  let stat;

  try { stat = lstatSync(resolved); } catch (error) { if (error.code === 'ENOENT') return; throw error; }

  let isLink = stat.isSymbolicLink();

  if (!isLink && IS_WINDOWS && stat.isDirectory()) {
    try { readlinkSync(resolved); isLink = true; } catch { isLink = false; }
  }

  if (!isLink) throw new Error(`Expected a junction or symlink at ${resolved}, found an ordinary path. Refusing.`);

  try { unlinkSync(resolved); } catch { rmdirSync(resolved); }

  if (existsSync(resolved)) throw new Error(`Failed to unlink the dependency link at ${resolved}.`);
}

/**
 * Unlink every tracked link, then remove the workspace root. If any step fails
 * the root is deliberately PRESERVED (process termination uncertain) and the
 * failure is propagated; it never silently leaves a junction behind.
 */
function disposeWorkspace(workspace) {
  assertInsideTemp(workspace.root);

  if (processHealth.uncertain) {
    throw new Error(
      `Cleanup withheld because child termination is uncertain (${processHealth.reasons.join('; ')}); scratch preserved at ${workspace.root}.`,
    );
  }

  const failures = [];

  for (const link of workspace.links) {
    try { safeUnlinkLink(link, workspace.root); } catch (error) { failures.push(`unlink ${link}: ${error.message}`); }
  }

  if (failures.length === 0) {
    try { rmSync(workspace.root, { recursive: true, force: true }); } catch (error) { failures.push(`remove root: ${error.message}`); }

    if (existsSync(workspace.root)) failures.push(`root still exists: ${workspace.root}`);
  }

  if (failures.length > 0) {
    throw new Error(`Cleanup failed; scratch preserved at ${workspace.root}: ${failures.join('; ')}`);
  }
}

/* ------------------------------------------------------------------ *
 * Byte integrity snapshots
 * ------------------------------------------------------------------ */

/** Hash tracked checkout bytes (git ls-files) so git status alone is not trusted. */
function snapshotTrackedBytes() {
  const listed = runSync('git', ['ls-files', '-z'], REPO_ROOT);

  expectExit(listed, 0, 'git ls-files');

  const files = listed.stdout.split('\0').filter((entry) => entry.length > 0).sort();
  const hash = createHash('sha256');

  for (const relative of files) {
    hash.update(relative);
    hash.update('\0');
    hash.update(readFileSync(path.join(REPO_ROOT, relative)));
    hash.update('\0');
  }

  return { count: files.length, digest: hash.digest('hex') };
}

/** Deterministic tree hash; never follows junctions/symlinks. */
function snapshotTree(root, skipNames) {
  const hash = createHash('sha256');

  walkTree(root, root, hash, skipNames);

  return hash.digest('hex');
}

function walkTree(root, dir, hash, skipNames) {
  const names = readdirSync(dir).sort();

  for (const name of names) {
    if (skipNames.has(name)) continue;

    const full = path.join(dir, name);
    const stat = lstatSync(full);

    if (stat.isSymbolicLink()) continue;

    const relative = path.relative(root, full);

    if (stat.isDirectory()) {
      hash.update(`D:${relative}\0`);
      walkTree(root, full, hash, skipNames);
    } else if (stat.isFile()) {
      hash.update(`F:${relative}\0`);
      hash.update(readFileSync(full));
      hash.update('\0');
    }
  }
}

/** Built artifacts are read-only run inputs; their bytes must not change. */
function snapshotBuiltArtifacts() {
  const dist = path.join(REPO_ROOT, 'dist');

  if (!existsSync(dist)) return { present: false, digest: '' };

  return { present: true, digest: snapshotTree(dist, new Set()) };
}

/** Combined run-input snapshot: tracked checkout bytes plus built dist bytes. */
function snapshotRunInputs() {
  return { tracked: snapshotTrackedBytes(), built: snapshotBuiltArtifacts() };
}

/** Report a change to either input set; called even when the run itself failed. */
function compareRunInputs(before, after, label) {
  if (before.tracked.digest !== after.tracked.digest || before.tracked.count !== after.tracked.count) {
    fail(`${label} changed tracked checkout bytes (${before.tracked.count} -> ${after.tracked.count} files).`);
  }

  if (before.built.present !== after.built.present || before.built.digest !== after.built.digest) {
    fail(`${label} changed built dist/ bytes.`);
  }
}

/* ------------------------------------------------------------------ *
 * Readiness gates (pure decisions + thin I/O wrappers)
 * ------------------------------------------------------------------ */

/** Pure readiness decision for a built registry value (separately self-tested). */
function decideRegistryReadiness(providers) {
  if (!Array.isArray(providers) || providers.length === 0) {
    return { ready: false, reason: 'The built registry did not expose a nonempty SUPPORTED_PROVIDERS array.' };
  }

  if (providers.length !== TARGET_PROVIDERS) {
    return {
      ready: false,
      reason: `Registry has ${providers.length} providers; the configured CLI matrix requires exactly ${TARGET_PROVIDERS}.`,
    };
  }

  const unique = new Set(providers);

  if (unique.size !== TARGET_PROVIDERS) {
    return { ready: false, reason: 'Registry provider IDs are not unique.' };
  }

  for (let index = 0; index < TARGET_PROVIDERS; index += 1) {
    if (providers[index] !== EXPECTED_PROVIDER_ORDER[index]) {
      return {
        ready: false,
        reason: `Registry provider #${index} is ${JSON.stringify(providers[index])}; expected ${JSON.stringify(EXPECTED_PROVIDER_ORDER[index])}.`,
      };
    }
  }

  return { ready: true };
}

/** Pure readiness decision for CLI help text (separately self-tested). */
function decideFlagsReadiness(helpText) {
  const missing = REQUIRED_CLI_FLAGS.filter((flag) => !helpText.includes(flag));

  if (missing.length > 0) {
    return { ready: false, reason: `CLI help does not advertise: ${missing.join(', ')}.` };
  }

  return { ready: true };
}

/** Combined readiness: registry first, then flags; both pure and separately tested. */
function evaluateReadiness({ providers, helpText }) {
  const registry = decideRegistryReadiness(providers);

  if (!registry.ready) return registry;

  return decideFlagsReadiness(helpText);
}

async function loadBuiltRegistryProviders() {
  const registryPath = path.join(REPO_ROOT, 'dist', 'providers', 'index.js');

  if (!existsSync(registryPath)) {
    return { present: false, reason: 'dist/providers/index.js is missing; run npm run build first.' };
  }

  const module = await import(pathToFileURL(registryPath).href);

  return { present: true, providers: module.SUPPORTED_PROVIDERS };
}

function builtCliPath() {
  return path.join(REPO_ROOT, 'dist', 'cli', 'index.js');
}

function readCliHelp(cli, cwd) {
  const help = runSync(process.execPath, [cli, '--help'], cwd);

  expectExit(help, 0, `CLI --help (${cli})`);

  return help.stdout;
}

/* ------------------------------------------------------------------ *
 * Structural providerOptions inspection (comment-proof)
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * AST binding of generated handlers (pinned TypeScript)
 * ------------------------------------------------------------------ */

/** Expected adapter import per framework, from the CLI template contract. */
const ADAPTER_IMPORTS = {
  express: { module: 'hooklatch/express', name: 'createWebhookMiddleware' },
  hono: { module: 'hooklatch/hono', name: 'createWebhookMiddleware' },
  nextjs: { module: 'hooklatch/nextjs', name: 'createWebhookHandler' },
  cloudflare: { module: 'hooklatch/cloudflare', name: 'createWebhookHandler' },
};

function requireTypeScript() {
  if (ts === null) fail('The pinned TypeScript compiler API is unavailable; restore the prepared dependency snapshot.');

  return ts;
}

/** Parse generated TypeScript and reject syntax errors before binding. */
function parseGeneratedSource(caseSpec, source) {
  const T = requireTypeScript();

  const sourceFile = T.createSourceFile(
    `generated-${caseSpec.id.replaceAll('/', '-')}.ts`,
    source,
    T.ScriptTarget.Latest,
    true,
    T.ScriptKind.TS,
  );

  if (sourceFile.parseDiagnostics.length > 0) {
    fail(`Generated handler ${caseSpec.id} has TypeScript syntax errors.`);
  }

  return sourceFile;
}

/** Property name text for identifier/string-literal keys. */
function propertyKeyName(name, T) {
  if (T.isIdentifier(name)) return name.text;

  if (T.isStringLiteral(name) || T.isNoSubstitutionTemplateLiteral(name)) return name.text;

  return null;
}

/** Find a direct literal property assignment on an object literal. */
function findProperty(objectLiteral, name, T) {
  for (const property of objectLiteral.properties) {
    if (!T.isPropertyAssignment(property)) continue;

    if (propertyKeyName(property.name, T) === name) return property;
  }

  return null;
}

function unwrapExpression(node, T) {
  let current = node;

  while (T.isParenthesizedExpression(current)) current = current.expression;

  return current;
}

/** Resolve an identifier to a `const name = { ... }` declaration, or inline object. */
function resolveObjectLiteral(node, variables, T) {
  const expression = unwrapExpression(node, T);

  if (T.isIdentifier(expression)) return variables.get(expression.text) ?? null;

  if (T.isObjectLiteralExpression(expression)) return expression;

  return null;
}

/** Resolve an arrow/function factory (Workers `options: (env) => ({...})`). */
function resolveReturnedObject(node, variables, T) {
  const expression = unwrapExpression(node, T);

  if (T.isArrowFunction(expression) || T.isFunctionExpression(expression)) {
    const body = expression.body;

    if (T.isObjectLiteralExpression(body)) return body;

    if (T.isBlock(body)) {
      for (const statement of body.statements) {
        if (!T.isReturnStatement(statement) || statement.expression === undefined) continue;

        const returned = unwrapExpression(statement.expression, T);

        if (T.isObjectLiteralExpression(returned)) return returned;
      }

      return null;
    }

    const returned = unwrapExpression(body, T);

    return T.isObjectLiteralExpression(returned) ? returned : null;
  }

  return resolveObjectLiteral(expression, variables, T);
}

/** Collect only top-level const objects; nested declarations have other bindings. */
function collectObjectDeclarations(sourceFile, T) {
  const variables = new Map();

  for (const statement of sourceFile.statements) {
    if (!T.isVariableStatement(statement) || (statement.declarationList.flags & T.NodeFlags.Const) === 0) continue;

    for (const node of statement.declarationList.declarations) {
      if (!T.isIdentifier(node.name) || node.initializer === undefined || !T.isObjectLiteralExpression(node.initializer)) continue;

      if (variables.has(node.name.text)) fail('Generated handler has ambiguous options declarations.');

      variables.set(node.name.text, node.initializer);
    }
  }

  return variables;
}

function findCallNamed(node, T, localName) {
  const expression = unwrapExpression(node, T);

  return T.isCallExpression(expression) && T.isIdentifier(expression.expression) && expression.expression.text === localName ? expression : null;
}

function hasExportModifier(node, T) {
  if (node.modifiers === undefined) return false;

  return node.modifiers.some((modifier) => modifier.kind === T.SyntaxKind.ExportKeyword);
}

/**
 * Find the adapter call that is actually exported. A dead (non-exported) decoy
 * call or declaration can never be selected.
 */
function findExportedAdapterCall(sourceFile, T, localName) {
  const calls = [];

  for (const statement of sourceFile.statements) {
    let candidate = null;

    if (T.isVariableStatement(statement) && hasExportModifier(statement, T)) {
      for (const declaration of statement.declarationList.declarations) {
        if (declaration.initializer === undefined) continue;

        candidate = findCallNamed(declaration.initializer, T, localName);

        if (candidate !== null) calls.push(candidate);
      }

      continue;
    }

    if (T.isExportAssignment(statement)) {
      candidate = findCallNamed(statement.expression, T, localName);
    }

    if (candidate !== null) calls.push(candidate);
  }

  if (calls.length > 1) fail('Generated handler has ambiguous multiple exported adapter calls.');

  return calls[0] ?? null;
}

/**
 * Bind the inspection to the imported adapter call and the exact options it
 * consumes: an identifier reference, a nextjs `...options` spread, or the
 * cloudflare Workers `options: (env) => ({...})` factory.
 */
function resolveBoundOptions(caseSpec, call, variables, T) {
  if (call.arguments.length === 0) return null;

  const argument = unwrapExpression(call.arguments[0], T);

  if (caseSpec.framework === 'cloudflare') {
    if (!T.isObjectLiteralExpression(argument)) return null;

    if (argument.properties.some((property) => T.isSpreadAssignment(property))) {
      fail('Generated handler has ambiguous Workers options spreads.');
    }

    const factory = findProperty(argument, 'options', T);

    if (factory === null) return null;

    return resolveReturnedObject(factory.initializer, variables, T);
  }

  if (T.isObjectLiteralExpression(argument)) {
    const spreads = argument.properties.filter((property) => T.isSpreadAssignment(property));

    if (spreads.length > 0) {
      const [spread, handler] = argument.properties;

      // The emitted Next handler has exactly {...options, handler: ...}.
      // Reject other spreads/properties rather than overlooking an override.
      if (caseSpec.framework !== 'nextjs' || argument.properties.length !== 2 || !T.isSpreadAssignment(spread)
        || !T.isIdentifier(spread.expression) || !T.isPropertyAssignment(handler) || propertyKeyName(handler.name, T) !== 'handler') {
        fail('Generated handler has ambiguous options spreads or overrides.');
      }

      const bound = variables.get(spread.expression.text) ?? null;

      if (bound !== null && bound.properties.some((property) => T.isSpreadAssignment(property))) {
        fail('Generated handler has ambiguous nested options spreads.');
      }

      return bound;
    }

    return argument;
  }

  return resolveObjectLiteral(argument, variables, T);
}

/** Parse a literal providerOptions value into a Map (non-literals are rejected). */
function readProviderOptions(bound, caseSpec) {
  const T = requireTypeScript();
  const property = findProperty(bound, 'providerOptions', T);

  if (property === null) return null;

  const value = unwrapExpression(property.initializer, T);

  if (!T.isObjectLiteralExpression(value)) {
    fail(`Generated handler ${caseSpec.id} providerOptions is not an object literal.`);
  }

  const entries = new Map();

  for (const entry of value.properties) {
    if (!T.isPropertyAssignment(entry)) {
      fail(`Generated handler ${caseSpec.id} providerOptions contains a non-literal member.`);
    }

    const key = propertyKeyName(entry.name, T);

    if (key === null) fail(`Generated handler ${caseSpec.id} providerOptions has a computed key.`);

    const literal = entry.initializer;

    if (T.isStringLiteral(literal) || T.isNoSubstitutionTemplateLiteral(literal)) {
      entries.set(key, literal.text);
      continue;
    }

    if (T.isNumericLiteral(literal)) { entries.set(key, literal.text); continue; }

    if (literal.kind === T.SyntaxKind.TrueKeyword) { entries.set(key, 'true'); continue; }

    if (literal.kind === T.SyntaxKind.FalseKeyword) { entries.set(key, 'false'); continue; }

    fail(`Generated handler ${caseSpec.id} providerOptions.${key} is not a literal.`);
  }

  return entries;
}

/** Bind the generated file and return { sourceFile, bound, providerOptions }. */
function inspectBoundHandler(caseSpec, source) {
  const T = requireTypeScript();
  const sourceFile = parseGeneratedSource(caseSpec, source);
  const expectedImport = ADAPTER_IMPORTS[caseSpec.framework];
  let importBinding = null;

  for (const statement of sourceFile.statements) {
    if (!T.isImportDeclaration(statement) || statement.moduleSpecifier.text !== expectedImport.module) continue;

    const bindings = statement.importClause === undefined ? undefined : statement.importClause.namedBindings;

    if (bindings === undefined || !T.isNamedImports(bindings)) continue;

    for (const element of bindings.elements) {
      const imported = element.propertyName === undefined ? element.name.text : element.propertyName.text;

      if (imported === expectedImport.name) importBinding = element.name.text;
    }
  }

  if (importBinding === null) {
    fail(`Generated handler ${caseSpec.id} does not import ${expectedImport.name} from '${expectedImport.module}'.`);
  }

  const call = findExportedAdapterCall(sourceFile, T, importBinding);

  if (call === null) fail(`Generated handler ${caseSpec.id} has no exported ${expectedImport.name} call.`);

  const variables = collectObjectDeclarations(sourceFile, T);
  const bound = resolveBoundOptions(caseSpec, call, variables, T);

  if (bound === null) fail(`Generated handler ${caseSpec.id} does not bind its adapter call to a literal options object.`);

  if (bound.properties.some((property) => T.isSpreadAssignment(property))) {
    fail('Generated handler has ambiguous nested options spreads.');
  }

  return { sourceFile, bound, providerOptions: readProviderOptions(bound, caseSpec) };
}

/** Structural providerOptions assertion bound to the exported adapter call. */
function assertProviderOptions(caseSpec, source) {
  const { providerOptions } = inspectBoundHandler(caseSpec, source);
  const expected = caseSpec.expect.providerOptions;

  if (expected === null) {
    if (providerOptions !== null) {
      fail(`Generated handler ${caseSpec.id} carries an unexpected providerOptions for a non-configured provider.`);
    }

    return;
  }

  if (Array.isArray(expected.anyOf)) {
    if (matchesAnyAlternative(providerOptions, expected.anyOf)) return;

    fail(`Generated handler ${caseSpec.id} providerOptions does not match any accepted shape.`);
  }

  assertExactProviderOptions(caseSpec.id, providerOptions, expected);
}

function matchesAnyAlternative(entries, alternatives) {
  for (const alternative of alternatives) {
    if (alternative === null) {
      if (entries === null) return true;
      continue;
    }

    if (entries !== null && tryExactProviderOptions(entries, alternative)) return true;
  }

  return false;
}

function tryExactProviderOptions(entries, expected) {
  const keys = Object.keys(expected);

  if (entries.size !== keys.length) return false;

  for (const key of keys) {
    if (!entries.has(key) || entries.get(key) !== expected[key]) return false;
  }

  return true;
}

function assertExactProviderOptions(label, entries, expected) {
  if (entries === null) fail(`Generated handler ${label} is missing providerOptions ${JSON.stringify(expected)}.`);

  const keys = Object.keys(expected);

  for (const key of keys) {
    if (!entries.has(key)) fail(`Generated handler ${label} providerOptions is missing key ${key}.`);

    if (entries.get(key) !== expected[key]) {
      fail(`Generated handler ${label} providerOptions.${key} is ${JSON.stringify(entries.get(key))}; expected ${JSON.stringify(expected[key])}.`);
    }
  }

  for (const key of entries.keys()) {
    if (!Object.hasOwn(expected, key)) fail(`Generated handler ${label} providerOptions has unexpected key ${key}.`);
  }
}

/** Parse a quoted JS string literal (surrounding quotes included) to its value. */
function parseQuotedLiteral(text) {
  const quote = text[0];
  let value = '';
  let index = 1;

  while (index < text.length - 1) {
    const char = text[index];

    if (char === '\\') {
      value += unescapeChar(text[index + 1]);
      index += 2;
      continue;
    }

    value += char;
    index += 1;
  }

  return { value, quote };
}

function unescapeChar(char) {
  if (char === 'n') return '\n';

  if (char === 'r') return '\r';

  if (char === 't') return '\t';

  if (char === '0') return '\0';

  return char ?? '';
}

/* ------------------------------------------------------------------ *
 * Content assertions
 * ------------------------------------------------------------------ */

function expectContent(caseSpec, secretEnv, content) {
  const T = requireTypeScript();
  const label = caseSpec.id;
  const { sourceFile, bound } = inspectBoundHandler(caseSpec, content);
  const provider = findProperty(bound, 'provider', T);
  const providerValue = provider === null ? null : unwrapExpression(provider.initializer, T);

  if (providerValue === null || !T.isStringLiteral(providerValue) || providerValue.text !== caseSpec.provider) {
    fail(`Generated handler ${label} does not bind provider ${JSON.stringify(caseSpec.provider)} on its adapter options.`);
  }

  const maximum = findProperty(bound, 'maxBodyBytes', T);
  const maximumValue = maximum === null ? null : unwrapExpression(maximum.initializer, T);

  if (maximumValue === null || !T.isNumericLiteral(maximumValue) || maximumValue.text !== String(BODY_LIMIT)) {
    fail(`Generated handler ${label} does not bind maxBodyBytes ${BODY_LIMIT} on its adapter options.`);
  }

  const secrets = findProperty(bound, 'secrets', T);
  const expectedSecrets = caseSpec.framework === 'cloudflare' ? `[env.${secretEnv}]` : `[process.env.${secretEnv}!]`;
  const actualSecrets = secrets === null ? '' : secrets.initializer.getText(sourceFile).replaceAll(/\s+/g, '');

  if (actualSecrets !== expectedSecrets) {
    fail(`Generated handler ${label} binds secrets ${JSON.stringify(actualSecrets)}; expected ${JSON.stringify(expectedSecrets)}.`);
  }

  assertProviderOptions(caseSpec, content);
}

/* ------------------------------------------------------------------ *
 * Independent semantic compilation
 * ------------------------------------------------------------------ */

function tscPath() {
  const tsc = path.join(REPO_ROOT, 'node_modules', 'typescript', 'lib', 'tsc.js');

  if (!existsSync(tsc)) fail('The pinned TypeScript toolchain is missing; restore the prepared dependency snapshot.');

  return tsc;
}

function tscArgs(file) {
  return [
    '--noEmit',
    '--strict',
    '--target', 'es2022',
    '--module', 'nodenext',
    '--moduleResolution', 'nodenext',
    '--lib', 'es2022,dom,dom.iterable',
    '--types', 'node',
    '--esModuleInterop',
    '--skipLibCheck',
    '--exactOptionalPropertyTypes',
    '--noUncheckedIndexedAccess',
    '--verbatimModuleSyntax',
    file,
  ];
}

/** Minimal flags for a self-contained diagnostic control (no ambient Node types). */
function tscDiagnosticArgs(file) {
  return ['--noEmit', '--strict', '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', file];
}

/** Compile one generated file; any non-clean result is a real failure. */
function typecheckFile(file, cwd, label) {
  const result = runSync(process.execPath, [tscPath(), ...tscArgs(file)], cwd);

  if (result.timedOut) fail(`Semantic compilation timed out for ${label}.`);

  if (result.status !== 0) fail(`Semantic compilation failed for ${label}:\n${result.stdout || result.stderr}`);
}

/* ------------------------------------------------------------------ *
 * Inventory and byte helpers
 * ------------------------------------------------------------------ */

function assertSameBytes(first, second, label) {
  if (!readFileSync(first).equals(readFileSync(second))) fail(`Regenerated bytes differ between runs for ${label}.`);
}

function assertCompletedDir(directory, fileName, label) {
  const entries = readdirSync(directory);

  if (entries.length !== 1 || entries[0] !== fileName) {
    fail(`${label} produced [${entries.join(', ')}] instead of exactly [${fileName}].`);
  }
}

/* ------------------------------------------------------------------ *
 * Self-test controls (harness only — never SDK evidence)
 * ------------------------------------------------------------------ */

function controlMissingFile(root) {
  const directory = path.join(root, 'control-missing');
  const fileName = 'stripe.express.ts';
  const file = path.join(directory, fileName);

  mkdirSync(directory, { recursive: true });
  writeFileSync(file, 'export {};\n');
  assertCompletedDir(directory, fileName, 'control-missing-present');
  unlinkSync(file);

  let detected = false;

  try { assertCompletedDir(directory, fileName, 'control-missing-absent'); } catch { detected = true; }

  assert(detected, 'Inventory control failed: a missing generated file was not detected.');
}

/**
 * Control: a real TypeScript diagnostic is detected by its exit code (2) AND the
 * specific diagnostic code. A crash/timeout (infrastructure) can never be
 * mistaken for controlled rejection.
 */
function controlSemanticFailure(root) {
  const directory = path.join(root, 'control-semantic');
  const badFile = path.join(directory, 'bad.ts');
  const okFile = path.join(directory, 'ok.ts');

  mkdirSync(directory, { recursive: true });
  writeFileSync(badFile, 'const value: number = "not a number";\nexport {};\n');
  writeFileSync(okFile, 'const value: number = 1;\nexport { value };\n');

  const bad = runSync(process.execPath, [tscPath(), ...tscDiagnosticArgs(badFile)], directory);

  if (bad.timedOut) fail('Semantic control infrastructure failure: tsc timed out.');

  if (bad.status !== 2) fail(`Semantic control infrastructure failure: tsc exited ${bad.status}; expected diagnostics exit 2.`);

  if (!`${bad.stdout}${bad.stderr}`.includes('error TS2322')) {
    fail('Semantic control failed: expected TS2322 diagnostic was not reported.');
  }

  const ok = runSync(process.execPath, [tscPath(), ...tscDiagnosticArgs(okFile)], directory);

  if (ok.timedOut) fail('Semantic control infrastructure failure: clean tsc timed out.');

  if (ok.status !== 0) fail(`Semantic control failed: a valid file exited ${ok.status} instead of 0.`);
}

function controlChangedRegeneration(root) {
  const directory = path.join(root, 'control-regen');
  const first = path.join(directory, 'first.ts');
  const second = path.join(directory, 'second.ts');

  mkdirSync(directory, { recursive: true });
  writeFileSync(first, 'export const same = 1;\n');
  writeFileSync(second, 'export const same = 2;\n');

  let detected = false;

  try { assertSameBytes(first, second, 'control-regen'); } catch { detected = true; }

  assert(detected, 'Regeneration control failed: differing bytes were treated as deterministic.');

  writeFileSync(second, 'export const same = 1;\n');
  assertSameBytes(first, second, 'control-regen-identical');
}

/** Control: an arbitrary nonzero exit must never be classified as a pass. */
function controlClassification() {
  assert.equal(classifyStatus(0), 'pass', 'Zero exit must be a pass.');
  assert.notEqual(classifyStatus(1), 'pass', 'Exit 1 must never be a pass.');
  assert.notEqual(classifyStatus(2), 'pass', 'Exit 2 must never be a pass.');
  assert.notEqual(classifyStatus(3), 'pass', 'Exit 3 must never be a pass.');
  assert.equal(classifyStatus(3), 'not-ready', 'Exit 3 must classify as not-ready.');
  assert.equal(classifyStatus(0, true), 'fail', 'A timed-out zero must never be a pass.');
}

function classifyStatus(status, timedOut = false) {
  if (timedOut) return 'fail';

  if (status === 0) return 'pass';

  if (status === EXIT_NOT_READY) return 'not-ready';

  return 'fail';
}

/** RFC 9110 field-name token, matching the Stage B configuration policy. */
function isSafeHeaderToken(name) {
  return name.length > 0 && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name);
}

/** Emit a safe double-quoted JS string literal for a configured header name. */
function quoteForSource(value) {
  const escaped = value
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('\n', '\\n')
    .replaceAll('\r', '\\r');

  return `"${escaped}"`;
}

/** Control: header token validation AND safe literal emission round-trip. */
function controlHeaderToken() {
  for (const bad of ['bad name', 'bad:name', 'bad"name', 'bad\\name', 'bad\nname', '']) {
    assert(!isSafeHeaderToken(bad), `Header control failed: a non-token name ${JSON.stringify(bad)} was accepted.`);
  }

  for (const good of ['x-grafana-alerting-signature', 'x-custom-signature', 'X-Timestamp', HOSTILE_VALID_HEADER]) {
    assert(isSafeHeaderToken(good), `Header control failed: a valid token ${good} was rejected.`);
  }

  const literal = quoteForSource(HOSTILE_VALID_HEADER);

  assert.equal(parseQuotedLiteral(literal).value, HOSTILE_VALID_HEADER,
    'Header control failed: an emitted literal did not round-trip to the original token.');
}

/** Control: no embedded real secret, and diagnostics are redacted. */
function controlNoSecret() {
  const sample = `${EXPECTED_SECRET_ENV.grafana}='whsec_REAL_LOOKING_SECRET' CANARY_SECRET_DATA 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`;
  const clean = redact(sample);

  assert(!clean.includes('whsec_REAL_LOOKING_SECRET'), 'Secret control failed: a webhook secret was not redacted.');
  assert(!clean.includes('CANARY_SECRET_DATA'), 'Secret control failed: a canary was not redacted.');
  assert(!clean.includes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    'Secret control failed: a hex digest was not redacted.');
}

/**
 * Control: readiness gates reject independently; the exact 18-provider order is
 * required; and an 18-shaped registry with the real (flag-less) built help is
 * BLOCKED without allocating any temp directory.
 */
function controlReadiness() {
  const ready = [...EXPECTED_PROVIDER_ORDER];

  assert.equal(decideRegistryReadiness(ready).ready, true, 'Readiness control: the exact 18-provider shape was rejected.');
  assert.equal(decideRegistryReadiness(EXPECTED_PROVIDER_ORDER.slice(0, EXISTING_PROVIDER_COUNT)).ready, false,
    'Readiness control: a 16-provider registry was accepted.');
  assert.equal(decideRegistryReadiness([...EXPECTED_PROVIDER_ORDER.slice(0, 16), 'polar', 'grafana']).ready, false,
    'Readiness control: a wrong-order 18-provider tail was accepted.');
  assert.equal(decideRegistryReadiness([...EXPECTED_PROVIDER_ORDER.slice(0, 17), 'grafana']).ready, false,
    'Readiness control: a duplicate ID 18-provider registry was accepted.');
  assert.equal(decideRegistryReadiness([]).ready, false, 'Readiness control: an empty registry was accepted.');
  assert.equal(decideRegistryReadiness(undefined).ready, false, 'Readiness control: a missing registry was accepted.');

  const fullHelp = REQUIRED_CLI_FLAGS.join(' ');

  assert.equal(decideFlagsReadiness(fullHelp).ready, true, 'Readiness control: complete help was rejected.');

  for (const flag of REQUIRED_CLI_FLAGS) {
    const partial = REQUIRED_CLI_FLAGS.filter((other) => other !== flag).join(' ');
    const decision = decideFlagsReadiness(partial);

    assert.equal(decision.ready, false, `Readiness control: help missing ${flag} was accepted.`);
    assert(decision.reason.includes(flag), `Readiness control: the reason does not name the missing ${flag}.`);
  }

  assert.equal(decideFlagsReadiness('').ready, false, 'Readiness control: empty help was accepted.');

  // The expectation tables must cover exactly the 18 providers, uniquely.
  assert.equal(EXPECTED_PROVIDER_ORDER.length, TARGET_PROVIDERS, 'Readiness control: expected order is not 18 long.');
  assert.equal(new Set(EXPECTED_PROVIDER_ORDER).size, TARGET_PROVIDERS, 'Readiness control: expected order has duplicates.');
  assert.equal(Object.keys(EXPECTED_SECRET_ENV).length, TARGET_PROVIDERS, 'Readiness control: secret-env map is not 18 long.');

  for (const provider of EXPECTED_PROVIDER_ORDER) {
    assert(Object.hasOwn(EXPECTED_SECRET_ENV, provider), `Readiness control: no secret-env expectation for ${provider}.`);
  }

  // Authored negative help fixture: missing every required Stage B flag.
  const negativeHelp = 'Usage: hooklatch init webhook --provider <id> --framework <id> --out <dir>';
  const negativeDecision = decideFlagsReadiness(negativeHelp);

  assert.equal(negativeDecision.ready, false, 'Readiness control: authored flag-less help was accepted.');
  assert(negativeDecision.reason.includes('--grafana-mode'), 'Readiness control: the negative reason does not name a missing flag.');

  // Authored positive help fixture: complete help with an 18-provider registry is ready.
  const authoredComplete = evaluateReadiness({ providers: ready, helpText: REQUIRED_CLI_FLAGS.join('\n') });

  assert.equal(authoredComplete.ready, true, 'Readiness control: complete authored help with 18 providers was rejected.');

  // The REAL built help is accepted at whichever stage the base is at; never
  // assert that real readiness is false (Stage B makes the flags present).
  const builtHelp = readCliHelp(builtCliPath(), REPO_ROOT);
  const before = countTempWorkspaces();
  const realDecision = evaluateReadiness({ providers: ready, helpText: builtHelp });
  const after = countTempWorkspaces();

  assert.equal(realDecision.ready, decideFlagsReadiness(builtHelp).ready,
    'Readiness control: combined readiness disagreed with the flags decision for real built help.');
  assert.equal(after, before, 'Readiness control: readiness evaluation allocated a temp directory.');

  // Matrix shape: 72 primary + 12 configured, with explicit Grafana body mode.
  const primary = primaryCases(ready);
  const configured = configuredCases();

  assert.equal(primary.length, TARGET_PROVIDERS * FRAMEWORKS.length, 'Matrix control: primary count is not 72.');

  for (const caseSpec of primary.filter((entry) => entry.provider === 'grafana')) {
    assert(caseSpec.args.includes('--grafana-mode') && caseSpec.args.includes('body'),
      'Matrix control: a Grafana primary case lacks the explicit body mode.');
    assert.deepEqual(caseSpec.expect.providerOptions, { mode: 'body' },
      'Matrix control: a Grafana primary case does not expect explicit body mode.');
  }

  for (const caseSpec of primary.filter((entry) => entry.provider !== 'grafana')) {
    assert(!caseSpec.args.includes('--grafana-mode'), `Matrix control: ${caseSpec.id} should not carry --grafana-mode.`);
  }

  assert.equal(configured.length, FRAMEWORKS.length * 3, 'Matrix control: configured variant count is wrong.');

  for (const caseSpec of configured) {
    assert(Object.hasOwn(EXPECTED_SECRET_ENV, caseSpec.provider), `Matrix control: ${caseSpec.id} has no secret-env expectation.`);
  }

  assert.equal(expectedFileName('grafana', 'nextjs'), 'route.ts', 'File-name control: nextjs target is wrong.');
  assert.equal(expectedFileName('grafana', 'cloudflare'), 'grafana.cloudflare.ts', 'File-name control: cloudflare target is wrong.');
  assert.equal(expectedFileName('polar', 'hono'), 'polar.hono.ts', 'File-name control: hono target is wrong.');
  assert.equal(expectedFileName('polar', 'express'), 'polar.express.ts', 'File-name control: express target is wrong.');
}

function countTempWorkspaces() {
  return readdirSync(os.tmpdir()).filter((name) => name.startsWith(TEMP_PREFIX)).length;
}

function grafanaControlCase(framework, providerOptions) {
  return { id: `control/${framework}`, provider: 'grafana', framework, args: [], expect: { providerOptions } };
}

/**
 * Control: inspection is bound to the exported adapter call. A dead decoy
 * declaration, a comment, or an unexported call must never satisfy it, while
 * identifier, spread and Workers-factory bindings must.
 */
function controlStructuralOptions() {
  const timestamped = { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' };

  // Dead non-exported decoy first, then the real exported body-mode call.
  const decoyExpress = [
    "import { createWebhookMiddleware } from 'hooklatch/express';",
    "// providerOptions: { mode: 'timestamped', signatureHeader: 'x-comment', timestampHeader: 'x-comment-ts' }",
    "const decoy = { provider: 'grafana', secrets: [process.env.GRAFANA_WEBHOOK_SECRET!], maxBodyBytes: 4242, providerOptions: { mode: 'timestamped', signatureHeader: 'x-decoy', timestampHeader: 'x-decoy-ts' } };",
    "const options = { provider: 'grafana', secrets: [process.env.GRAFANA_WEBHOOK_SECRET!], maxBodyBytes: 4242, providerOptions: { mode: 'body' } };",
    'export const grafanaExpressWebhook = createWebhookMiddleware(options);',
    '',
  ].join('\n');

  assertProviderOptions(grafanaControlCase('express', { mode: 'body' }), decoyExpress);

  let decoyDetected = false;

  try {
    assertProviderOptions(grafanaControlCase('express', { mode: 'timestamped', signatureHeader: 'x-decoy', timestampHeader: 'x-decoy-ts' }), decoyExpress);
  } catch { decoyDetected = true; }

  assert(decoyDetected, 'Binding control failed: a dead decoy declaration satisfied providerOptions.');

  // nextjs: the exported call spreads the exact options declaration.
  const nextjs = [
    "import { createWebhookHandler } from 'hooklatch/nextjs';",
    'const options = {',
    "  provider: 'grafana',",
    '  secrets: [process.env.GRAFANA_WEBHOOK_SECRET!],',
    '  maxBodyBytes: 4242,',
    `  providerOptions: { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' },`,
    '};',
    'export const POST = createWebhookHandler({ ...options, handler: () => Response.json({}) });',
    '',
  ].join('\n');

  assertProviderOptions(grafanaControlCase('nextjs', timestamped), nextjs);

  // cloudflare: the Workers options factory returns the literal options.
  const cloudflare = [
    "import { createWebhookHandler } from 'hooklatch/cloudflare';",
    'interface Env { GRAFANA_WEBHOOK_SECRET: string }',
    'export const fetch = createWebhookHandler<Env>({',
    '  options: (env) => ({',
    "    provider: 'grafana',",
    '    secrets: [env.GRAFANA_WEBHOOK_SECRET],',
    '    maxBodyBytes: 4242,',
    `    providerOptions: { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' },`,
    '  }),',
    '  handler: () => Response.json({}),',
    '});',
    '',
  ].join('\n');

  assertProviderOptions(grafanaControlCase('cloudflare', timestamped), cloudflare);

  // Existing providers must carry no providerOptions on the bound options.
  const existing = { id: 'control/existing', provider: 'stripe', framework: 'express', args: [], expect: { providerOptions: null } };

  const existingSource = [
    "import { createWebhookMiddleware } from 'hooklatch/express';",
    "const options = { provider: 'stripe', secrets: [process.env.STRIPE_WEBHOOK_SECRET!], maxBodyBytes: 4242 };",
    'export const stripeExpressWebhook = createWebhookMiddleware(options);',
    '',
  ].join('\n');

  assertProviderOptions(existing, existingSource);

  let unexpected = false;

  try {
    assertProviderOptions(existing, existingSource.replace('maxBodyBytes: 4242', "maxBodyBytes: 4242, providerOptions: { mode: 'body' }"));
  } catch { unexpected = true; }

  assert(unexpected, 'Binding control failed: an unexpected providerOptions was accepted for a non-configured provider.');

  // A call that is not exported is not the generated handler; binding must fail.
  const unexported = existingSource.replace('export const stripeExpressWebhook =', 'const stripeExpressWebhook =');
  let unexportedDetected = false;

  try { assertProviderOptions(existing, unexported); } catch { unexportedDetected = true; }

  assert(unexportedDetected, 'Binding control failed: an unexported adapter call was accepted.');
}

/** A nested declaration with the same name must not replace the live binding. */
function controlScopedOptions() {
  const source = [
    "import { createWebhookMiddleware } from 'hooklatch/express';",
    "const options = { providerOptions: { mode: 'body' } };",
    'export const webhook = createWebhookMiddleware(options);',
    "function unused() { const options = { providerOptions: { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' } }; }",
  ].join('\n');

  for (const framework of ['express', 'hono']) {
    const adapted = source.replace('hooklatch/express', `hooklatch/${framework}`);

    assertProviderOptions(grafanaControlCase(framework, { mode: 'body' }), adapted);
    assert.throws(() => assertProviderOptions(grafanaControlCase(framework, {
      mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts',
    }), adapted), /providerOptions/, 'An unused nested declaration must not replace the live options binding.');
  }
}

/** Competing spreads must be rejected rather than checked as the first object. */
function controlSpreadOverrides() {
  const source = [
    "import { createWebhookHandler } from 'hooklatch/nextjs';",
    "const options = { providerOptions: { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' } };",
    "export const POST = createWebhookHandler({ ...options, ...{ providerOptions: { mode: 'body' } }, handler: () => Response.json({}) });",
  ].join('\n');

  assert.throws(() => assertProviderOptions(grafanaControlCase('nextjs', {
    mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts',
  }), source), /ambiguous|spread/, 'A later spread must not override the inspected options unnoticed.');
}

/** An exported decoy must not hide another exported adapter call. */
function controlExportedDecoys() {
  for (const framework of FRAMEWORKS) {
    const adapter = ADAPTER_IMPORTS[framework];
    const wrap = framework === 'cloudflare' ? 'options: () => ' : '';
    const timestamped = "{ providerOptions: { mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts' } }";
    const body = "{ providerOptions: { mode: 'body' } }";
    const argument = (options) => framework === 'cloudflare' ? `{ ${wrap}(${options}) }` : options;

    const source = [
      `import { ${adapter.name} } from '${adapter.module}';`,
      `export const decoy = ${adapter.name}(${argument(timestamped)});`,
      `export const ${framework === 'nextjs' ? 'POST' : 'fetch'} = ${adapter.name}(${argument(body)});`,
    ].join('\n');

    assert.throws(() => assertProviderOptions(grafanaControlCase(framework, {
      mode: 'timestamped', signatureHeader: 'x-real', timestampHeader: 'x-ts',
    }), source), /ambiguous|multiple/, 'An exported decoy must not hide another exported adapter call.');
  }
}

/**
 * Control: fault injection after the first junction. The outer ledger must still
 * unlink it, the junction target sentinel must be unchanged, and the scratch
 * root must be removed.
 */
function controlWorkspaceFaultInjection() {
  const workspace = createWorkspace();
  const target = mkdtempSync(path.join(os.tmpdir(), TARGET_PREFIX));
  const sentinel = path.join(target, 'sentinel.txt');

  writeFileSync(sentinel, 'SENTINEL-CONTENT');

  try {
    const link = path.join(workspace.root, 'node_modules', 'first');
    createTrackedJunction(workspace, target, link);
    assert(existsSync(link), 'Fault-injection control: the first junction was not created.');

    let injected = false;

    try { throw new Error('injected-failure-after-first-junction'); } catch (error) { injected = error.message === 'injected-failure-after-first-junction'; }

    assert(injected, 'Fault-injection control: the injected failure was not observed.');

    disposeWorkspace(workspace);

    assert(!existsSync(workspace.root), 'Fault-injection control: the scratch root was not removed.');
    assert(readFileSync(sentinel, 'utf8') === 'SENTINEL-CONTENT', 'Fault-injection control: the junction target sentinel mutated.');
  } finally {
    if (existsSync(workspace.root)) {
      try { disposeWorkspace(workspace); } catch { /* preserved deliberately */ }
    }

    rmSync(target, { recursive: true, force: true });
  }
}

/**
 * Control: a genuinely timed-out child sets the cleanup ledger, and disposal is
 * WITHHELD (scratch preserved) instead of recursively deleting a tree that may
 * still have running descendants. No sleep is used as proof.
 */
function controlUncertainTermination() {
  resetProcessHealth();

  const workspace = createWorkspace();
  let preserved = false;

  try {
    const probe = runSync(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], workspace.root, { timeoutMs: 250 });

    assert(probe.timedOut, 'Uncertain-termination control: the child was not reported as timed out.');
    assert(processHealth.uncertain, 'Uncertain-termination control: timeout did not set the cleanup ledger.');
    assert(processHealth.reasons.some((reason) => reason.includes('timed out')),
      'Uncertain-termination control: the ledger does not name the timed-out child.');

    let withheld = false;

    try {
      disposeWorkspace(workspace);
    } catch (error) {
      withheld = true;
      assert(/preserved/i.test(error.message), 'Uncertain-termination control: cleanup error did not report preserved scratch.');
    }

    assert(withheld, 'Uncertain-termination control: cleanup proceeded while termination was uncertain.');
    assert(existsSync(workspace.root), 'Uncertain-termination control: scratch was removed.');
    preserved = true;
  } finally {
    resetProcessHealth();

    if (existsSync(workspace.root)) rmSync(workspace.root, { recursive: true, force: true });

    resetProcessHealth();
  }

  assert(preserved, 'Uncertain-termination control: the preservation path was not reached.');
}

/**
 * Control: tracked-byte snapshots are stable; the full consumer tree (including
 * installed hooklatch inside node_modules) detects writes outside a requested
 * output directory; dependency junctions are never followed.
 */
function controlSnapshots() {
  const first = snapshotTrackedBytes();
  const second = snapshotTrackedBytes();

  assert.equal(first.digest, second.digest, 'Snapshot control: tracked-byte digest is not stable.');
  assert(first.count > 0, 'Snapshot control: tracked-byte snapshot is empty.');

  const workspace = createWorkspace();
  const target = mkdtempSync(path.join(os.tmpdir(), TARGET_PREFIX));

  try {
    const consumer = path.join(workspace.root, 'consumer');
    const cliDirectory = path.join(consumer, 'node_modules', 'hooklatch', 'dist', 'cli');
    const skip = new Set();

    mkdirSync(cliDirectory, { recursive: true });
    writeFileSync(path.join(cliDirectory, 'index.js'), 'export {};\n');
    writeFileSync(path.join(target, 'sentinel.txt'), 'A');
    createTrackedJunction(workspace, target, path.join(consumer, 'node_modules', 'linked-peers'));

    const beforeOutsideWrite = snapshotTree(consumer, skip);

    // A write outside the requested output directory, inside installed
    // node_modules, must be caught (node_modules is NOT skipped).
    writeFileSync(path.join(cliDirectory, 'extra.js'), 'export {};\n');

    const afterOutsideWrite = snapshotTree(consumer, skip);

    assert.notEqual(beforeOutsideWrite, afterOutsideWrite,
      'Snapshot control failed: a write under installed node_modules was not detected.');

    const beforeJunctionChange = snapshotTree(consumer, skip);

    writeFileSync(path.join(target, 'sentinel.txt'), 'B');

    const afterJunctionChange = snapshotTree(consumer, skip);

    assert.equal(beforeJunctionChange, afterJunctionChange,
      'Snapshot control failed: a dependency junction target was followed.');

    writeFileSync(path.join(consumer, 'a.txt'), 'one');

    const beforeFileChange = snapshotTree(consumer, skip);

    writeFileSync(path.join(consumer, 'a.txt'), 'two');

    const afterFileChange = snapshotTree(consumer, skip);

    assert.notEqual(beforeFileChange, afterFileChange,
      'Snapshot control failed: tree snapshot did not detect changed file bytes.');
  } finally {
    disposeWorkspace(workspace);
    rmSync(target, { recursive: true, force: true });
  }
}

/**
 * Control: drive the real built CLI (no pack/install) through the same
 * inventory/content/typecheck/determinism helpers the ready path uses, for all
 * four frameworks. Harness evidence only; no Grafana/Polar support is implied.
 */
function controlLiveGenerator(workspace) {
  const cli = builtCliPath();

  if (!existsSync(cli)) fail('Live-generator control needs dist/cli/index.js; run npm run build first.');

  writeFileSync(path.join(workspace.root, 'package.json'),
    `${JSON.stringify({ name: 'hooklatch-phase7-selftest', version: '0.0.0', private: true, type: 'module' }, null, 2)}\n`);

  linkSelfTestDependencies(workspace);

  for (const framework of FRAMEWORKS) {
    const caseSpec = {
      id: `stripe/${framework}`,
      provider: 'stripe',
      framework,
      args: ['--provider', 'stripe', '--framework', framework],
      expect: { providerOptions: null },
    };

    const fileName = expectedFileName('stripe', framework);
    const firstDir = path.join(workspace.root, 'live-1', framework);
    const secondDir = path.join(workspace.root, 'live-2', framework);

    const first = generateInto(workspace.root, cli, caseSpec, fileName, firstDir);

    expectContent(caseSpec, EXPECTED_SECRET_ENV.stripe, readFileSync(first, 'utf8'));

    const second = generateInto(workspace.root, cli, caseSpec, fileName, secondDir);

    assertSameBytes(first, second, `live-generator-${framework}`);

    let detected = false;

    try { expectContent({ ...caseSpec, id: `stripe/${framework}-wrong-limit` }, EXPECTED_SECRET_ENV.stripe, readFileSync(first, 'utf8').replaceAll(String(BODY_LIMIT), '9999')); } catch { detected = true; }

    assert(detected, `Live-generator control failed: a wrong body limit was accepted for ${framework}.`);

    typecheckFile(first, workspace.root, `live-generator-${framework}`);
  }
}

function generateInto(cwd, cli, caseSpec, fileName, outDir) {
  const result = runSync(process.execPath, generationArgv(cli, caseSpec, path.relative(cwd, outDir)), cwd);

  expectExit(result, 0, `Live generation (${caseSpec.id})`);
  assertCompletedDir(outDir, fileName, `Live generation (${caseSpec.id})`);

  return path.join(outDir, fileName);
}

function linkSelfTestDependencies(workspace) {
  createTrackedJunction(workspace, REPO_ROOT, path.join(workspace.root, 'node_modules', 'hooklatch'));

  for (const name of PEER_PACKAGES) {
    linkPinnedDependency(workspace, name, workspace.root);
  }
}

const PEER_PACKAGES = ['typescript', 'express', 'hono', '@types/express', '@types/node'];

/* ------------------------------------------------------------------ *
 * Self-test entry
 * ------------------------------------------------------------------ */

function runSelfTests() {
  const workspace = createWorkspace();

  try {
    controlMissingFile(workspace.root);
    controlSemanticFailure(workspace.root);
    controlChangedRegeneration(workspace.root);
    controlClassification();
    controlHeaderToken();
    controlNoSecret();
    controlReadiness();
    controlStructuralOptions();
    controlScopedOptions();
    controlSpreadOverrides();
    controlExportedDecoys();
    controlWorkspaceFaultInjection();
    controlUncertainTermination();
    controlSnapshots();
    controlLiveGenerator(workspace);
  } finally {
    disposeWorkspace(workspace);
  }

  return [
    'inventory detects a missing generated file',
    'a real TS2322 diagnostic (exit 2) is detected; a crash is not',
    'changed regeneration is detected',
    'nonzero and timed-out exits are never classified as pass',
    'non-token header names are rejected and accepted names round-trip safely',
    'secrets and canaries are redacted',
    'readiness accepts authored complete help and never asserts real help is flag-less',
    'providerOptions is bound to the exported adapter call; dead decoys and unexported calls fail',
    'nested declarations cannot replace the live top-level options binding',
    'later spreads cannot override the inspected options unnoticed',
    'multiple exported adapter calls cannot hide behind an exported decoy',
    'fault injection after the first junction unlinks it and leaves the target intact',
    'uncertain child termination withholds cleanup and preserves scratch',
    'full consumer-tree snapshots catch out-of-directory writes and do not follow junctions',
    'the real built CLI drives inventory/content/typecheck/determinism for all four frameworks',
  ];
}

/* ------------------------------------------------------------------ *
 * Help
 * ------------------------------------------------------------------ */

function printHelp() {
  process.stdout.write(`Hooklatch Phase 7 configured CLI qualification

Usage: node scripts/phase7-cli-config-smoke.mjs [options]

Options:
  --self-test   Run harness controls, including a live local-generation control
                and fault-injection cleanup checks (no pack/install).
  --help, -h    Show this help.

Behaviour:
  A normal run first checks — BEFORE allocating any temp directory — that the
  built registry is exactly the ordered ${TARGET_PROVIDERS} providers
  (${NEW_PROVIDERS.join(', ')} appended after the existing ${EXISTING_PROVIDER_COUNT}) and that the BUILT CLI
  advertises the Stage B configuration flags. If either is missing it exits
  ${EXIT_NOT_READY} (BLOCKED) with no temp allocation. When ready it rechecks the
  INSTALLED CLI, then packs and installs the local tarball offline into a checked
  OS-temp consumer and drives the INSTALLED bin to generate all
  ${TARGET_PROVIDERS * FRAMEWORKS.length} primary provider/framework combinations plus Grafana
  timestamped-header (incl. a hostile-but-valid token) and Polar legacy variants
  for all ${FRAMEWORKS.length} frameworks, binds each handler's providerOptions to its exported
  adapter call, typechecks it, and checks the full consumer tree (including
  installed node_modules) around probes. Tracked and built bytes are snapshotted
  before and after; PASS is printed only after cleanup and integrity succeed.

Exit codes:
  ${EXIT_PASS}  All selected real checks and cleanup passed.
  ${EXIT_FAIL}  A real qualification check failed.
  ${EXIT_USAGE}  Invalid invocation.
  ${EXIT_NOT_READY}  Not ready (upstream dependency missing); no temp allocated.
`);
}

/* ------------------------------------------------------------------ *
 * Normal run
 * ------------------------------------------------------------------ */

function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath) candidates.push(process.env.npm_execpath);

  candidates.push(
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  if (!found) fail('npm CLI is unavailable: neither npm_execpath nor the node install tree provide npm-cli.js.');

  return found;
}

/** npm environment isolated to the workspace so no user cache is written. */
function isolatedNpmEnv(workspace) {
  const cache = path.join(workspace.root, 'npm-cache');

  mkdirSync(cache, { recursive: true });

  return {
    ...process.env,
    npm_config_cache: cache,
    NPM_CONFIG_OFFLINE: 'true',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
  };
}

/** Run npm through the node binary (npm_execpath is a .js entry, never a binary). */
function runNpm(npmCli, args, cwd, workspace) {
  return runSync(process.execPath, [npmCli, ...args], cwd, { env: isolatedNpmEnv(workspace) });
}

function installedCliPath(consumerRoot) {
  const cli = path.join(consumerRoot, 'node_modules', 'hooklatch', 'dist', 'cli', 'index.js');

  if (!existsSync(cli)) fail('The installed packed package does not expose dist/cli/index.js.');

  return cli;
}

function linkPinnedDependency(workspace, localName, root) {
  const target = path.resolve(path.join(REPO_ROOT, 'node_modules', localName));

  if (!existsSync(target)) fail(`Pinned dependency tree is missing: ${localName} (the repository node_modules stays read-only).`);

  return createTrackedJunction(workspace, target, path.join(root, 'node_modules', localName));
}

function generationArgv(cli, caseSpec, relativeOut) {
  return [
    cli, 'init', 'webhook', ...caseSpec.args,
    '--out', relativeOut,
    '--secret-env', EXPECTED_SECRET_ENV[caseSpec.provider],
    '--body-limit', String(BODY_LIMIT),
  ];
}

/** Error probes must exit 2 and write nothing; dry-run must exit 0 and change nothing. */
function runErrorProbes(cli, consumerRoot) {
  const probes = [
    { id: 'grafana-missing-mode', args: ['--provider', 'grafana', '--framework', 'express'] },
    { id: 'grafana-invalid-mode', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'bogus'] },
    { id: 'grafana-unknown-mode-flag', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode'] },
    { id: 'body-forbids-timestamp', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'body', '--timestamp-header', 'x-ts'] },
    { id: 'timestamped-requires-header', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'timestamped'] },
    { id: 'polar-mode-on-grafana', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'body', '--polar-secret-mode', 'legacy'] },
    { id: 'grafana-flag-on-polar', args: ['--provider', 'polar', '--framework', 'express', '--grafana-mode', 'body'] },
    { id: 'duplicate-grafana-mode', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'body', '--grafana-mode', 'timestamped'] },
    { id: 'invalid-polar-mode', args: ['--provider', 'polar', '--framework', 'express', '--polar-secret-mode', 'bogus'] },
    { id: 'unsafe-header-space', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'timestamped', '--timestamp-header', 'bad name'] },
    { id: 'unsafe-header-colon', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'timestamped', '--timestamp-header', 'bad:name'] },
    { id: 'reserved-header', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'body', '--signature-header', 'authorization'] },
    { id: 'colliding-headers', args: ['--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'timestamped', '--signature-header', 'x-same', '--timestamp-header', 'x-same'] },
  ];

  const skip = new Set();
  const before = snapshotTree(consumerRoot, skip);

  for (const probe of probes) {
    const out = `gen-error-${probe.id}`;
    const result = runSync(process.execPath, [cli, 'init', 'webhook', ...probe.args, '--out', out], consumerRoot);

    expectExit(result, 2, `Error probe ${probe.id}`);

    if (existsSync(path.join(consumerRoot, out))) fail(`Error probe ${probe.id} wrote output despite exiting 2.`);
  }

  // The whole probe + dry-run window must leave the full consumer tree
  // unchanged, including installed hooklatch under node_modules.
  const dryOut = 'gen-dry-run';

  const dry = runSync(process.execPath,
    [cli, 'init', 'webhook', '--provider', 'grafana', '--framework', 'express', '--grafana-mode', 'body', '--out', dryOut, '--dry-run'],
    consumerRoot);

  const after = snapshotTree(consumerRoot, skip);

  expectExit(dry, 0, 'Dry run');

  if (existsSync(path.join(consumerRoot, dryOut))) fail('Dry run created its output directory.');

  if (before !== after) fail('Error probes or dry run changed the consumer tree (including node_modules).');

  return { errorProbes: probes.length, dryRun: true };
}

async function runQualification(providers, npmCli) {
  const workspace = createWorkspace();
  const consumerRoot = path.join(workspace.root, 'consumer');
  let result = EXIT_PASS;
  let passMessage = '';

  try {
    const beforeSnapshot = snapshotTrackedBytes();

    mkdirSync(consumerRoot);
    writeFileSync(path.join(consumerRoot, 'package.json'),
      `${JSON.stringify({ name: 'hooklatch-phase7-config-consumer', version: '0.0.0', private: true, type: 'module' }, null, 2)}\n`);

    const pack = runNpm(npmCli, ['pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', workspace.root], REPO_ROOT, workspace);

    expectExit(pack, 0, 'npm pack');

    const filename = JSON.parse(pack.stdout)[0].filename;
    const tarballPath = path.join(workspace.root, filename);

    if (!existsSync(tarballPath)) fail('npm pack did not produce the expected archive.');

    const install = runNpm(npmCli,
      ['install', tarballPath, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--legacy-peer-deps'],
      consumerRoot, workspace);

    expectExit(install, 0, 'offline npm install');

    const cli = installedCliPath(consumerRoot);
    const installedFlags = decideFlagsReadiness(readCliHelp(cli, consumerRoot));

    if (!installedFlags.ready) fail(`Installed CLI readiness regression: ${installedFlags.reason}`);

    for (const name of PEER_PACKAGES) linkPinnedDependency(workspace, name, consumerRoot);

    const cases = [...primaryCases(providers), ...configuredCases()];

    for (const caseSpec of cases) {
      const fileName = expectedFileName(caseSpec.provider, caseSpec.framework);
      const firstDir = path.join(consumerRoot, 'gen', caseSpec.id);
      const secondDir = path.join(consumerRoot, 'gen2', caseSpec.id);

      const first = generateInto(consumerRoot, cli, caseSpec, fileName, firstDir);

      expectContent(caseSpec, EXPECTED_SECRET_ENV[caseSpec.provider], readFileSync(first, 'utf8'));

      const second = generateInto(consumerRoot, cli, caseSpec, fileName, secondDir);

      assertSameBytes(first, second, caseSpec.id);
      typecheckFile(first, consumerRoot, caseSpec.id);
    }

    const probes = runErrorProbes(cli, consumerRoot);

    const afterSnapshot = snapshotTrackedBytes();

    if (beforeSnapshot.digest !== afterSnapshot.digest || beforeSnapshot.count !== afterSnapshot.count) {
      fail(`Tracked checkout bytes changed during qualification (${beforeSnapshot.count} -> ${afterSnapshot.count} files).`);
    }

    // Reported by the caller only after cleanup AND input-integrity succeed.
    passMessage = `PASS: ${cases.length} generated handlers (${providers.length} providers x ${FRAMEWORKS.length} primary + ${configuredCases().length} configured) are complete, bound to their exported adapter calls, deterministic and semantically typechecked; ${probes.errorProbes} error probes exited 2 with no writes; dry-run exited 0 with an unchanged consumer tree; tracked and built bytes unchanged.\n`;
  } catch (error) {
    process.stderr.write(`FAIL: phase7 CLI config qualification (${redact(error.message)})\n`);
    result = EXIT_FAIL;
  } finally {
    try {
      disposeWorkspace(workspace);
    } catch (error) {
      process.stderr.write(`CLEANUP FAILURE: ${redact(error.message)}\n`);
      result = EXIT_FAIL;
    }
  }

  return { code: result, message: passMessage };
}

/* ------------------------------------------------------------------ *
 * Entry
 * ------------------------------------------------------------------ */

async function main() {
  resetProcessHealth();

  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    printHelp();

    return EXIT_PASS;
  }

  if (argv.some((arg) => arg !== '--self-test')) {
    process.stderr.write('Invalid invocation: unexpected argument. Use --help.\n');

    return EXIT_USAGE;
  }

  const selfTest = argv.includes('--self-test');
  let providers = null;

  if (!selfTest) {
    // Readiness gate — BEFORE any temp allocation, install, generation or control.
    const registry = await loadBuiltRegistryProviders();

    if (!registry.present) {
      process.stderr.write(`BLOCKED (exit ${EXIT_NOT_READY}): ${registry.reason}\n`);
      process.stderr.write('No temp root was allocated and no package was installed or generated.\n');

      return EXIT_NOT_READY;
    }

    const registryDecision = decideRegistryReadiness(registry.providers);

    if (!registryDecision.ready) {
      process.stderr.write(`BLOCKED (exit ${EXIT_NOT_READY}): ${registryDecision.reason}\n`);
      process.stderr.write('No temp root was allocated and no package was installed or generated.\n');

      return EXIT_NOT_READY;
    }

    const builtFlags = decideFlagsReadiness(readCliHelp(builtCliPath(), REPO_ROOT));

    if (!builtFlags.ready) {
      process.stderr.write(`BLOCKED (exit ${EXIT_NOT_READY}): ${builtFlags.reason}\n`);
      process.stderr.write('No temp root was allocated and no package was installed or generated.\n');

      return EXIT_NOT_READY;
    }

    providers = registry.providers;
  }

  // Capture read-only inputs before any control/qualification work.
  const beforeInputs = snapshotRunInputs();
  let failure = null;
  let controls = null;
  let qualification = { code: EXIT_PASS, message: '' };

  try {
    if (selfTest) {
      controls = runSelfTests();
    } else {
      // Harness controls prove the detectors work before trusting a pass.
      runSelfTests();
      qualification = await runQualification(providers, locateNpmCli());
    }
  } catch (error) {
    failure = error;
  }

  // Input integrity is checked even when the run itself failed (including a
  // cleanup failure or uncertain child termination).
  let integrityError = null;

  try {
    compareRunInputs(beforeInputs, snapshotRunInputs(), selfTest ? '--self-test' : 'qualification');
  } catch (error) { integrityError = error; }

  if (failure !== null) {
    process.stderr.write(`FAIL: ${redact(failure.message ?? String(failure))}\n`);

    return EXIT_FAIL;
  }

  if (integrityError !== null) {
    process.stderr.write(`FAIL: ${redact(integrityError.message)}\n`);

    return EXIT_FAIL;
  }

  if (selfTest) {
    process.stdout.write('SELF-TEST PASS (harness controls only; not SDK evidence):\n');

    for (const control of controls) process.stdout.write(`  - ${control}\n`);

    process.stdout.write('SELF-TEST NOTE: harness controls do not establish Grafana or Polar support.\n');

    return EXIT_PASS;
  }

  // PASS is only reported after cleanup and input-integrity both succeeded.
  if (qualification.code === EXIT_PASS) process.stdout.write(qualification.message);

  return qualification.code;
}

process.exitCode = await main();
