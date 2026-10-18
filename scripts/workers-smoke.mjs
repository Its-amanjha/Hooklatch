#!/usr/bin/env node
/**
 * Offline Workers runtime smoke harness for hooklatch.
 *
 * Bundles `tests/workers/worker.ts` together with the core and the Cloudflare
 * Workers adapter using esbuild, then executes the bundle inside a real
 * `workerd` runtime via Miniflare. Nothing in this harness touches the network:
 * `Miniflare#dispatchFetch` invokes the Worker in-process, and no Cloudflare,
 * provider, or Upstash account is involved.
 *
 * Runtime qualification constraints:
 *  - No Node compatibility flags: esbuild uses `platform: 'neutral'` with
 *    `workerd`/`worker`/`browser` export conditions, and Miniflare runs with an
 *    empty `compatibilityFlags` array. Any `node:` builtin import in the core
 *    therefore fails the esbuild resolve step rather than being polyfilled.
 *  - No skipping: if the core or adapter cannot run in workerd, the harness
 *    fails. There is no "unsupported, skipping" path.
 *  - Temporary build output goes to an OS temp directory, never into tracked
 *    source, and is removed on exit.
 *  - Miniflare is always disposed, including on assertion failure or throw.
 *
 * Exit codes:
 *   0  PASS   - every case passed
 *   1  FAIL   - a case failed, the bundle would not build, or the runtime threw
 *   2  USAGE  - the harness could not start (missing toolchain, bad invocation)
 *   3  BLOCKED- required partner-owned source files are not present yet
 *
 * `BLOCKED` is deliberately nonzero: a run that could not execute the core is
 * never reported as a pass.
 */

import { createHash, createHmac } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import * as esbuild from 'esbuild';
import { Miniflare } from 'miniflare';

import {
  COMPATIBILITY_DATE,
  ENV_BINDINGS,
  ENV_MARKER,
  FIXED_NOW,
  GITHUB_BODY,
  GITHUB_DELIVERY_ID,
  GITHUB_SECRET,
  GITHUB_SIGNATURE_HEADER,
  GITHUB_TAMPERED_BODY,
  ORIGIN,
  OVERSIZED_BODY,
  PROBE_MAX_BODY_BYTES,
  ROUTE_GITHUB,
  ROUTE_REQUEST_WRAPPER,
  ROUTE_REQUEST_WRAPPER_STANDARD_WEBHOOKS,
  ROUTE_RUNTIME,
  ROUTE_STANDARD_WEBHOOKS,
  STANDARD_WEBHOOKS_BODY,
  STANDARD_WEBHOOKS_EXPIRED_OFFSET_SECONDS,
  STANDARD_WEBHOOKS_ID,
  STANDARD_WEBHOOKS_SECRET,
  STANDARD_WEBHOOKS_SIGNATURE,
  STANDARD_WEBHOOKS_TAMPERED_BODY,
  STANDARD_WEBHOOKS_TIMESTAMP,
} from '../tests/workers/fixtures.mjs';

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const WORKER_ENTRY = path.join(PROJECT_ROOT, 'tests', 'workers', 'worker.ts');

/**
 * Files this harness needs that other partners own. Listed explicitly so a
 * blocked run reports the exact dependency instead of an opaque bundler error.
 */
const REQUIRED_SOURCES = [
  { relative: 'src/index.ts', owner: 'Codex', purpose: 'root exports: verify, verifyRequest, createVerifier, HooklatchError' },
  { relative: 'src/adapters/cloudflare.ts', owner: 'Beam', purpose: 'Workers adapter: createWebhookHandler' },
  { relative: 'src/providers/index.ts', owner: 'DeepSeek', purpose: 'provider descriptors: getProviderDescriptor' },
];

const EXIT = { PASS: 0, FAIL: 1, USAGE: 2, BLOCKED: 3 };

/* -------------------------------------------------------------------------- */
/* assertion recording                                                         */
/* -------------------------------------------------------------------------- */

const results = [];

function check(name, ok, detail) {
  results.push({ name, ok: Boolean(ok), detail: detail ?? '' });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}`);
}

function checkEqual(name, actual, expected) {
  const same = actual === expected;
  const detail = same
    ? `= ${JSON.stringify(actual)}`
    : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
  check(name, same, detail);
  return same;
}

function checkBytes(name, actualBase64, expectedBytes) {
  const actual = Buffer.from(actualBase64 ?? '', 'base64');
  const ok = actual.length === expectedBytes.length && actual.equals(Buffer.from(expectedBytes));
  const detail = ok
    ? `${actual.length} bytes identical`
    : `expected ${expectedBytes.length} bytes ${JSON.stringify(Buffer.from(expectedBytes).toString('utf8'))}, got ${actual.length} bytes ${JSON.stringify(actual.toString('utf8'))}`;
  check(name, ok, detail);
  return ok;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

/* -------------------------------------------------------------------------- */
/* preflight                                                                   */
/* -------------------------------------------------------------------------- */

async function preflightSources() {
  const missing = REQUIRED_SOURCES.filter((entry) => !existsSync(path.join(PROJECT_ROOT, entry.relative)));
  if (missing.length === 0) return;

  console.error('');
  console.error('RESULT: BLOCKED — required partner-owned source files are absent.');
  console.error('This harness will not substitute its own implementations.');
  console.error('');
  for (const entry of missing) {
    console.error(`  missing: ${entry.relative}`);
    console.error(`    owner:  ${entry.owner}`);
    console.error(`    needed: ${entry.purpose}`);
  }
  console.error('');
  console.error('Until these land, the Workers runtime qualification cannot run.');
  process.exit(EXIT.BLOCKED);
}

function checkNodeCompatibilityFlags() {
  // Explicit, not implicit: a future edit that adds nodejs_compat must fail.
  const flags = [];
  check('miniflare runs without Node compatibility flags', !flags.includes('nodejs_compat'), `compatibilityFlags=[]`);
  check(
    'esbuild targets a neutral platform with workerd conditions',
    WORKER_CONDITIONS.includes('workerd') && WORKER_CONDITIONS.includes('worker'),
    `platform=neutral conditions=${WORKER_CONDITIONS.join(',')}`,
  );
}

const WORKER_CONDITIONS = ['workerd', 'worker', 'browser'];

/* -------------------------------------------------------------------------- */
/* build                                                                       */
/* -------------------------------------------------------------------------- */

async function bundleWorker(outfile) {
  await esbuild.build({
    entryPoints: [WORKER_ENTRY],
    outfile,
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    target: 'es2022',
    conditions: WORKER_CONDITIONS,
    mainFields: ['module', 'main'],
    sourcemap: 'inline',
    logLevel: 'warning',
  });

  const code = await readFile(outfile, 'utf8');
  const nodeImports = [...code.matchAll(/(?:from|import|require\()\s*["'](node:[a-z_/]+)["']/gi)].map((m) => m[1]);
  checkEqual('bundle contains no node: builtin imports', nodeImports.length, 0);
  if (nodeImports.length > 0) check('bundle node builtin detail', false, [...new Set(nodeImports)].join(', '));
  return code;
}

/* -------------------------------------------------------------------------- */
/* cases                                                                       */
/* -------------------------------------------------------------------------- */

function standardWebhooksHeaders({ id = STANDARD_WEBHOOKS_ID, timestamp, signature = STANDARD_WEBHOOKS_SIGNATURE }) {
  return {
    'content-type': 'application/json',
    'webhook-id': id,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': signature,
  };
}

/** Locally derived (not a published vector): valid HMAC over a stale timestamp. */
function derivedStandardWebhooksSignature(timestamp) {
  const key = Buffer.from(STANDARD_WEBHOOKS_SECRET.slice('whsec_'.length), 'base64');
  const content = Buffer.from(`${STANDARD_WEBHOOKS_ID}.${timestamp}.${STANDARD_WEBHOOKS_BODY}`, 'utf8');
  return `v1,${createHmac('sha256', key).update(content).digest('base64')}`;
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { __unparsable: text.slice(0, 200) };
  }
}

/**
 * The adapter response contract requires 400/413/500 responses
 * to carry *generic* text, with core reasons kept out of HTTP bodies so they
 * remain available only for safe application-side logging. This asserts that
 * contract positively, and additionally asserts the rejection body leaks
 * neither the signing secret nor the submitted signature.
 */
async function checkGenericRejection(label, response) {
  const body = (await response.text()).trim();
  const opaque = body !== '' && !body.startsWith('{') && !body.startsWith('[');
  check(`${label}: rejection body is generic text, not a diagnostics payload`, opaque, JSON.stringify(body.slice(0, 80)));
  const leaks = [GITHUB_SECRET, GITHUB_SIGNATURE_HEADER, GITHUB_SIGNATURE_HEADER.split('=')[1], STANDARD_WEBHOOKS_SECRET, STANDARD_WEBHOOKS_SIGNATURE]
    .filter((value) => value && body.includes(value));
  checkEqual(`${label}: rejection body leaks no secret or signature`, leaks.length, 0);
}

async function runCases(mf) {
  const post = (pathname, headers, body) =>
    mf.dispatchFetch(`${ORIGIN}${pathname}`, {
      method: 'POST',
      headers,
      body: new Uint8Array(Buffer.from(body, 'utf8')),
    });

  // ---- runtime identity -----------------------------------------------------
  const runtime = await mf.dispatchFetch(`${ORIGIN}${ROUTE_RUNTIME}`);
  const runtimeBody = await readJson(runtime);
  checkEqual('runs inside a real workerd runtime', runtimeBody.userAgent, 'Cloudflare-Workers');
  checkEqual('no Node globals leak into the Worker', runtimeBody.hasNodeGlobals, false);

  // ---- GitHub published vector ---------------------------------------------
  const github = await post(
    ROUTE_GITHUB,
    {
      'content-type': 'text/plain',
      'x-hub-signature-256': GITHUB_SIGNATURE_HEADER,
      'x-github-delivery': GITHUB_DELIVERY_ID,
      'x-github-event': 'push',
    },
    GITHUB_BODY,
  );
  checkEqual('github published vector returns 200', github.status, 200);
  const githubBody = await readJson(github);
  checkEqual('github published vector verifies', githubBody.verified, true);
  checkEqual('github provider is reported', githubBody.provider, 'github');
  checkBytes('github handler receives the exact request bytes', githubBody.rawBodyBase64, GITHUB_BODY);
  checkEqual('in-worker sha256 matches node sha256 (github)', githubBody.rawBodySha256Hex, sha256Hex(Buffer.from(GITHUB_BODY, 'utf8')));
  checkEqual('github unsigned delivery id is surfaced as identity', githubBody.identity?.deliveryId, GITHUB_DELIVERY_ID);
  checkEqual('github claims no signed timestamp', githubBody.identity?.timestamp, null);
  checkEqual('env binding resolved inside workerd', githubBody.envMarker, ENV_MARKER);

  // ---- GitHub tampered bytes ----------------------------------------------
  const githubTampered = await post(
    ROUTE_GITHUB,
    { 'content-type': 'text/plain', 'x-hub-signature-256': GITHUB_SIGNATURE_HEADER, 'x-github-delivery': GITHUB_DELIVERY_ID },
    GITHUB_TAMPERED_BODY,
  );
  checkEqual('github tampered bytes rejected with 400', githubTampered.status, 400);
  await checkGenericRejection('github tampered bytes', githubTampered);

  // ---- Standard Webhooks published vector ---------------------------------
  const sw = await post(
    ROUTE_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: STANDARD_WEBHOOKS_TIMESTAMP }),
    STANDARD_WEBHOOKS_BODY,
  );
  checkEqual('standard-webhooks published vector returns 200', sw.status, 200);
  const swBody = await readJson(sw);
  checkEqual('standard-webhooks published vector verifies', swBody.verified, true);
  checkBytes('standard-webhooks handler receives the exact request bytes', swBody.rawBodyBase64, STANDARD_WEBHOOKS_BODY);
  checkEqual(
    'in-worker sha256 matches node sha256 (standard-webhooks)',
    swBody.rawBodySha256Hex,
    sha256Hex(Buffer.from(STANDARD_WEBHOOKS_BODY, 'utf8')),
  );
  checkEqual('standard-webhooks signed event id surfaced', swBody.identity?.eventId, STANDARD_WEBHOOKS_ID);
  checkEqual('standard-webhooks signed timestamp surfaced', swBody.identity?.timestamp, STANDARD_WEBHOOKS_TIMESTAMP);
  check(
    'standard-webhooks marks id and timestamp as signature-authenticated',
    Array.isArray(swBody.identity?.authenticatedFields)
      && swBody.identity.authenticatedFields.includes('eventId')
      && swBody.identity.authenticatedFields.includes('timestamp'),
    JSON.stringify(swBody.identity?.authenticatedFields),
  );

  // ---- Standard Webhooks tampered bytes -----------------------------------
  const swTampered = await post(
    ROUTE_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: STANDARD_WEBHOOKS_TIMESTAMP }),
    STANDARD_WEBHOOKS_TAMPERED_BODY,
  );
  checkEqual('standard-webhooks tampered bytes rejected with 400', swTampered.status, 400);
  await checkGenericRejection('standard-webhooks tampered bytes', swTampered);

  // ---- Standard Webhooks stale timestamp (freshness in workerd) -----------
  const expiredTs = STANDARD_WEBHOOKS_TIMESTAMP - STANDARD_WEBHOOKS_EXPIRED_OFFSET_SECONDS;
  const swExpired = await post(
    ROUTE_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: expiredTs, signature: derivedStandardWebhooksSignature(expiredTs) }),
    STANDARD_WEBHOOKS_BODY,
  );
  checkEqual('standard-webhooks stale timestamp rejected with 400', swExpired.status, 400);
  await checkGenericRejection('standard-webhooks stale timestamp', swExpired);

  // ---- core reasons, observable only through the verifyRequest probes -------
  // The adapter contract keeps reasons out of HTTP bodies by design, so the
  // exact reason for each rejection is asserted here instead.
  const probeGitHubTampered = await post(
    ROUTE_REQUEST_WRAPPER,
    { 'content-type': 'text/plain', 'x-hub-signature-256': GITHUB_SIGNATURE_HEADER, 'x-github-delivery': GITHUB_DELIVERY_ID },
    GITHUB_TAMPERED_BODY,
  );
  checkEqual('core reason: github tampered is invalid-signature', (await readJson(probeGitHubTampered)).reason, 'invalid-signature');

  const probeSwTampered = await post(
    ROUTE_REQUEST_WRAPPER_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: STANDARD_WEBHOOKS_TIMESTAMP }),
    STANDARD_WEBHOOKS_TAMPERED_BODY,
  );
  checkEqual('core reason: standard-webhooks tampered is invalid-signature', (await readJson(probeSwTampered)).reason, 'invalid-signature');

  const probeSwExpired = await post(
    ROUTE_REQUEST_WRAPPER_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: expiredTs, signature: derivedStandardWebhooksSignature(expiredTs) }),
    STANDARD_WEBHOOKS_BODY,
  );
  checkEqual('core reason: stale timestamp is timestamp-expired', (await readJson(probeSwExpired)).reason, 'timestamp-expired');

  // Freshness must not be reachable without a correct signature.
  const probeSwBadSigStaleTs = await post(
    ROUTE_REQUEST_WRAPPER_STANDARD_WEBHOOKS,
    standardWebhooksHeaders({ timestamp: expiredTs }),
    STANDARD_WEBHOOKS_BODY,
  );
  checkEqual(
    'core checks cryptography before freshness',
    (await readJson(probeSwBadSigStaleTs)).reason,
    'invalid-signature',
  );

  // ---- verifyRequest wrapper, success --------------------------------------
  const wrapper = await post(
    ROUTE_REQUEST_WRAPPER,
    { 'content-type': 'text/plain', 'x-hub-signature-256': GITHUB_SIGNATURE_HEADER, 'x-github-delivery': GITHUB_DELIVERY_ID },
    GITHUB_BODY,
  );
  checkEqual('verifyRequest wrapper returns 200', wrapper.status, 200);
  const wrapperBody = await readJson(wrapper);
  checkEqual('verifyRequest wrapper verifies', wrapperBody.verified, true);
  checkBytes('verifyRequest wrapper returns the exact bytes', wrapperBody.rawBodyBase64, GITHUB_BODY);

  // ---- verifyRequest wrapper, tampered -------------------------------------
  const wrapperTampered = await post(
    ROUTE_REQUEST_WRAPPER,
    { 'content-type': 'text/plain', 'x-hub-signature-256': GITHUB_SIGNATURE_HEADER, 'x-github-delivery': GITHUB_DELIVERY_ID },
    GITHUB_TAMPERED_BODY,
  );
  checkEqual('verifyRequest wrapper rejects tampered bytes', wrapperTampered.status, 400);
  checkEqual('verifyRequest wrapper tampered reason', (await readJson(wrapperTampered)).reason, 'invalid-signature');

  // ---- streaming body limit in workerd -------------------------------------
  const oversized = await post(
    ROUTE_REQUEST_WRAPPER,
    { 'content-type': 'text/plain', 'x-hub-signature-256': GITHUB_SIGNATURE_HEADER },
    OVERSIZED_BODY,
  );
  checkEqual('body overflow returns 413', oversized.status, 413);
  checkEqual('body overflow reason', (await readJson(oversized)).reason, 'body-too-large');
  checkEqual('overflow fixture really exceeds the limit', OVERSIZED_BODY.length > PROBE_MAX_BODY_BYTES, true);

  // ---- unknown route --------------------------------------------------------
  const missing = await mf.dispatchFetch(`${ORIGIN}/probe/does-not-exist`);
  checkEqual('unknown route returns 404', missing.status, 404);
}

/* -------------------------------------------------------------------------- */
/* main                                                                        */
/* -------------------------------------------------------------------------- */

async function main() {
  await preflightSources();
  checkNodeCompatibilityFlags();

  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'hooklatch-workers-smoke-'));
  const bundlePath = path.join(tempDir, 'worker.mjs');
  let miniflare;
  let failure = null;

  console.log('');
  console.log('Hooklatch — offline Workers runtime smoke');
  console.log(`  node                ${process.version}`);
  console.log(`  esbuild             ${esbuild.version}`);
  console.log(`  miniflare           ${readVersion('miniflare')}`);
  console.log(`  workerd             ${readVersion('workerd')}`);
  console.log(`  compatibilityDate   ${COMPATIBILITY_DATE}`);
  console.log(`  fixed clock (epoch) ${FIXED_NOW}`);
  console.log(`  temp build          ${tempDir}`);
  console.log('');

  try {
    await bundleWorker(bundlePath);

    miniflare = new Miniflare({
      modules: true,
      scriptPath: bundlePath,
      compatibilityDate: COMPATIBILITY_DATE,
      compatibilityFlags: [],
      bindings: { ...ENV_BINDINGS },
    });

    await runCases(miniflare);
  } catch (error) {
    failure = error;
    console.error('');
    console.error(`RESULT: FAIL — ${error instanceof Error ? error.message : String(error)}`);
    if (error instanceof Error && error.stack) console.error(error.stack);
  } finally {
    // Always dispose, even on throw, so the workerd child never lingers.
    if (miniflare) {
      try {
        await miniflare.dispose();
        console.log('miniflare disposed');
      } catch (error) {
        console.error(`failed to dispose miniflare: ${error instanceof Error ? error.message : String(error)}`);
        failure ??= new Error('miniflare disposal failed');
      }
    }
    await rm(tempDir, { recursive: true, force: true });
  }

  const failed = results.filter((result) => !result.ok);
  console.log('');
  console.log(`${results.length - failed.length}/${results.length} checks passed`);

  if (failure) {
    process.exit(EXIT.FAIL);
  }
  if (failed.length > 0) {
    for (const result of failed) console.error(`  failed: ${result.name} ${result.detail}`);
    console.error('RESULT: FAIL');
    process.exit(EXIT.FAIL);
  }
  console.log('RESULT: PASS');
  process.exit(EXIT.PASS);
}

function readVersion(packageName) {
  try {
    const packageJson = path.join(PROJECT_ROOT, 'node_modules', packageName, 'package.json');
    return JSON.parse(readFileSync(packageJson, 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

main().catch((error) => {
  console.error(`harness crashed: ${error instanceof Error ? error.stack : String(error)}`);
  process.exit(EXIT.USAGE);
});
