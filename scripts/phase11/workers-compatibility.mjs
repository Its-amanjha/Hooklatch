import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import {
  createHealthLedger, createWorkspace, createTrackedJunction, disposeWorkspace,
  installCandidateConsumer, packCheckout, runChild, snapshotCheckout, compareCheckout,
} from './mixed-format-runtime.mjs';
import { UsageError, validateResultsDestination } from './package-contract.mjs';
import { FRAMEWORKS, STATES, assertResponse, inputBody, materializeOptions } from '../../tests/compatibility/phase11-framework-consumer.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const BASES = ['index', 'diagnostics/index', 'adapters/express', 'adapters/hono', 'adapters/nextjs', 'adapters/cloudflare'];

function parseArgs(argv) {
  const args = { tarball: null, node: process.execPath, results: null, selfTest: false, help: false };
  const seen = new Set();

  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index];

    if (seen.has(flag)) throw new UsageError('duplicate flag');
    seen.add(flag);

    if (flag === '--self-test') args.selfTest = true;
    else if (flag === '--help') args.help = true;
    else if (['--tarball', '--node', '--results'].includes(flag)) {
      const value = argv[++index];

      if (!value || value.startsWith('--')) throw new UsageError('missing flag value');
      args[flag.slice(2)] = path.resolve(value);
    } else throw new UsageError('unknown flag');
  }

  return args;
}

function signedCases() {
  const body = new Uint8Array([0, 255, 195, 40, 10, 128, 65]);
  const now = 1700000100;
  const secret = 'phase11-synthetic-credential-canary';
  const hmac = (bytes) => createHmac('sha256', secret).update(bytes).digest('hex');
  const identity = { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] };
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const hash = createHash('sha256').update(body).digest('hex');
  const user = 'phase11-synthetic-user';
  const requestId = 'phase11-synthetic-request';

  return [
    { provider: 'github', body: [...body], now, identity,
      options: { provider: 'github', secrets: [secret] },
      headers: { 'x-hub-signature-256': `sha256=${hmac(body)}` } },
    { provider: 'grafana', body: [...body], now,
      identity: { ...identity, timestamp: now, authenticatedFields: ['timestamp'] },
      options: { provider: 'grafana', secrets: [secret], providerOptions: { mode: 'timestamped', signatureHeader: 'x-custom-mac', timestampHeader: 'x-custom-time' } },
      headers: { 'x-custom-mac': hmac(Buffer.concat([Buffer.from(`${now}:`), body])), 'x-custom-time': String(now) } },
    { provider: 'fal', body: [...body], now,
      identity: { ...identity, timestamp: now, authenticatedFields: ['timestamp'] },
      options: { provider: 'fal', publicKeys: [[...publicKey]], expectedUserId: user },
      headers: { 'x-fal-webhook-signature': sign(null, Buffer.from(`${requestId}\n${user}\n${now}\n${hash}`), keys.privateKey).toString('hex'),
        'x-fal-webhook-request-id': requestId, 'x-fal-webhook-user-id': user, 'x-fal-webhook-timestamp': String(now) } },
  ];
}

function workerSource(entries) {
  return `import * as root from 'hooklatch';
import * as diagnostics from 'hooklatch/diagnostics';
import * as express from 'hooklatch/express';
import * as hono from 'hooklatch/hono';
import * as nextjs from 'hooklatch/nextjs';
import * as cloudflare from 'hooklatch/cloudflare';
const entries = ${JSON.stringify(entries)};
const assertResponse = ${assertResponse.toString()};
const inputBody = ${inputBody.toString()};
const materializeOptions = ${materializeOptions.toString()};
export default { async fetch(request) {
  const functions = [root.verify, diagnostics.diagnose, express.createWebhookMiddleware, hono.createWebhookMiddleware, nextjs.createWebhookHandler, cloudflare.createWebhookHandler];
  if (functions.some((fn) => typeof fn !== 'function')) throw new Error('public exports absent');
  const tuples = [];
  for (const entry of entries) {
    for (const state of ['valid','tamper','overflow']) {
      let calls = 0;
      const handler = cloudflare.createWebhookHandler({
        options: () => ({...materializeOptions(entry),maxBodyBytes:128}),
        handler: (_request,_env,_ctx,result) => { calls++; return Response.json({bytes:[...result.rawBody],identity:result.identity}); }
      });
      const response = await handler(new Request('https://synthetic.invalid/hook',{method:'POST',headers:entry.headers,body:inputBody(entry,state)}),{},{});
      assertResponse(response.status,await response.text(),calls,entry,state);
      tuples.push({provider:entry.provider,state});
    }
  }
  const fal = entries.find((entry) => entry.provider === 'fal');
  let calls = 0;
  const wrongAccount = cloudflare.createWebhookHandler({options:()=>({...materializeOptions(fal),expectedUserId:'another-account'}),handler:()=>{calls++;return new Response('unexpected');}});
  const rejected = await wrongAccount(new Request('https://synthetic.invalid',{method:'POST',headers:fal.headers,body:new Uint8Array(fal.body)}),{},{});
  assertResponse(rejected.status,await rejected.text(),calls,fal,'tamper');
  return Response.json({tuples,wrongAccount:true,userAgent:navigator.userAgent,process:typeof globalThis.process,Buffer:typeof globalThis.Buffer,require:typeof globalThis.require,url:request.url});
}};`;
}

function validateBundle(result) {
  const inputs = Object.keys(result.metafile.inputs).map((name) => name.replaceAll('\\', '/'));

  assert.equal(inputs.some((name) => /\/dist\/(node|cjs)\//.test(name)), false, 'Node branch in neutral bundle');

  for (const base of BASES) assert.ok(inputs.some((name) => name.endsWith(`/hooklatch/dist/${base}.js`)), `original ESM entry missing: ${base}`);
  assert.equal(result.outputFiles[0].text.includes('node:'), false, 'Node builtin in neutral output');

  return inputs;
}

async function workerMatrix(code, compat, timeoutMs = 30000) {
  const worker = new Miniflare({ modules: true, script: code, compatibilityDate: '2026-08-06', compatibilityFlags: compat ? ['nodejs_compat'] : [] });

  let timer;

  try {
    const response = await Promise.race([worker.dispatchFetch('https://synthetic.invalid/'), new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('worker timed out')), timeoutMs); })]);
    const text = await response.text();

    assert.equal(response.status, 200, text);

    const report = JSON.parse(text);
    assert.equal(report.userAgent, 'Cloudflare-Workers');

    if (!compat) {
      assert.equal(report.process, 'undefined');
      assert.equal(report.Buffer, 'undefined');
      assert.equal(report.require, 'undefined');
    }

    assert.equal(report.wrongAccount, true);
    assert.deepEqual(report.tuples, ['github', 'grafana', 'fal'].flatMap((provider) => STATES.map((state) => ({ provider, state }))));

    return report;
  } finally {
    clearTimeout(timer);
    await worker.dispose();
  }
}

async function run(args) {
  if (args.help) {
    console.log('Usage: workers-compatibility.mjs [--tarball FILE] [--node FILE] [--results FILE] [--self-test]');

    return 0;
  }

  if (args.results !== null) validateResultsDestination(args.results, ROOT);

  if (args.tarball === null && (!existsSync(path.join(ROOT, 'dist/cjs/index.cjs')) || !existsSync(path.join(ROOT, 'dist/node/index.js')))) return 3;

  if (args.tarball !== null && !existsSync(args.tarball)) return 3;

  if (!existsSync(args.node)) return 3;

  const before = snapshotCheckout();
  const workspace = createWorkspace('hooklatch-phase11-framework-');
  const ledger = createHealthLedger();
  const report = { artifact: null, runtime: null, nodeTuples: [], workers: [], controls: [] };

  try {
    const tarball = args.tarball ?? await packCheckout(workspace, ledger);

    report.artifact = { sha256: createHash('sha256').update(readFileSync(tarball)).digest('hex') };

    const { consumerDir, installedRoot } = await installCandidateConsumer(workspace, tarball, ledger);

    for (const peer of ['express', 'hono']) createTrackedJunction(workspace, path.join(ROOT, 'node_modules', peer), path.join(consumerDir, 'node_modules', peer));

    const entries = signedCases();
    const dataPath = path.join(consumerDir, 'cases.json');

    writeFileSync(dataPath, JSON.stringify(entries));
    copyFileSync(path.join(ROOT, 'tests/compatibility/phase11-framework-consumer.mjs'), path.join(consumerDir, 'phase11-framework-consumer.mjs'));

    const version = await runChild(args.node, ['-v'], { ledger });

    assert.ok(version.ok, version.stderr);
    assert.match(version.stdout.trim(), /^v(22|24)\./);
    report.runtime = version.stdout.trim();

    for (const format of ['import', 'require']) {
      const child = await runChild(args.node, ['phase11-framework-consumer.mjs', dataPath, format], { cwd: consumerDir, ledger });

      assert.ok(child.ok, child.stderr);

      const output = JSON.parse(child.stdout.trim().split('\n').pop());
      const expected = FRAMEWORKS.flatMap((framework) => entries.flatMap((entry) => STATES.map((state) => ({ framework, format, provider: entry.provider, state }))));

      assert.equal(output.runtime, report.runtime);
      assert.deepEqual(output.tuples, expected);
      report.nodeTuples.push(...output.tuples);
    }

    const entry = path.join(consumerDir, 'worker.mjs');

    writeFileSync(entry, workerSource(entries));

    const bundled = await build({ entryPoints: [entry], bundle: true, write: false, format: 'esm', platform: 'neutral', conditions: ['workerd', 'worker', 'browser'], target: 'es2022', metafile: true, logLevel: 'silent' });

    report.bundleInputs = validateBundle(bundled);

    for (const compat of [false, true]) report.workers.push(await workerMatrix(bundled.outputFiles[0].text, compat));

    if (args.selfTest) {
      const exportsPath = path.join(installedRoot, 'package.json');
      const pristineManifest = readFileSync(exportsPath, 'utf8');
      const manifest = JSON.parse(pristineManifest);

      manifest.exports['./cloudflare'].default = './dist/node/adapters/cloudflare.js';
      manifest.exports['./cloudflare'].import = './dist/node/adapters/cloudflare.js';
      writeFileSync(exportsPath, JSON.stringify(manifest));

      const wrong = await build({ entryPoints: [entry], bundle: true, write: false, format: 'esm', platform: 'neutral', conditions: ['workerd'], metafile: true, logLevel: 'silent' });

      assert.throws(() => validateBundle(wrong), /Node branch/);
      report.controls.push('wrong-branch');
      writeFileSync(exportsPath, pristineManifest);

      const wrongAccountCode = bundled.outputFiles[0].text.replace(/expectedUserId: ["']another-account["']/, 'expectedUserId:fal.options.expectedUserId');

      assert.notEqual(wrongAccountCode, bundled.outputFiles[0].text, 'account mutation site');
      await assert.rejects(() => workerMatrix(wrongAccountCode, false), { name: 'AssertionError' });
      report.controls.push('wrong-account-acceptance');

      const crash = await runChild(args.node, ['-e', 'process.exit(9)'], { ledger });

      assert.equal(crash.exitCode, 9);
      assert.equal(crash.timedOut, false);
      report.controls.push('real-child-crash');

      await assert.rejects(() => workerMatrix('export default {fetch(){throw new Error("synthetic worker crash")}}', false), { name: 'AssertionError' });
      report.controls.push('real-worker-crash');
      await assert.rejects(() => workerMatrix('export default {fetch(){return new Promise((resolve)=>setTimeout(()=>resolve(new Response("late")),60000))}}', false, 300), /worker timed out/);
      report.controls.push('real-worker-timeout');

      const builtin = await build({ stdin: { contents: "import * as fs from 'node:fs';globalThis.__probe=fs.readFileSync;" + workerSource(entries), resolveDir: consumerDir }, bundle: true, write: false, format: 'esm', platform: 'neutral', external: ['node:*'], conditions: ['workerd'], metafile: true, logLevel: 'silent' });

      assert.throws(() => validateBundle(builtin), /Node branch|Node builtin/);
      report.controls.push('node-builtin-bundle');

      const facade = path.join(installedRoot, 'dist/adapters/cloudflare.js');
      const pristine = readFileSync(facade, 'utf8');

      writeFileSync(facade, 'export function createWebhookHandler(){return async()=>new Response("misbound handler");}');

      try {
        const misbound = await build({ stdin: { contents: workerSource(entries), resolveDir: consumerDir }, bundle: true, write: false, format: 'esm', platform: 'neutral', conditions: ['workerd'], metafile: true, logLevel: 'silent' });

        await assert.rejects(() => workerMatrix(misbound.outputFiles[0].text, false), { name: 'AssertionError' });
        report.controls.push('misbound-exported-handler');
      } finally {
        writeFileSync(facade, pristine);
      }
    }
  } finally {
    disposeWorkspace(workspace, { ledger });
    assert.deepEqual(compareCheckout(before, snapshotCheckout()), []);
  }

  report.cleanupVerified = true;

  if (args.results !== null) {
    mkdirSync(path.dirname(args.results), { recursive: true });
    writeFileSync(args.results, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  }

  console.log(`PASS: ${report.nodeTuples.length} real Node framework requests; ${report.workers.length} workerd matrices; ${report.controls.length} controls.`);

  return 0;
}

async function main() {
  try {
    return await run(parseArgs(process.argv.slice(2)));
  } catch (error) {
    console.error(error);

    return error instanceof UsageError ? 2 : 1;
  }
}

process.exitCode = await main();
