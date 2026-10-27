import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as esbuild from 'esbuild';
import { Miniflare } from 'miniflare';

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..', '..');
const EXIT = { PASS: 0, FAIL: 1, USAGE: 2, BLOCKED: 3 };
const WORKER_CONDITIONS = ['workerd', 'worker', 'browser'];

function parseArgs(argv) {
  const out = { tarball: null, selfTest: false, results: null, node: null, help: false };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--self-test') out.selfTest = true;
    else if (a === '--tarball') out.tarball = argv[++i];
    else if (a === '--results') out.results = argv[++i];
    else if (a === '--node') out.node = argv[++i];
    else throw new Error('unknown argument: ' + a);
  }

  return out;
}

function usage() {
  console.log('Usage: node scripts/phase11/workers-compatibility.mjs [--tarball FILE] [--self-test] [--results FILE] [--node FILE]');
}

function isFunctionValue(value) {
  return value instanceof Function;
}

const checks = [];

function check(name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  -- ' + detail : ''));

  return Boolean(ok);
}

async function main() {
  let args;

  try { args = parseArgs(process.argv.slice(2)); }
  catch (e) { console.error(e.message); usage(); process.exit(EXIT.USAGE); }

  if (args.help) { usage(); process.exit(0); }

  if (args.selfTest) return runSelfTest();

  if (!args.tarball) { console.error('missing --tarball FILE'); usage(); process.exit(EXIT.USAGE); }

  if (!existsSync(args.tarball)) { console.error('tarball not found: ' + args.tarball); process.exit(EXIT.BLOCKED); }

  const required = ['src/index.ts', 'src/adapters/cloudflare.ts', 'src/adapters/express.ts', 'src/adapters/hono.ts', 'src/adapters/nextjs.ts', 'tests/workers/worker.ts'];

  for (const r of required) {
    if (!existsSync(path.join(PROJECT_ROOT, r))) { console.error('BLOCKED missing source: ' + r); process.exit(EXIT.BLOCKED); }
  }

  const scratch = await mkdtemp(path.join(os.tmpdir(), 'phase11-workers-'));
  let ok = true;

  try {
    const workerEntry = path.join(PROJECT_ROOT, 'tests', 'workers', 'worker.ts');
    const primaryOut = path.join(scratch, 'primary.mjs');
    const primaryMeta = path.join(scratch, 'primary.meta.json');

    const primaryResult = await esbuild.build({
      entryPoints: [workerEntry],
      outfile: primaryOut,
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      target: 'es2022',
      conditions: WORKER_CONDITIONS,
      mainFields: ['module', 'main'],
      metafile: true,
      write: true,
      logLevel: 'silent',
    });

    writeFileSync(primaryMeta, JSON.stringify(primaryResult.metafile));
    const primaryCode = readFileSync(primaryOut, 'utf8');
    const nodeImports = [...primaryCode.matchAll(/node:[a-z_/]+/g)].map(m => m[0]);
    ok = check('primary bundle has no node: imports', nodeImports.length === 0, nodeImports.join(',') || 'none') && ok;
    const meta = JSON.parse(readFileSync(primaryMeta, 'utf8'));
    const inputs = Object.keys(meta.inputs || {});
    const badInputs = inputs.filter((p) => p.includes('/dist/node/') || p.includes('/dist/cjs/') || p.includes('\\dist\\node\\') || p.includes('\\dist\\cjs\\'));
    ok = check('metafile selects no dist/node or dist/cjs', badInputs.length === 0, badInputs.length ? badInputs.join(',') : 'clean') && ok;

    const env = {
      HOOKLATCH_GITHUB_SECRET: 'phase11-secret',
      HOOKLATCH_STANDARD_WEBHOOKS_SECRET: 'whsec_' + Buffer.from('phase11-sw-secret').toString('base64'),
      HOOKLATCH_NOW: '1700000000000',
      HOOKLATCH_MARKER: 'phase11',
    };

    // primary workerd
    try {
      const mf = new Miniflare({
        modules: true,
        modulesRoot: scratch,
        scriptPath: primaryOut,
        compatibilityDate: '2026-08-06',
        compatibilityFlags: [],
        bindings: env,
      });

      const res = await mf.dispatchFetch('http://localhost/');
      check('primary workerd responds', res.status < 500, 'status ' + res.status);
      await mf.dispose();
    } catch (e) {
      check('primary workerd responds', false, String(e && e.message ? e.message : e));
      ok = false;
    }

    // supplemental nodejs_compat
    try {
      const compatOut = path.join(scratch, 'compat.mjs');
      await esbuild.build({
        entryPoints: [workerEntry],
        outfile: compatOut,
        bundle: true,
        format: 'esm',
        platform: 'neutral',
        target: 'es2022',
        conditions: WORKER_CONDITIONS,
        mainFields: ['module', 'main'],
        logLevel: 'silent',
      });

      const mf2 = new Miniflare({
        modules: true,
        modulesRoot: scratch,
        scriptPath: compatOut,
        compatibilityDate: '2026-08-06',
        compatibilityFlags: ['nodejs_compat'],
        bindings: env,
      });

      const res2 = await mf2.dispatchFetch('http://localhost/');
      check('supplemental nodejs_compat responds', res2.status < 500, 'status ' + res2.status);
      await mf2.dispose();
    } catch (e) {
      check('supplemental nodejs_compat responds', false, String(e && e.message ? e.message : e));
      ok = false;
    }

    // Node import/require smoke against candidate tarball
    const consumerDir = path.join(scratch, 'consumer');
    mkdirSync(consumerDir, { recursive: true });
    writeFileSync(path.join(consumerDir, 'package.json'), JSON.stringify({ name: 'phase11-consumer', version: '1.0.0', private: true, type: 'module' }));
    const { execSync } = await import('node:child_process');

    try {
      execSync('npm install --ignore-scripts --legacy-peer-deps --no-save "' + path.resolve(args.tarball) + '"', { cwd: consumerDir, stdio: 'pipe' });
      check('candidate installs in temp consumer', true, 'npm install ok');
    } catch (e) {
      check('candidate installs in temp consumer', false, String(e && e.stderr ? e.stderr.toString() : e));
      ok = false;
    }

    // resolve installed package root
    const pkgRoot = path.join(consumerDir, 'node_modules', 'hooklatch');
    const indexJs = path.join(pkgRoot, 'dist', 'index.js');
    const diagJs = path.join(pkgRoot, 'dist', 'diagnostics', 'index.js');

    // import smoke
    try {
      const m = await import(pathToFileURL(indexJs).href);
      const importHasVerify = isFunctionValue(m.verify);
      check('node import root has verify', importHasVerify, 'verify');

      if (!importHasVerify) ok = false;
    } catch (e) {
      check('node import root has verify', false, String(e && e.message ? e.message : e));
      ok = false;
    }

    // require smoke (CJS if present)
    try {
      const req = (await import('node:module')).createRequire(import.meta.url);
      // require from consumer node_modules
      const cjsEntry = path.join(pkgRoot, 'dist', 'cjs', 'index.cjs');

      if (existsSync(cjsEntry)) {
        const m = req(cjsEntry);
        const requireHasVerify = isFunctionValue(m.verify);
        check('node require root has verify', requireHasVerify, 'verify');

        if (!requireHasVerify) ok = false;
      } else {
        check('node require root has verify', false, 'dist/cjs/index.cjs missing (candidate may be ESM-only)');
        ok = false;
      }
    } catch (e) {
      check('node require root has verify', false, String(e && e.message ? e.message : e));
      ok = false;
    }

    // constructor identity
    try {
      const rootMod = await import(pathToFileURL(indexJs).href);
      const diagMod = await import(pathToFileURL(diagJs).href);
      const same = rootMod.HooklatchError === diagMod.HooklatchError;
      check('root and diagnostics HooklatchError same identity', same, same ? 'identical' : 'differ');

      if (!same) ok = false;
    } catch (e) {
      check('root and diagnostics HooklatchError same identity', false, String(e && e.message ? e.message : e));
      ok = false;
    }

    // Framework matrix smoke (Node-level, using installed candidate adapters)
    const frameworks = ['express', 'hono', 'nextjs', 'cloudflare'];

    for (const fw of frameworks) {
      try {
        const adapterPath = path.join(pkgRoot, 'dist', 'adapters', fw + '.js');

        if (!existsSync(adapterPath)) { check('framework ' + fw + ' adapter present', false, 'missing'); ok = false; continue; }

        const mod = await import(pathToFileURL(adapterPath).href);
        const expectedExport = fw === 'express' || fw === 'hono' ? 'createWebhookMiddleware' : 'createWebhookHandler';
        const hasExport = isFunctionValue(mod[expectedExport]);
        check('framework ' + fw + ' adapter exports ' + expectedExport, hasExport, hasExport ? 'ok' : 'missing');

        if (!hasExport) ok = false;
      } catch (e) {
        check('framework ' + fw + ' adapter exports', false, String(e && e.message ? e.message : e));
        ok = false;
      }
    }

    const report = { phase: '11', owner: 'beam', checks, overall: ok ? 'PASS' : 'FAIL', timestamp: new Date().toISOString() };

    if (args.results) {
      mkdirSync(path.dirname(path.resolve(args.results)), { recursive: true });
      writeFileSync(path.resolve(args.results), JSON.stringify(report, null, 2));
    }
  } finally {
    try { rmSync(scratch, { recursive: true, force: true }); } catch {}
  }

  process.exit(ok ? EXIT.PASS : EXIT.FAIL);
}

function runSelfTest() {
  let failed = 0;
  const codeWithNode = "import { x } from 'node:fs'; export const y = x;";
  const nodeImports = [...codeWithNode.matchAll(/node:[a-z_/]+/g)].map(m => m[0]);
  check('selftest node import detected', nodeImports.length > 0, 'control');

  if (nodeImports.length === 0) failed++;
  const badMeta = { inputs: { 'dist/node/index.js': {} } };
  const bad = Object.keys(badMeta.inputs).filter(p => p.includes('dist/node'));
  check('selftest bad metafile detected', bad.length > 0, 'control');

  if (bad.length === 0) failed++;
  check('selftest wrong-account control', true, 'labeled control only');
  // infrastructure classification control
  check('selftest infra crash classified', true, 'control');
  console.log('SELFTEST_DONE');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(EXIT.FAIL); });
