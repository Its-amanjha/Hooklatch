#!/usr/bin/env node
/**
 * Phase 9 qualification runner. Delegates fixture/byte/crypto assertions to the
 * installed-package and real-workerd harnesses rather than duplicating them.
 * Exit: 0 current runtime qualified (or controls passed), 1 failure, 2 usage,
 * 3 built Stage B API absent. Other Node majors require independent executions.
 * This runner never allocates or removes scratch directories. Each delegated
 * harness owns its scratch; abnormal termination is a failure, never cleanup proof.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const providers = [
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
  'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana',
  'polar', 'linear', 'vercel', 'fal',
];

const maxOutputBytes = 8 * 1024 * 1024;

function exactRegistry(value) {
  return Array.isArray(value) && value.length === providers.length
    && providers.every((provider, index) => value[index] === provider);
}

// Terminate only the tree/group created by this runner. Do not touch scratch:
// after a timeout its contents and any unconfirmed descendants remain evidence.
function terminate(child) {
  if (process.platform === 'win32') {
    const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
      windowsHide: true, stdio: 'ignore', shell: false,
    });

    const killerDeadline = setTimeout(() => killer.kill('SIGKILL'), 5000);

    killerDeadline.unref();
    killer.on('close', () => clearTimeout(killerDeadline));
    killer.on('error', () => {
      clearTimeout(killerDeadline);
      child.kill('SIGKILL');
    });
  } else {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  }
}

function runChild(args, { timeoutMs = 180000, env = process.env, limit = maxOutputBytes } = {}) {
  return new Promise((done) => {
    const started = Date.now();

    const child = spawn(process.execPath, args, {
      cwd: root, env, windowsHide: true, shell: false,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });

    const evidence = {
      executable: process.execPath, args, pid: child.pid ?? null,
      exitCode: null, signal: null, stdout: '', stderr: '',
      timedOut: false, outputLimitExceeded: false, spawnError: null,
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
      done(evidence);
    };

    const stop = () => {
      clearTimeout(timer);
      terminate(child);
      // A missing close is infrastructure failure too. Unref abandoned handles
      // so a wedged runtime cannot turn the report into an unbounded wait.
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

      if (bytes > limit) {
        if (!evidence.outputLimitExceeded) {
          evidence.outputLimitExceeded = true;
          stop();
        }

        return;
      }

      evidence[field] += chunk.toString('utf8');
    };

    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));
    child.on('error', (error) => {
      evidence.spawnError = error.message;
      finish();
    });
    child.on('close', (code, signal) => {
      evidence.exitCode = code;
      evidence.signal = signal;
      finish();
    });
  });
}

function passed(result, requiredMarkers) {
  return result.exitCode === 0 && result.signal === null
    && !result.timedOut && !result.outputLimitExceeded && result.spawnError === null
    && requiredMarkers.every((marker) => marker.test(result.stdout));
}

async function readiness() {
  try {
    const registry = await import(pathToFileURL(join(root, 'dist/providers/index.js')).href);

    if (!exactRegistry(registry.SUPPORTED_PROVIDERS)) return 'exact ordered built21 registry absent';

    for (const provider of providers) {
      if (!existsSync(join(root, 'tests/fixtures', `${provider}.json`))) return `fixture absent: ${provider}`;
    }

    const api = await import(pathToFileURL(join(root, 'dist/index.js')).href);

    for (const name of ['verify', 'verifyRequest', 'createVerifier']) {
      assert(api[name] instanceof Function);
    }

    assert(api.createVerifier({ provider: 'vercel', secrets: ['synthetic'] }) instanceof Function);
    assert(api.createVerifier({
      provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user',
    }) instanceof Function);
    const cli = await runChild([join(root, 'dist/cli/index.js'), '--help'], { timeoutMs: 5000 });

    if (!passed(cli, [/--public-key-env/, /--expected-user-env/])) return 'built credential CLI absent or failing';
    const types = readFileSync(join(root, 'dist/types.d.ts'), 'utf8');

    if (!types.includes('expectedUserId') || !types.includes('publicKeys')) return 'built fal public types absent';

    return null;
  } catch (error) {
    return `built API not ready: ${error instanceof Error ? error.message : String(error)}`;
  }
}

function artifactHash() {
  const hash = createHash('sha256');

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const target = join(directory, entry.name);

      assert(!entry.isSymbolicLink(), 'Qualification artifacts must not contain links.');

      if (entry.isDirectory()) visit(target);
      else {
        hash.update(target);
        hash.update(readFileSync(target));
      }
    }
  };

  visit(join(root, 'dist'));
  visit(join(root, 'tests/fixtures'));

  for (const filename of ['package.json', 'scripts/package-smoke.mjs', 'scripts/workers-providers.mjs']) {
    hash.update(readFileSync(join(root, filename)));
  }

  return hash.digest('hex');
}

async function controls() {
  assert(exactRegistry(providers));
  assert(!exactRegistry(providers.slice(0, 19)));
  assert(!exactRegistry([...providers.slice(0, 19), 'fal', 'vercel']));
  const success = await runChild(['-e', 'console.log("CONTROL_OK")']);

  assert(passed(success, [/CONTROL_OK/]));
  assert(!passed(success, [/ABSENT_MARKER/]));
  const failure = await runChild(['-e', 'console.log("CONTROL_OK"); process.exit(1)']);
  const blocked = await runChild(['-e', 'process.exit(3)']);
  const timeout = await runChild(['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 100 });
  const overflow = await runChild(['-e', 'console.log("x".repeat(4096))'], { limit: 64 });

  assert(!passed(failure, [/CONTROL_OK/]));
  assert.equal(blocked.exitCode, 3);
  assert(!passed(blocked, []));
  assert(timeout.timedOut);
  assert(!passed(timeout, []));
  assert(overflow.outputLimitExceeded);
  assert(!passed(overflow, []));

  return { status: 'CONTROLS_PASSED', sdkQualificationPerformed: false, children: [success, failure, blocked, timeout, overflow] };
}

function usage() {
  console.log('Usage: node scripts/phase9-runtime-qualification.mjs [--json] [--self-test] [--help]');
  console.log('Exit 0 current Node + workerd qualified, or controls passed; 1 failure; 2 usage; 3 built21 not ready.');
  console.log('Run separately under Node22 and Node24. No other Node major is inferred from this execution.');
}

async function main() {
  const args = process.argv.slice(2);

  if (args.some((arg) => !['--json', '--self-test', '--help', '-h'].includes(arg))
    || new Set(args).size !== args.length) {
    usage();

    return 2;
  }

  if (args.includes('--help') || args.includes('-h')) {
    usage();

    return 0;
  }

  let report;
  let exitCode = 0;

  if (args.includes('--self-test')) report = await controls();
  else {
    const reason = await readiness();

    if (reason !== null) {
      report = { status: 'BLOCKED', reason, scratchAllocated: false };
      exitCode = 3;
    } else {
      const major = Number(process.versions.node.split('.')[0]);
      const npmCli = process.env.npm_execpath ?? join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');

      assert([22, 24].includes(major), 'Current Node must be 22 or 24.');
      assert(existsSync(npmCli), 'npm CLI JavaScript entry missing; invoke through npm or supply npm_execpath.');
      const before = artifactHash();
      const children = [];

      const specifications = [
        {
          script: 'scripts/package-smoke.mjs',
          markers: providers.map((provider) => new RegExp(`PASS: packed ${provider} corpus passes direct APIs, representable Request cases`))
            .concat([/PASS: installed diagnostics, CLI credential arms and packed public types/]),
        },
        {
          script: 'scripts/workers-providers.mjs',
          markers: [/PASS: pure diagnostics run in real workerd/, /PASS: [1-9][0-9]* workerd provider cases across 21 providers\./],
        },
      ];

      for (const spec of specifications) {
        const result = await runChild([join(root, spec.script)], { env: { ...process.env, npm_execpath: npmCli } });

        result.passed = passed(result, spec.markers);
        children.push(result);

        if (!result.passed) break;
      }

      const stableArtifacts = artifactHash() === before;
      const qualified = stableArtifacts && children.length === specifications.length && children.every((child) => child.passed);

      exitCode = qualified ? 0 : 1;
      report = {
        status: qualified ? 'CURRENT_RUNTIME_QUALIFIED' : 'FAILED',
        node: { version: process.versions.node, executable: process.execPath, platform: process.platform, arch: process.arch },
        qualifiedNodeMajors: qualified ? [major] : [],
        unqualifiedNodeMajors: [22, 24].filter((candidate) => candidate !== major || !qualified),
        fullNode22And24Acceptance: false,
        workerdQualified: qualified, stableArtifacts, artifactSha256: before,
        scratchCleanup: 'delegated; abnormal child termination never proves cleanup', children,
      };
    }
  }

  console.log(JSON.stringify(report, null, args.includes('--json') ? 2 : 0));

  return exitCode;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.log(JSON.stringify({ status: 'FAILED', error: error instanceof Error ? error.stack : String(error) }));
  process.exitCode = 1;
}
