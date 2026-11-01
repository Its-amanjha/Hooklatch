#!/usr/bin/env node
/**
 * Phase 13 onboarding controls (Codebuff DeepSeek owner).
 *
 * HARness-only discriminating controls for scripts/phase13/onboarding-smoke.mjs.
 * Nothing here is product, install or release evidence: every control either
 * rejects a deliberately broken input, proves a bounded-child observation, or
 * proves that a harness verdict cannot become `ready` without confirmation.
 *
 * Covered defects:
 *   - no arguments / a missing or non-gzip artifact / a bad guide must stop the
 *     smoke before it creates any OS-temp consumer (BLOCKED 3 or FAILED 1);
 *   - the guide parity rules reject a missing, duplicate, unknown, wrongly
 *     fenced or rewritten example, and accept the exact frozen guide;
 *   - an altered ESM or CommonJS example document can never validate;
 *   - a missing-peer error, an unrelated crash and a missing package are
 *     classified differently, so an unrelated crash is never accepted;
 *   - a created or changed file anywhere in a consumer tree is detected;
 *   - a real non-zero child and a real hung child are recorded as such, bounded
 *     and close-confirmed;
 *   - `--results` cannot overwrite an existing file, a frozen input, the
 *     session claim, or a path under a linked ancestor;
 *   - cleanup uncertainty and integrity loss each force a failing verdict;
 *   - no smoke workspace is left behind.
 *
 * Usage:
 *   node scripts/phase13/onboarding-controls.mjs [--results FILE]
 *   node scripts/phase13/onboarding-controls.mjs --help
 *
 * Exit: 0 every control passed, 1 a control failed, 2 usage.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { UsageError, validateResultsDestination } from '../phase11/package-contract.mjs';
import { createHealthLedger, runChild } from '../phase11/mixed-format-runtime.mjs';

import {
  EXIT, FROZEN_EXAMPLES, REPO_ROOT, classifyMissingPackage, classifyPeerFailure, compareTreeSnapshots,
  loadExamplesFile, parseGuide, renderGuide, resolveOnboardingExit, snapshotTree,
  validateExamplesDocument,
} from './onboarding-smoke.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SMOKE = path.join(SCRIPT_DIR, 'onboarding-smoke.mjs');
const SMOKE_TEMP_PREFIX = 'hooklatch-phase13-onboarding-';
const SCRATCH_PREFIX = 'hooklatch-phase13-controls-';
const OUTPUT_LIMIT = 256 * 1024;
const CHILD_TIMEOUT_MS = 120_000;

const USAGE = [
  'Phase 13 onboarding controls (harness-only)',
  '',
  'Usage:',
  '  node scripts/phase13/onboarding-controls.mjs [--results FILE]',
  '  node scripts/phase13/onboarding-controls.mjs --help',
  '',
  'Options:',
  '  --results FILE  Write the JSON control report to a new file only.',
  '  --help, -h      Show this help.',
  '',
  'Exit: 0 every control passed, 1 a control failed, 2 usage.',
  '',
  'These controls never install a package and never modify this checkout; they',
  'only spawn the smoke harness with deliberately broken inputs and exercise its',
  'pure validators.',
].join('\n');

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function sha256File(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

function parseArguments(argv) {
  const options = { help: false, results: null };
  let seenResults = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }

    if (argument === '--results') {
      if (seenResults) throw new UsageError('duplicate option: --results');

      seenResults = true;

      const value = argv[index + 1];

      if (value === undefined || value.startsWith('--')) throw new UsageError('--results requires a value');

      options.results = value;
      index += 1;
      continue;
    }

    throw new UsageError(`unknown argument: ${argument}`);
  }

  return options;
}

function smokeTempEntries() {
  try {
    return readdirSync(os.tmpdir()).filter((name) => name.startsWith(SMOKE_TEMP_PREFIX)).sort();
  } catch {
    return [];
  }
}

function sameStrings(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }

  return true;
}

async function runSmoke(args, ledger) {
  return await runChild(process.execPath, [SMOKE, ...args], {
    cwd: REPO_ROOT, env: process.env, ledger, timeoutMs: CHILD_TIMEOUT_MS, limit: OUTPUT_LIMIT,
  });
}

async function runSmokeBlockedCase({ args, expectedExit, ledger, label }) {
  const before = smokeTempEntries();
  const run = await runSmoke(args, ledger);
  const after = smokeTempEntries();
  const createdTemp = !sameStrings(before, after);
  const passed = run.exitCode === expectedExit && run.signal === null && !run.timedOut && run.closeConfirmed && !createdTemp;

  return {
    passed,
    detail: {
      label,
      expectedExit,
      exitCode: run.exitCode,
      timedOut: run.timedOut,
      closeConfirmed: run.closeConfirmed,
      createdTempDirectory: createdTemp,
      stderrHead: run.stderr.split(/\r?\n/).filter((line) => line.trim().length > 0).slice(-1)[0] ?? '',
    },
  };
}

function writeGuide(file, examples) {
  writeFileSync(file, renderGuide(examples), 'utf8');
}

async function runControls() {
  const controls = [];

  const record = (id, passed, detail) => {
    controls.push({ id, passed: passed === true, detail });
  };

  const recordControl = (id, run) => {
    try {
      const detail = run();

      record(id, detail.passed, detail.detail);
    } catch (error) {
      record(id, false, { error: messageOf(error) });
    }
  };

  const recordAsync = async (id, run) => {
    try {
      const detail = await run();

      record(id, detail.passed, detail.detail);
    } catch (error) {
      record(id, false, { error: messageOf(error) });
    }
  };

  const scratch = mkdtempSync(path.join(os.tmpdir(), SCRATCH_PREFIX));
  const ledger = createHealthLedger();
  const baselineTemp = smokeTempEntries();

  try {
    const absentTarball = path.join(scratch, 'absent', 'hooklatch-0.0.0.tgz');
    const notATarball = path.join(scratch, 'not-a-tarball.tgz');

    writeFileSync(notATarball, 'this is not a gzip archive\n', 'utf8');
    mkdirSync(path.dirname(absentTarball), { recursive: true });

    const goodGuide = path.join(scratch, 'guide-good.md');
    const missingIdGuide = path.join(scratch, 'guide-missing-id.md');

    writeGuide(goodGuide, FROZEN_EXAMPLES);
    writeFileSync(
      missingIdGuide,
      renderGuide(FROZEN_EXAMPLES.slice(0, 3)),
      'utf8',
    );

    // --- CLI contract of the smoke harness ------------------------------
    await recordAsync('smoke-help-exits-zero', async () => {
      const run = await runSmoke(['--help'], ledger);

      return {
        passed: run.exitCode === EXIT.READY && run.stdout.includes('Usage:'),
        detail: { exitCode: run.exitCode, usage: run.stdout.includes('Usage:') },
      };
    });

    await recordAsync('smoke-unknown-option-usage', async () => {
      const run = await runSmoke(['--bogus'], ledger);

      return { passed: run.exitCode === EXIT.USAGE, detail: { exitCode: run.exitCode } };
    });

    await recordAsync('smoke-duplicate-option-usage', async () => {
      const run = await runSmoke(['--tarball', notATarball, '--tarball', notATarball], ledger);

      return { passed: run.exitCode === EXIT.USAGE, detail: { exitCode: run.exitCode } };
    });

    await recordAsync('smoke-missing-option-value-usage', async () => {
      const run = await runSmoke(['--tarball'], ledger);

      return { passed: run.exitCode === EXIT.USAGE, detail: { exitCode: run.exitCode } };
    });

    await recordAsync('smoke-self-test-passes', async () => {
      const run = await runSmoke(['--self-test'], ledger);
      const report = run.stdout.trim().length > 0 ? JSON.parse(run.stdout) : {};

      return {
        passed: run.exitCode === EXIT.READY && report.status === 'CONTROLS-PASS',
        detail: { exitCode: run.exitCode, status: report.status ?? null },
      };
    });

    // --- blocked before any temporary consumer --------------------------
    await recordAsync('no-args-blocked-before-temp', async () => {
      const outcome = await runSmokeBlockedCase({ args: [], expectedExit: EXIT.BLOCKED, ledger, label: 'no arguments' });

      return { passed: outcome.passed, detail: outcome.detail };
    });

    await recordAsync('missing-tarball-blocked-before-temp', async () => {
      const outcome = await runSmokeBlockedCase({ args: ['--tarball', absentTarball], expectedExit: EXIT.BLOCKED, ledger, label: 'absent artifact' });

      return { passed: outcome.passed, detail: outcome.detail };
    });

    await recordAsync('non-gzip-tarball-blocked-before-temp', async () => {
      const outcome = await runSmokeBlockedCase({ args: ['--tarball', notATarball], expectedExit: EXIT.BLOCKED, ledger, label: 'not a gzip archive' });

      return { passed: outcome.passed, detail: outcome.detail };
    });

    await recordAsync('bad-guide-fails-before-artifact-and-temp', async () => {
      const outcome = await runSmokeBlockedCase({
        args: ['--tarball', absentTarball, '--guide', missingIdGuide], expectedExit: EXIT.FAILED, ledger, label: 'guide missing one id',
      });

      return { passed: outcome.passed, detail: outcome.detail };
    });

    await recordAsync('good-guide-accepted-then-artifact-blocks', async () => {
      const outcome = await runSmokeBlockedCase({
        args: ['--tarball', notATarball, '--guide', goodGuide], expectedExit: EXIT.BLOCKED, ledger, label: 'good guide, bad artifact',
      });

      return { passed: outcome.passed, detail: outcome.detail };
    });

    // --- frozen guide and example validators ----------------------------
    recordControl('good-guide-parity-accepted', () => {
      const parsed = parseGuide(renderGuide());

      return { passed: parsed.ok && parsed.matched.length === FROZEN_EXAMPLES.length, detail: { problems: parsed.problems } };
    });

    const guideDefects = [
      { id: 'guide-missing-id', text: renderGuide(FROZEN_EXAMPLES.slice(0, 3)), prefix: 'guide-missing-id:' },
      { id: 'guide-duplicate-id', text: `${renderGuide()}\n\n${renderGuide([FROZEN_EXAMPLES[2]])}`, prefix: 'guide-duplicate-id:' },
      {
        id: 'guide-wrong-language',
        text: renderGuide().replace('```js\nimport { createHmac }', '```ts\nimport { createHmac }'),
        prefix: 'guide-fence-language:',
      },
      {
        id: 'guide-wrong-code',
        text: renderGuide().replace("console.log('verified');", "console.log('passed');"),
        prefix: 'guide-fence-code:',
      },
      {
        id: 'guide-unknown-id',
        text: `${renderGuide()}\n\n<!-- hooklatch:example:extra -->\n\`\`\`js\nconsole.log('x');\n\`\`\``,
        prefix: 'guide-unknown-id:',
      },
      {
        id: 'guide-missing-fence',
        text: renderGuide().replace('<!-- hooklatch:example:cli-help -->\n```bash\nnpx --no-install hooklatch --help\n```', '<!-- hooklatch:example:cli-help -->'),
        prefix: 'guide-fence-missing:',
      },
    ];

    for (const defect of guideDefects) {
      const parsed = parseGuide(defect.text);

      record(defect.id, !parsed.ok && parsed.problems.some((problem) => problem.startsWith(defect.prefix)),
        { problems: parsed.problems });
    }

    recordControl('altered-esm-example-never-validates', () => {
      const document = { examples: FROZEN_EXAMPLES.map((example) => ({ ...example })) };

      document.examples[0].code = `${document.examples[0].code}\nconsole.log('extra');`;

      const validated = validateExamplesDocument(document);

      return { passed: !validated.ok && validated.problems.includes('example-code:core-esm'), detail: { problems: validated.problems } };
    });

    recordControl('altered-commonjs-example-never-validates', () => {
      const document = { examples: FROZEN_EXAMPLES.map((example) => ({ ...example })) };

      document.examples[1].code = document.examples[1].code.replace('main().catch', 'main().then');

      const validated = validateExamplesDocument(document);

      return { passed: !validated.ok && validated.problems.includes('example-code:core-commonjs'), detail: { problems: validated.problems } };
    });

    recordControl('frozen-examples-file-matches-this-runner', () => {
      const loaded = loadExamplesFile();

      return { passed: loaded.ok, detail: { problems: loaded.problems } };
    });

    // --- discriminating classifiers -------------------------------------
    recordControl('peer-classifier-rejects-unrelated-crash', () => {
      const documented = classifyPeerFailure('hooklatch/express', 'ERR_MODULE_NOT_FOUND', "Cannot find package 'express' imported from x");
      const crash = classifyPeerFailure('hooklatch/express', 'TypeError', 'createWebhookMiddleware is not a function');
      const otherPeer = classifyPeerFailure('hooklatch/hono', 'ERR_MODULE_NOT_FOUND', "Cannot find package 'express'");
      const noCode = classifyPeerFailure('hooklatch/express', null, "Cannot find package 'express'");

      return {
        passed: documented === 'missing-peer' && crash === 'unexpected-failure'
          && otherPeer === 'unexpected-failure' && noCode === 'unexpected-failure',
        detail: { documented, crash, otherPeer, noCode },
      };
    });

    recordControl('missing-package-classifier-rejects-other-errors', () => {
      const documented = classifyMissingPackage('ERR_MODULE_NOT_FOUND', "Cannot find package 'hooklatch' imported from x");
      const otherPackage = classifyMissingPackage('ERR_MODULE_NOT_FOUND', "Cannot find package 'left-pad'");
      const runtimeCrash = classifyMissingPackage('TypeError', "Cannot find package 'hooklatch'");

      return {
        passed: documented === 'missing-package' && otherPackage === 'unexpected-failure'
          && runtimeCrash === 'unexpected-failure',
        detail: { documented, otherPackage, runtimeCrash },
      };
    });

    // --- real child observations ----------------------------------------
    await recordAsync('real-nonzero-child-observed', async () => {
      const run = await runChild(process.execPath, ['-e', 'process.exit(7)'], {
        cwd: scratch, env: process.env, ledger, timeoutMs: 30_000, limit: OUTPUT_LIMIT,
      });

      return {
        passed: run.exitCode === 7 && run.ok === false && run.timedOut === false
          && run.signal === null && run.closeConfirmed === true,
        detail: { exitCode: run.exitCode, timedOut: run.timedOut, ok: run.ok, closeConfirmed: run.closeConfirmed },
      };
    });

    await recordAsync('real-hung-child-bounded-and-confirmed', async () => {
      const run = await runChild(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
        cwd: scratch, env: process.env, ledger, timeoutMs: 600, limit: OUTPUT_LIMIT,
      });

      return {
        passed: run.timedOut === true && run.ok === false && run.closeConfirmed === true,
        detail: { timedOut: run.timedOut, ok: run.ok, closeConfirmed: run.closeConfirmed, killAttempted: run.killAttempted },
      };
    });

    // --- consumer write detection ---------------------------------------
    recordControl('tree-snapshot-detects-created-file', () => {
      const tree = path.join(scratch, 'tree');
      const created = path.join(tree, 'hooklatch', 'github.express.ts');

      mkdirSync(path.dirname(created), { recursive: true });

      const before = snapshotTree(tree);

      writeFileSync(created, 'export {};\n', 'utf8');

      const problems = compareTreeSnapshots(before, snapshotTree(tree));

      rmSync(tree, { recursive: true, force: true });

      return { passed: problems.includes('tree-added:hooklatch/github.express.ts'), detail: { problems } };
    });

    // --- results destination guards -------------------------------------
    await recordAsync('results-cannot-overwrite-existing-file', async () => {
      const existing = path.join(scratch, 'existing-results.json');

      writeFileSync(existing, '{"existing":true}\n', 'utf8');

      const hashBefore = sha256File(existing);
      const run = await runSmoke(['--tarball', notATarball, '--results', existing], ledger);
      const unchanged = sha256File(existing) === hashBefore;

      return {
        passed: run.exitCode === EXIT.USAGE && unchanged,
        detail: { exitCode: run.exitCode, unchanged },
      };
    });

    await recordAsync('results-cannot-overwrite-frozen-input', async () => {
      const input = path.join(REPO_ROOT, 'scripts', 'phase13', 'onboarding-examples.json');
      const hashBefore = sha256File(input);
      const run = await runSmoke(['--tarball', notATarball, '--results', input], ledger);
      const unchanged = sha256File(input) === hashBefore;

      return {
        passed: run.exitCode === EXIT.USAGE && unchanged,
        detail: { exitCode: run.exitCode, unchanged },
      };
    });

    await recordAsync('results-cannot-overwrite-claim', async () => {
      const claim = path.join(REPO_ROOT, 'notes', 'phase-13', 'deepseek-codebuff', 'session.json');
      const hashBefore = existsSync(claim) ? sha256File(claim) : null;
      const run = await runSmoke(['--tarball', notATarball, '--results', claim], ledger);
      const unchanged = hashBefore === null ? !existsSync(claim) : sha256File(claim) === hashBefore;

      return {
        passed: run.exitCode === EXIT.USAGE && unchanged,
        detail: { exitCode: run.exitCode, claimPresent: hashBefore !== null, unchanged },
      };
    });

    await recordAsync('results-reject-linked-ancestor', async () => {
      const real = path.join(scratch, 'real-target');
      const link = path.join(scratch, 'linked-ancestor');

      mkdirSync(real, { recursive: true });
      symlinkSync(real, link, process.platform === 'win32' ? 'junction' : 'dir');

      const destination = path.join(link, 'out.json');
      const run = await runSmoke(['--tarball', notATarball, '--results', destination], ledger);
      const notWritten = !existsSync(destination) && !existsSync(path.join(real, 'out.json'));

      return {
        passed: run.exitCode === EXIT.USAGE && notWritten,
        detail: { exitCode: run.exitCode, notWritten },
      };
    });

    recordControl('existing-helper-matches-guard-expectations', () => {
      const existing = path.join(scratch, 'guard-existing.json');
      const guardLink = path.join(scratch, 'guard-link');

      writeFileSync(existing, '{}\n', 'utf8');
      mkdirSync(path.join(scratch, 'guard-target'), { recursive: true });
      symlinkSync(path.join(scratch, 'guard-target'), guardLink, process.platform === 'win32' ? 'junction' : 'dir');

      let existingRejected = false;
      let linkedRejected = false;

      try {
        validateResultsDestination(existing, REPO_ROOT);
      } catch (error) {
        existingRejected = error instanceof UsageError;
      }

      try {
        validateResultsDestination(path.join(guardLink, 'other.json'), REPO_ROOT);
      } catch (error) {
        linkedRejected = error instanceof UsageError;
      }

      return {
        passed: existingRejected && linkedRejected,
        detail: { existingRejected, linkedRejected },
      };
    });

    // --- verdict guards -------------------------------------------------
    recordControl('cleanup-or-integrity-loss-blocks-ready', () => {
      const passing = {
        status: 'ready',
        checks: [
          { id: 'install', status: 'passed' },
          { id: 'guide-parity', status: 'not-run', required: false },
        ],
        cleanup: { confirmed: true },
        integrity: { artifactUnchanged: true, checkoutUnchanged: true },
      };

      const mapping = {
        clean: resolveOnboardingExit(passing),
        cleanupUnconfirmed: resolveOnboardingExit({ ...passing, cleanup: { confirmed: false } }),
        artifactChanged: resolveOnboardingExit({ ...passing, integrity: { artifactUnchanged: false, checkoutUnchanged: true } }),
        checkoutChanged: resolveOnboardingExit({ ...passing, integrity: { artifactUnchanged: true, checkoutUnchanged: false } }),
        requiredNotRun: resolveOnboardingExit({ ...passing, checks: [{ id: 'install', status: 'not-run' }] }),
        blocked: resolveOnboardingExit({ ...passing, status: 'blocked' }),
      };

      return {
        passed: mapping.clean === EXIT.READY
          && mapping.cleanupUnconfirmed === EXIT.FAILED
          && mapping.artifactChanged === EXIT.FAILED
          && mapping.checkoutChanged === EXIT.FAILED
          && mapping.requiredNotRun === EXIT.FAILED
          && mapping.blocked === EXIT.BLOCKED,
        detail: mapping,
      };
    });

    // --- no leftovers ---------------------------------------------------
    recordControl('no-smoke-temp-left-behind', () => {
      const after = smokeTempEntries();

      return { passed: sameStrings(baselineTemp, after), detail: { baseline: baselineTemp.length, after: after.length } };
    });
  } finally {
    const insideTemp = !path.relative(path.resolve(os.tmpdir()), path.resolve(scratch)).startsWith('..');

    if (insideTemp && existsSync(scratch)) rmSync(scratch, { recursive: true, force: true });
  }

  const failed = controls.filter((control) => control.passed !== true);

  return {
    schemaVersion: 1,
    phase: '13 onboarding controls',
    owner: 'deepseek-codebuff',
    script: 'scripts/phase13/onboarding-controls.mjs',
    controlsOnly: true,
    note: 'Harness-only controls. A pass here proves the smoke harness rejects broken inputs; it is never product, install or release evidence.',
    status: failed.length === 0 ? 'CONTROLS-PASS' : 'CONTROLS-FAILED',
    total: controls.length,
    failed: failed.length,
    hostRuntime: { version: process.version, platform: process.platform, arch: process.arch },
    controls,
  };
}

export async function main(argv = process.argv.slice(2)) {
  let options;

  try {
    options = parseArguments(argv);
  } catch (error) {
    console.error(`Usage error: ${messageOf(error)}\n\n${USAGE}`);

    return EXIT.USAGE;
  }

  if (options.help) {
    console.log(USAGE);

    return EXIT.READY;
  }

  if (options.results !== null) {
    try {
      validateResultsDestination(path.resolve(options.results), REPO_ROOT);
    } catch (error) {
      if (!(error instanceof UsageError)) throw error;

      console.error(`Results destination rejected: ${error.message}`);

      return EXIT.USAGE;
    }
  }

  const report = await runControls();

  if (options.results !== null) {
    try {
      const destination = path.resolve(options.results);

      mkdirSync(path.dirname(destination), { recursive: true });
      writeFileSync(destination, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
      report.resultsWritten = true;
    } catch (error) {
      console.error(`Results were not written: ${messageOf(error)}`);

      return EXIT.FAILED;
    }
  }

  console.log(JSON.stringify(report, null, 2));

  return report.status === 'CONTROLS-PASS' ? EXIT.READY : EXIT.FAILED;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = await main();
}
