/**
 * Generated CLI qualification: every handler must be real, complete,
 * deterministic and semantically typechecked against the packed package and
 * the pinned framework/type trees from this checkout. Run AFTER npm run build:
 *
 *   node scripts/templates-smoke.mjs
 *
 * The script is standalone (no npm_execpath requirement). npm pack/install use
 * offline mode on the local tarball. Repository src and examples are never
 * imported as a verification fallback.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const PROVIDERS = [
  ['stripe', 'STRIPE_WEBHOOK_SECRET'],
  ['github', 'GITHUB_WEBHOOK_SECRET'],
  ['shopify', 'SHOPIFY_WEBHOOK_SECRET'],
  ['standard-webhooks', 'STANDARD_WEBHOOKS_SECRET'],
  ['clerk', 'CLERK_WEBHOOK_SIGNING_SECRET'],
  ['svix', 'SVIX_WEBHOOK_SECRET'],
  ['razorpay', 'RAZORPAY_WEBHOOK_SECRET'],
  ['paddle', 'PADDLE_WEBHOOK_SECRET'],
  ['lemon-squeezy', 'LEMON_SQUEEZY_WEBHOOK_SECRET'],
];

const FRAMEWORKS = ['express', 'nextjs', 'hono', 'cloudflare'];

const BODY_LIMIT = 1237;

function fail(message) {
  throw new Error(message);
}

/* Normalizes child-process failures into a labeled, nonempty diagnostic. */
function invoke(argv, cwd, label) {
  try {
    return execFileSync(process.execPath, argv, { cwd, encoding: 'utf8' });
  } catch (error) {
    const detail = [error.stdout, error.stderr].flatMap((part) => (String(part).trim().length > 0 ? [String(part)] : [])).join('\n');
    const enriched = new Error(`${label} failed with status ${error.status}${detail.length > 0 ? `:\n${detail}` : ''}`);

    enriched.exitStatus = error.status;
    throw enriched;
  }
}

function requireBuildArtifacts() {
  if (!existsSync(join(root, 'dist', 'index.js')) || !existsSync(join(root, 'dist', 'cli', 'index.js'))) {
    fail('Built package artifacts are missing; run npm run build before node scripts/templates-smoke.mjs.');
  }

  if (!existsSync(join(root, 'node_modules', 'typescript', 'lib', 'tsc.js'))) {
    fail('The pinned TypeScript toolchain is missing from this checkout; restore the prepared dependency snapshot.');
  }
}

function locateNpmCli() {
  const candidates = [];

  if (process.env.npm_execpath) candidates.push(process.env.npm_execpath);

  candidates.push(
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );

  const found = candidates.find((candidate) => existsSync(candidate));

  if (!found) {
    fail('npm CLI is unavailable: neither npm_execpath nor the node install tree provide npm-cli.js.');
  }

  return found;
}

function installedCliPath(consumerRoot) {
  const cli = join(consumerRoot, 'node_modules', 'hooklatch', 'dist', 'cli', 'index.js');

  if (!existsSync(cli)) {
    fail('The installed packed package does not expose dist/cli/index.js; inspect the npm tarball contents.');
  }

  return cli;
}

function linkFixedDependency(localName, consumerRoot) {
  const target = resolve(join(root, 'node_modules', localName));

  if (!existsSync(target)) {
    fail(`Pinned dependency tree is missing from this checkout: ${localName} (the repository node_modules stays read-only).`);
  }

  const linkPath = join(consumerRoot, 'node_modules', localName);

  mkdirSync(dirname(linkPath), { recursive: true });
  symlinkSync(target, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
}

function expectedFileName(provider, framework) {
  if (framework === 'nextjs') return 'route.ts';

  if (framework === 'cloudflare') return `${provider}.cloudflare.ts`;

  return `${provider}.${framework}.ts`;
}

function expectContentMarkers(provider, framework, secretEnv, content) {
  for (const marker of [`provider: '${provider}'`, `maxBodyBytes: ${BODY_LIMIT}`]) {
    if (!content.includes(marker)) {
      fail(`Generated ${framework} handler for ${provider} is missing: ${marker}`);
    }
  }

  if (framework === 'cloudflare') {
    for (const marker of [`from 'hooklatch/cloudflare'`, `${secretEnv}: string`, `env.${secretEnv}`]) {
      if (!content.includes(marker)) {
        fail(`Generated cloudflare handler for ${provider} is missing: ${marker}`);
      }
    }

    return;
  }

  const sharedMarkers = [`from 'hooklatch/${framework}'`, `process.env.${secretEnv}!`];

  if (framework === 'hono') sharedMarkers.push(`from 'hono'`);

  for (const marker of sharedMarkers) {
    if (!content.includes(marker)) {
      fail(`Generated ${framework} handler for ${provider} is missing: ${marker}`);
    }
  }
}

/* Every combination directory must hold exactly the generated target file. */
function assertCompletedDir(directory, fileName, label) {
  const entries = readdirSync(directory);

  if (entries.length !== 1 || entries[0] !== fileName) {
    fail(`${label} produced [${entries.join(', ')}] instead of exactly [${fileName}].`);
  }
}

function generationArgv(cli, provider, framework, secretEnv, relativeOut) {
  return [
    cli,
    'init', 'webhook',
    '--provider', provider,
    '--framework', framework,
    '--out', relativeOut,
    '--secret-env', secretEnv,
    '--body-limit', String(BODY_LIMIT),
  ];
}

/* Compiler options mirror the repo's own checker (skipLibCheck parity). */
function typecheckGeneratedFile(file, consumerRoot, label) {
  const argv = [
    join(root, 'node_modules', 'typescript', 'lib', 'tsc.js'),
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

  invoke(argv, consumerRoot, `semantic typecheck of ${label}`);
}

async function main() {
  requireBuildArtifacts();

  const npmCli = locateNpmCli();
  const tempRoot = await mkdtemp(join(tmpdir(), 'hooklatch-templates-'));
  const consumerRoot = join(tempRoot, 'consumer');

  try {
    mkdirSync(consumerRoot);

    // The consumer pins an ESM module system; the tarball below carries the
    // entire hooklatch surface, so no repository code is imported anywhere.
    const consumerManifest = {
      name: 'hooklatch-template-consumer',
      version: '0.0.0',
      private: true,
      type: 'module',
    };

    writeFileSync(join(consumerRoot, 'package.json'), `${JSON.stringify(consumerManifest, null, 2)}\n`);

    const packed = JSON.parse(invoke([npmCli, 'pack', '--json', '--offline', '--ignore-scripts', '--pack-destination', tempRoot], root, 'npm pack'));
    const tarballPath = join(tempRoot, packed[0].filename);

    if (!existsSync(tarballPath)) fail('npm pack did not produce the expected archive.');

    invoke(
      [npmCli, 'install', tarballPath, '--no-save', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'],
      consumerRoot,
      'offline npm install of the packed package',
    );

    const cli = installedCliPath(consumerRoot);

    for (const name of ['express', 'hono', '@types/express', '@types/node']) linkFixedDependency(name, consumerRoot);

    for (const [provider, secretEnv] of PROVIDERS) {
      for (const framework of FRAMEWORKS) {
        const label = `${provider}/${framework}`;
        const relativeOut = join('gen', provider, framework);
        const relativeOutCopy = join('gen2', provider, framework);
        const firstDir = join(consumerRoot, relativeOut);
        const secondDir = join(consumerRoot, relativeOutCopy);

        const generationLabel = `hooklatch init webhook (${label})`;

        invoke(generationArgv(cli, provider, framework, secretEnv, relativeOut), consumerRoot, generationLabel);

        assertCompletedDir(firstDir, expectedFileName(provider, framework), `Generation (${label})`);

        const firstPath = join(firstDir, expectedFileName(provider, framework));
        const content = readFileSync(firstPath, 'utf8');

        expectContentMarkers(provider, framework, secretEnv, content);

        invoke(generationArgv(cli, provider, framework, secretEnv, relativeOutCopy), consumerRoot, `deterministic regeneration (${label})`);

        assertCompletedDir(secondDir, expectedFileName(provider, framework), `Regeneration (${label})`);

        if (!readFileSync(firstPath).equals(readFileSync(join(secondDir, expectedFileName(provider, framework))))) {
          fail(`Regenerated bytes differ between runs for ${label}.`);
        }

        // Independent compiler program: one NodeNext child per generated file.
        typecheckGeneratedFile(firstPath, consumerRoot, label);
      }
    }

    // The installed CLI must reject an unimplemented provider and write nothing.
    let invalidStatus;

    try {
      invoke([cli, 'init', 'webhook', '--provider', 'does-not-exist', '--framework', 'express', '--out', 'gen-invalid'], consumerRoot, 'invalid provider probe');

      invalidStatus = -1;
    } catch (error) {
      invalidStatus = error.exitStatus !== undefined ? error.exitStatus : -1;
    }

    if (invalidStatus !== 2) fail(`Installed CLI accepted an unknown provider (status ${invalidStatus}).`);

    if (existsSync(join(consumerRoot, 'gen-invalid'))) fail('Installed CLI wrote output for a rejected provider.');

    console.log(`PASS: ${PROVIDERS.length * FRAMEWORKS.length} generated handlers are complete, deterministic and semantically typechecked.`);
  } finally {
    const checked = resolve(tempRoot);

    assert(checked.startsWith(resolve(tmpdir()) + sep) && checked !== resolve(tmpdir()));
    rmSync(checked, { recursive: true, force: true });
    assert(!existsSync(checked), 'Checked temp root must be removed on every outcome.');
  }
}

try {
  await main();
} catch (error) {
  console.error(`FAIL: templates smoke (${error.message})`);
  process.exitCode = 1;
}
