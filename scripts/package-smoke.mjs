import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = await mkdtemp(join(tmpdir(), 'hooklatch-package-'));
const npmCli = process.env.npm_execpath;
assert(npmCli, 'Run this check via npm run test:package.');
const npm = (args, cwd) => execFileSync(process.execPath, [npmCli, ...args], {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
});
try {
  const [pack] = JSON.parse(npm(['pack', '--json', '--pack-destination', tempRoot], root));
  assert(pack.files.every(({ path }) => path.startsWith('dist/') || ['package.json', 'README.md', 'LICENSE'].includes(path)), 'Unexpected files in npm tarball.');
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0);
  npm(['install', join(tempRoot, pack.filename), '--omit=dev', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], tempRoot);
  // A new process outside the workspace proves core loads without dev/framework deps.
  const check = `
    import assert from 'node:assert/strict';
    import { verify, verifyRequest, createVerifier, HooklatchError } from 'hooklatch';
    const opts = { provider: 'github', secrets: ["It's a Secret to Everybody"] };
    const headers = { 'x-hub-signature-256': 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17' };
    const input = { rawBody: new TextEncoder().encode('Hello, World!'), headers };
    assert.equal((await verify(input, opts)).ok, true);
    assert.equal((await createVerifier(opts)(input)).ok, true);
    assert.equal((await verifyRequest(new Request('https://example.test', { method: 'POST', headers, body: 'Hello, World!' }), opts)).ok, true);
    assert.equal((await verify({ ...input, rawBody: new TextEncoder().encode('tampered') }, opts)).ok, false);
    assert.equal(typeof HooklatchError, 'function');
    for (const name of ['express', 'hono']) {
      await assert.rejects(import(name), { code: 'ERR_MODULE_NOT_FOUND' });
    }
    console.log('PASS: packed core imports and verifies offline without optional frameworks.');
  `;
  process.stdout.write(execFileSync(process.execPath, ['--input-type=module', '-e', check], { cwd: tempRoot, encoding: 'utf8' }));
} finally {
  const checked = resolve(tempRoot);
  assert(checked.startsWith(resolve(tmpdir()) + sep) && checked !== resolve(tmpdir()));
  await rm(checked, { recursive: true, force: true });
}
