import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = {};
for (const provider of ['stripe', 'github', 'shopify', 'standard-webhooks']) {
  const file = JSON.parse(await readFile(resolve(root, 'tests/fixtures', `${provider}.json`), 'utf8'));
  const fixture = file.cases.find((entry) => entry.expected.ok && entry.request.bodyBase64);
  assert(fixture, `Missing positive runtime fixture for ${provider}.`);
  fixtures[provider] = fixture;
}
const bundled = await build({
  stdin: { contents: `
    import { verifyRequest } from './src/index.ts';
    const fixtures = ${JSON.stringify(fixtures)};
    export default { async fetch(request) {
      const provider = new URL(request.url).pathname.slice(1);
      const fixture = fixtures[provider];
      const result = await verifyRequest(request, {
        provider, secrets: fixture.options.secrets,
        toleranceSeconds: fixture.options.toleranceSeconds ?? 300,
        now: () => fixture.options.now,
      });
      return Response.json(result.ok
        ? { ok: true, provider: result.provider, bytes: Array.from(result.rawBody) }
        : { ok: false, reason: result.reason });
    } };
  `, resolveDir: root, sourcefile: 'all-providers-worker.js' },
  bundle: true, write: false, platform: 'neutral', format: 'esm', target: 'es2022',
  conditions: ['workerd', 'worker', 'browser'],
});
const runtime = new Miniflare({ modules: true, script: bundled.outputFiles[0].text,
  compatibilityDate: '2026-08-06', compatibilityFlags: [] });
try {
  for (const [provider, fixture] of Object.entries(fixtures)) {
    const headers = new Headers();
    for (const [name, value] of Object.entries(fixture.request.headers)) {
      for (const item of typeof value === 'string' ? [value] : value) headers.append(name, item);
    }
    const bytes = Buffer.from(fixture.request.bodyBase64, 'base64');
    const send = (body) => runtime.dispatchFetch(`https://example.test/${provider}`, { method: 'POST', headers, body });
    const valid = await (await send(bytes)).json();
    assert.equal(valid.ok, true, `${provider} failed in workerd.`);
    assert.equal(valid.provider, provider);
    assert.deepEqual(valid.bytes, [...bytes]);
    const tampered = await (await send(Buffer.concat([bytes, Buffer.from('!')]))).json();
    assert.equal(tampered.ok, false, `${provider} accepted tampering in workerd.`);
    assert.equal(tampered.reason, 'invalid-signature');
    console.log(`PASS: ${provider} verifies exact bytes and rejects tampering in workerd.`);
  }
} finally { await runtime.dispose(); }
