import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

export const FRAMEWORKS = ['express', 'hono', 'nextjs', 'cloudflare'];
export const STATES = ['valid', 'tamper', 'overflow'];

export function assertResponse(status, response, calls, entry, state) {
  const expected = state === 'valid' ? 200 : state === 'overflow' ? 413 : 400;

  if (status !== expected) throw new Error(`status ${entry.provider}/${state}: ${status} != ${expected}`);

  if (calls !== (state === 'valid' ? 1 : 0)) throw new Error('handler call count');

  if (state === 'valid') {
    const actual = JSON.parse(response);

    if (JSON.stringify(actual.bytes) !== JSON.stringify(entry.body)) throw new Error('visible body bytes changed');

    if (JSON.stringify(actual.identity) !== JSON.stringify(entry.identity)) throw new Error('identity changed');
  } else {
    const message = expected === 413 ? 'Payload Too Large' : 'Bad Request';

    if (response !== message) throw new Error('non-generic error response');
  }
}

export function inputBody(entry, state) {
  const body = new Uint8Array(state === 'overflow' ? 129 : entry.body);

  if (state === 'tamper') body[0] ^= 1;

  return body;
}

export function materializeOptions(entry) {
  return entry.provider === 'fal'
    ? { ...entry.options, publicKeys: entry.options.publicKeys.map((key) => new Uint8Array(key)), now: () => entry.now }
    : { ...entry.options, now: () => entry.now };
}

export async function runFrameworkMatrix(entries, format) {
  const req = createRequire(import.meta.url);
  const load = (name) => format === 'require' ? Promise.resolve(req(name)) : import(name);
  const expressPackage = await load('express');
  const express = expressPackage.default ?? expressPackage;
  const { Hono } = await load('hono');
  const modules = {};
  const tuples = [];

  for (const framework of FRAMEWORKS) modules[framework] = await load(`hooklatch/${framework}`);

  for (const framework of FRAMEWORKS) {
    for (const entry of entries) {
      for (const state of STATES) {
        const options = { ...materializeOptions(entry), maxBodyBytes: 128 };
        const body = inputBody(entry, state);
        let calls = 0;

        const success = (result) => {
          calls++;

          return { bytes: [...result.rawBody], identity: result.identity };
        };

        let response;
        let server;

        try {
          if (framework === 'express') {
            const app = express();

            app.post('/hook', modules.express.createWebhookMiddleware(options), (request, res) => res.json(success(request.webhook)));
            server = createServer(app);
            await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
            response = await fetch(`http://127.0.0.1:${server.address().port}/hook`, { method: 'POST', headers: entry.headers, body });
          } else if (framework === 'hono') {
            const app = new Hono();

            app.post('/hook', modules.hono.createWebhookMiddleware(options), (context) => context.json(success(context.get('webhook'))));
            response = await app.fetch(new Request('https://synthetic.invalid/hook', { method: 'POST', headers: entry.headers, body }));
          } else if (framework === 'nextjs') {
            const POST = modules.nextjs.createWebhookHandler({ ...options, handler: (_request, result) => Response.json(success(result)) });

            response = await POST(new Request('https://synthetic.invalid/hook', { method: 'POST', headers: entry.headers, body }));
          } else {
            const handler = modules.cloudflare.createWebhookHandler({ options: () => options, handler: (_request, _env, _ctx, result) => Response.json(success(result)) });

            response = await handler(new Request('https://synthetic.invalid/hook', { method: 'POST', headers: entry.headers, body }), {}, {});
          }

          assertResponse(response.status, await response.text(), calls, entry, state);
          tuples.push({ framework, format, provider: entry.provider, state });
        } finally {
          if (server !== undefined) {
            server.closeAllConnections();
            await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
          }
        }
      }
    }
  }

  return tuples;
}

async function main() {
  const entries = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const format = process.argv[3];

  assert.ok(['import', 'require'].includes(format));

  const tuples = await runFrameworkMatrix(entries, format);

  console.log(JSON.stringify({ runtime: process.version, tuples }));
}

if (process.argv[1]?.replaceAll('\\', '/').endsWith('/phase11-framework-consumer.mjs')) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
