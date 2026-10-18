/**
 * Test Worker for the offline Workers runtime smoke harness.
 *
 * Bundled by `scripts/workers-smoke.mjs` with esbuild targeting `neutral`
 * platform and `workerd`/`worker`/`browser` export conditions, then executed
 * inside a real `workerd` runtime via Miniflare. No Node compatibility flags,
 * no network calls, no delivery/QStash code.
 *
 * Every handler reports the verified bytes it received (Base64) plus a
 * SHA-256 digest computed in the Worker, so the Node side can assert the exact
 * bytes rather than only an HTTP status.
 *
 * This file is strictly typechecked separately by `tsconfig.workers.json`.
 */

import { createWebhookHandler } from '../../src/adapters/cloudflare.js';
import { verifyRequest } from '../../src/index.js';
import type { VerificationSuccess } from '../../src/types.js';

import { PROBE_MAX_BODY_BYTES } from './fixtures.mjs';

interface Env {
  readonly HOOKLATCH_GITHUB_SECRET: string;
  readonly HOOKLATCH_STANDARD_WEBHOOKS_SECRET: string;
  readonly HOOKLATCH_NOW: string;
  readonly HOOKLATCH_MARKER: string;
}

/** Minimal structural stand-ins; Cloudflare types are not a dependency. */
interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Describes a successful verification using only Web APIs available in
 * workerd. `rawBody` here is the byte snapshot the core returned, so the digest
 * is an independent measurement of what survived the runtime boundary.
 */
async function describe(success: VerificationSuccess, env: unknown): Promise<Response> {
  const bindings = env as Env;
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(success.rawBody)),
  );
  return Response.json({
    verified: true,
    provider: success.provider,
    identity: success.identity,
    rawBodyLength: success.rawBody.byteLength,
    rawBodyBase64: toBase64(success.rawBody),
    rawBodySha256Hex: toHex(digest),
    envMarker: bindings.HOOKLATCH_MARKER,
  });
}

const githubHandler = createWebhookHandler({
  options: (env: unknown) => {
    const bindings = env as Env;
    return {
      provider: 'github',
      secrets: [bindings.HOOKLATCH_GITHUB_SECRET],
      now: () => Number(bindings.HOOKLATCH_NOW),
    };
  },
  handler: (_request, env, _ctx, success) => describe(success, env),
});

const standardWebhooksHandler = createWebhookHandler({
  options: (env: unknown) => {
    const bindings = env as Env;
    return {
      provider: 'standard-webhooks',
      secrets: [bindings.HOOKLATCH_STANDARD_WEBHOOKS_SECRET],
      now: () => Number(bindings.HOOKLATCH_NOW),
    };
  },
  handler: (_request, env, _ctx, success) => describe(success, env),
});

/**
 * Direct core `verifyRequest` probe, bypassing the adapter, so the Request
 * wrapper is exercised in workerd on its own.
 *
 * The agreed adapter contract deliberately returns *generic* response text
 * (`'Bad Request'`) and keeps core reasons out of HTTP bodies, so these probe
 * routes are the only place where an exact `reason` is observable from outside
 * the Worker. They also carry the only non-default body limit, which exercises
 * the streaming size guard (ReadableStream reader + cancel) inside workerd.
 */
async function requestWrapperProbe(request: Request, env: unknown, provider: 'github' | 'standard-webhooks'): Promise<Response> {
  const bindings = env as Env;
  const secret =
    provider === 'github' ? bindings.HOOKLATCH_GITHUB_SECRET : bindings.HOOKLATCH_STANDARD_WEBHOOKS_SECRET;
  try {
    const result = await verifyRequest(request, {
      provider,
      secrets: [secret],
      now: () => Number(bindings.HOOKLATCH_NOW),
      maxBodyBytes: PROBE_MAX_BODY_BYTES,
    });
    if (!result.ok) {
      const status = result.reason === 'body-too-large' ? 413 : 400;
      return Response.json({ verified: false, reason: result.reason }, { status });
    }
    return describe(result, bindings);
  } catch (error) {
    const code = error instanceof Error ? error.name : 'unknown';
    return Response.json({ verified: false, setupError: code }, { status: 500 });
  }
}

async function runtimeProbe(): Promise<Response> {
  // Proves the harness is executing inside a real Workers runtime rather than
  // a Node or jsdom shim.
  const userAgent = globalThis.navigator?.userAgent ?? 'unavailable';
  const hasNodeGlobals =
    typeof (globalThis as { process?: unknown }).process !== 'undefined' ||
    typeof (globalThis as { Buffer?: unknown }).Buffer !== 'undefined';
  return Response.json({ userAgent, hasNodeGlobals });
}

async function route(pathname: string, request: Request, env: unknown): Promise<Response> {
  switch (pathname) {
    case '/probe/runtime':
      return runtimeProbe();
    case '/probe/request-wrapper':
      return requestWrapperProbe(request, env, 'github');
    case '/probe/request-wrapper/standard-webhooks':
      return requestWrapperProbe(request, env, 'standard-webhooks');
    case '/webhooks/github':
      return githubHandler(request, env, {} as ExecutionContextLike);
    case '/webhooks/standard-webhooks':
      return standardWebhooksHandler(request, env, {} as ExecutionContextLike);
    default:
      return new Response('not found', { status: 404 });
  }
}

export default {
  fetch(request: Request, env: unknown, _ctx: ExecutionContextLike): Promise<Response> {
    return route(new URL(request.url).pathname, request, env);
  },
};
