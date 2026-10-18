# Hooklatch

**Verify webhooks. Preserve every byte.**

Portable webhook signature verification with a zero-dependency core.

Hooklatch verifies that incoming webhook requests genuinely come from the provider
you expect — before your code parses or trusts the payload. It supports
Stripe, GitHub, Shopify, and Standard Webhooks with one consistent
asynchronous API, and offers optional framework adapters.

## Requirements

- **Node.js >= 22** (ESM-only; no CommonJS build)
- Zero runtime dependencies in the core
- Optional peers: `express`, `hono` (only needed for those adapters)

## Installation

```bash
npm install hooklatch
```

## Quick start

```ts
import { verify } from 'hooklatch';

const result = await verify(
  { rawBody, headers },                       // exact bytes + headers
  { provider: 'stripe', secrets: [secret] },  // explicit provider
);

if (!result.ok) {
  // Request-validation failure: safe to log the reason.
  console.warn(result.reason, result.message);
  return;
}

// Verified. Parse the payload yourself — verification is not parsing.
const event = JSON.parse(new TextDecoder().decode(result.rawBody));
```

All examples in this README and under `examples/` use synthetic placeholder
values. Replace them with your real endpoint secrets and provider payloads.

## Features

- **Exact-byte verification.** Signatures are checked over the raw request
  bytes captured before any framework parsing or re-serialization.
- **Explicit provider selection.** You name the provider; there is no
  auto-detection to misidentify a request.
- **Secret rotation.** Pass every active secret; the verifier tries all
  signatures against all secrets until one pair matches.
- **Portable core.** Web Crypto HMAC with no Node-only imports; runs on
  Node 22+ and in Workers-compatible runtimes.
- **Framework adapters.** Express, Next.js App Router, Cloudflare Workers,
  and Hono on isolated subpaths.

## Supported protocols

All protocols use HMAC-SHA256. Verification never parses or validates
payload schemas.

| Protocol | Signed content | Secret handling | Timestamp | Identity |
|----------|---------------|-----------------|-----------|----------|
| Stripe | `timestamp.body` | Literal secret string | Signed; inclusive tolerance | Signed timestamp only |
| GitHub | Body only | Literal secret string | None signed | Unsigned delivery ID |
| Shopify | Body only | Literal secret string | None signed | Unsigned delivery/event IDs |
| Standard Webhooks | `id.timestamp.body` | Base64-decoded after `whsec_` strip | Signed; inclusive tolerance | Signed event ID + attempt timestamp |

> **Implementation status (2026-10-18):** The core, four provider descriptors,
> and four adapters are implemented. Tests use published reference vectors and
> synthetic signatures; no live provider/account testing has been performed.
> Run `npm run verify` for the full local checks. See `ARCHITECTURE.md` for
> the implemented layout. The package has not been published by this workflow.

## Core API

### `verify(request, options)`

```ts
verify(
  { rawBody: Uint8Array, headers: HeaderInput },
  { provider: Provider, secrets: string[], toleranceSeconds?, now?, maxBodyBytes? },
): Promise<VerificationResult>
```

- `rawBody` — the exact request bytes. Never a re-serialized object.
- `headers` — Web `Headers`, a readonly tuple list, or a record with string
  or string-array values. Lookup is case-insensitive; values are preserved.
- `secrets` — every active secret. During rotation include old and new.
- `toleranceSeconds` — signed-timestamp freshness window. Default `300`.
  The boundary is inclusive: a timestamp exactly `toleranceSeconds` old is
  accepted. `0` means a zero-width window (only exact matches), **not** a
  skip of verification.
- `now` — clock injection for tests; returns epoch seconds.
- `maxBodyBytes` — body size limit. Default `1048576` (1 MiB). Enforced
  while reading, not just from `Content-Length`.

### `verifyRequest(request, options)`

Consumes a Web `Request` once with bounded reading. Already-consumed bodies
are setup errors (`HooklatchError`). Returns the same `VerificationResult` shape.

### `createVerifier(options)`

Returns a preconfigured asynchronous verifier that takes just the request:

```ts
const verify = createVerifier({ provider: 'github', secrets: [secret] });
const result = await verify({ rawBody, headers });
```

## Result handling

Verification failures are **returned**, not thrown. Setup and runtime
problems are **thrown** as `HooklatchError`.

```ts
import { HooklatchError, verify } from 'hooklatch';

// Request failure — an outcome, not an exception.
const result = await verify(request, options);
if (!result.ok) {
  // result.reason is one of:
  // 'missing-signature' | 'malformed-signature' | 'unsupported-scheme'
  // | 'invalid-signature' | 'missing-identity' | 'missing-timestamp'
  // | 'timestamp-expired' | 'timestamp-future' | 'body-too-large'
}

// Setup failure — thrown, safe to let crash at boot time.
try {
  const verify = createVerifier({ provider: 'nope', secrets: [] });
} catch (err) {
  if (err instanceof HooklatchError) console.warn(err.code);
}
```

| Failure | Meaning |
|---------|---------|
| `missing-signature` | Expected signature header absent |
| `malformed-signature` | Header present but unparseable |
| `unsupported-scheme` | Only legacy/unknown schemes present |
| `invalid-signature` | Well-formed, matches no configured secret |
| `missing-identity` | Required metadata header absent |
| `missing-timestamp` | Signed-timestamp scheme lacks timestamp |
| `timestamp-expired` | Older than tolerance window |
| `timestamp-future` | Newer than tolerance window |
| `body-too-large` | Exceeds `maxBodyBytes` |

## Verified is not parsed

A successful result says the bytes are authentic. It says nothing about the
payload's shape. Decode and validate with your own tools:

```ts
import { z } from 'zod';

const result = await verify(request, options);
if (!result.ok) return;

const event = StripeEventSchema.parse(
  JSON.parse(new TextDecoder().decode(result.rawBody)),
);
```

## Body size limits

`maxBodyBytes` (default 1 MiB) is enforced while reading streams and before
copying raw inputs. Exceeding it returns `{ ok: false, reason:
'body-too-large' }` for request verification, or `HooklatchError` for invalid
limit configuration. Platform limits (e.g. Workers plan limits) may reject
earlier.

## Framework adapters

Adapters live on isolated subpaths and import their framework as an optional
peer dependency:

```ts
import { createWebhookMiddleware } from 'hooklatch/express';
import { createWebhookMiddleware } from 'hooklatch/hono';
import { createWebhookHandler } from 'hooklatch/nextjs';
import { createWebhookHandler } from 'hooklatch/cloudflare';
```

Adapter behavior (contract v1):

- Verification failures respond **400**; size violations **413**;
  setup/runtime failures **500** with a generic response. Core reasons remain
  available for safe application logging.
- User handler errors follow the host framework; they are never reported as
  signature failures.
- Success runs the handler/next stage without acknowledging work early.

### Express

```ts
import { createWebhookMiddleware } from 'hooklatch/express';

app.post(
  '/webhooks/stripe',
  createWebhookMiddleware({ provider: 'stripe', secrets: [secret] }),
  (req, res) => {
    const success = req.webhook;
    if (!success) return res.sendStatus(500);
    const event = JSON.parse(new TextDecoder().decode(success.rawBody));
    res.json({ received: true });
  },
);
```

Mount the middleware **before** any JSON body parser. The adapter reads the
existing raw `Buffer`/`Uint8Array` or an unconsumed request stream; it never
reconstructs bytes from a parsed object. Unsupported compressed bodies are
rejected explicitly.

### Hono

```ts
import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from 'hooklatch/hono';

const app = new Hono<{ Variables: WebhookVariables }>();

app.post(
  '/webhooks/github',
  createWebhookMiddleware({ provider: 'github', secrets: [secret] }),
  async (c) => {
    const success = c.get('webhook');    // VerificationSuccess
    const event = JSON.parse(new TextDecoder().decode(success.rawBody));
    return c.json({ received: true });
  },
);
```

### Next.js App Router

```ts
// app/webhooks/stripe/route.ts
import { createWebhookHandler } from 'hooklatch/nextjs';

export const POST = createWebhookHandler({
  provider: 'stripe',
  secrets: [process.env.STRIPE_SECRET!],
  handler: async (request, success) => {
    const event = JSON.parse(new TextDecoder().decode(success.rawBody));
    return Response.json({ received: true });
  },
});
```

The original request body is consumed during verification; read
`success.rawBody`, not the request body.

### Cloudflare Workers

```ts
import { createWebhookHandler } from 'hooklatch/cloudflare';

const fetch = createWebhookHandler<{ GITHUB_SECRET: string }>({
  options: (env) => ({ provider: 'github', secrets: [env.GITHUB_SECRET] }),
  handler: async (request, env, ctx, success) => {
    const event = JSON.parse(new TextDecoder().decode(success.rawBody));
    return Response.json({ received: true });
  },
});

export default { fetch };
```

`options` receives `env` so bindings are resolved explicitly.

## Roadmap

- Future delivery integrations (queueing, retries, DLQ) are planned but not
  part of this release. They will be designed separately and will not couple
  to the verification API.

## Security

See `SECURITY.md` for the vulnerability reporting policy.

## License

MIT — see `LICENSE`.
