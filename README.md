# Hooklatch

**Verify webhooks. Preserve every byte.**

[![CI](https://github.com/Its-amanjha/Hooklatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Its-amanjha/Hooklatch/actions/workflows/ci.yml)

Portable webhook signature verification with a zero-dependency core.

Hooklatch checks incoming webhook signatures over the exact request bytes
before your code parses or trusts the payload. It supports Stripe, GitHub,
Shopify, Standard Webhooks, Clerk, Svix, Razorpay, Paddle Billing, Lemon
Squeezy, Dodo Payments, GitLab signing tokens, Replicate, WorkOS, Sentry App,
Doppler signed webhooks, Sanity, Grafana, Polar, Linear, Vercel and fal through
one asynchronous API,
with optional framework adapters, diagnostics and a local scaffolding CLI.


## Requirements

- **Node.js >= 22** (ESM and CommonJS; the 22.0.0 floor, later 22.x and 24.x
  were qualified — see [module compatibility](docs/compatibility.md))
- Zero runtime dependencies in the core
- Optional peers: `express`, `hono` (only needed for those adapters)

## Installation

Publication to npm is pending, so `npm install hooklatch` is not yet supported.
Build this checkout with `npm ci` and `npm run build` before packing it. A
future published release is intended to install as:

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
- **Credential rotation.** For HMAC providers, pass every active secret; the
  verifier tries signatures against the accept-set. For fal, configure the
  trusted public-key accept-set and expected user ID.
- **Portable core.** Web Crypto HMAC and Ed25519 with no Node-only imports; runs on
  Node 22+ and in Workers-compatible runtimes.
- **Framework adapters.** Express, Next.js App Router, Cloudflare Workers,
  and Hono on isolated subpaths.

## Supported protocols

Verification never parses or validates payload schemas. Algorithms are fixed per
provider: the first nineteen use HMAC-SHA256, Vercel uses HMAC-SHA1, and fal uses
Ed25519. Request data cannot select the algorithm.

<!-- hooklatch:provider-table:start -->
| Provider | Algorithm | Signed content | Credentials | Freshness | Identity |
|----------|-----------|----------------|-------------|-----------|----------|
| `stripe` | HMAC-SHA256 | `timestamp.body` | Literal secret string | Signed; inclusive tolerance (default 300s) | Signed timestamp only |
| `github` | HMAC-SHA256 | Body only | Literal secret string | None signed | Unsigned delivery ID |
| `shopify` | HMAC-SHA256 | Body only | Literal secret string | None signed | Unsigned webhook/event IDs |
| `standard-webhooks` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after `whsec_` strip (24–64 bytes) | Signed; inclusive tolerance (default 300s) | Signed event ID + attempt timestamp |
| `clerk` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after `whsec_` strip (24–64 bytes) | Signed; inclusive tolerance (default 300s) | Signed event ID + attempt timestamp |
| `svix` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after `whsec_` strip (24–64 bytes) | Signed; inclusive tolerance (default 300s) | Signed event ID + attempt timestamp |
| `razorpay` | HMAC-SHA256 | Body only | Literal secret string | None signed | Optional unsigned event ID |
| `paddle` | HMAC-SHA256 | `ts:body` | Literal secret string | Signed; default 5s (symmetric inclusive) | Signed timestamp only |
| `lemon-squeezy` | HMAC-SHA256 | Body only | Literal secret string | None signed | None extracted |
| `dodo-payments` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after optional `whsec_` strip (24–64 bytes) | Signed; default 300s | Signed event ID + timestamp |
| `gitlab` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after optional `whsec_` strip (24–64 bytes) | Signed; default 300s | Signed event ID + timestamp |
| `replicate` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded after optional `whsec_` strip (24–64 bytes) | Signed; default 300s | Signed event ID + timestamp |
| `workos` | HMAC-SHA256 | `t.body` (millisecond `t`) | Literal secret string | Signed; default 180s | Signed timestamp only |
| `sentry` | HMAC-SHA256 | Body only | Literal secret string | None signed | None extracted |
| `doppler` | HMAC-SHA256 | Body only | Literal secret string | None signed | None extracted |
| `sanity` | HMAC-SHA256 | `t.body` (with `.` separator) | Literal secret string | Signed; default 300s (receiver policy) | Signed timestamp only |
| `grafana` | HMAC-SHA256 | Body (body mode) or `timestamp:body` (timestamped mode) | Literal secret string | Timestamped mode only; default 300s | Signed timestamp in timestamped mode |
| `polar` | HMAC-SHA256 | `id.timestamp.body` | Base64-decoded (current) or literal UTF-8 (legacy); one mode per accept-set | Signed; default 300s | Signed event ID + timestamp |
| `linear` | HMAC-SHA256 | Body only | Literal secret string | Body timestamp not extracted or freshness-checked | None extracted |
| `vercel` | HMAC-SHA1 | Body only | Literal secret string | None signed | None extracted |
| `fal` | Ed25519 | `requestId\nuserId\ntimestamp\nsha256hex(body)` | Raw 32-byte public keys (1..16) + required `expectedUserId`; no shared secret | Signed; default 300s | Signed timestamp only |
<!-- hooklatch:provider-table:end -->

Clerk ignores canonical `webhook-*` headers. Svix accepts either complete header
family; if both appear they must be complete and equal. Partial families are
never assembled together. Standard Webhooks, Clerk and Svix require decoded
signing keys of 24–64 bytes, as do Dodo, GitLab and Replicate; shorter
reference-library examples are rejected. GitLab requires a signing token;
legacy `X-Gitlab-Token` alone is not accepted.
Linear support authenticates the signature over exact body bytes. It does not
parse `webhookTimestamp` or enforce freshness. The body claims remain covered by
the MAC, but Hooklatch does not extract them into identity. `Linear-Timestamp`,
`Linear-Delivery` and `Linear-Event` headers are unsigned and ignored. Applications
that need replay checks must validate authenticated body claims after success.

See the [provider guide](docs/providers.md) for exact headers, identity fields,
and protocol-specific limits. Paddle support covers Billing webhooks only.

Use endpoint-specific secrets. Providers sharing a signing protocol can accept
the same signed request when configured with the same key. The `provider`
option selects verification rules; it does not add cryptographic vendor binding.

> **Implementation status (documentation reviewed 2026-10-30):** The core,
> twenty-one provider descriptors, four adapters, CLI and diagnostics helper are
> implemented. The last measured acceptance was commit `baa8a74` on 2026-10-28:
> a clean local `npm run verify` passed 87 suites / 4,161 tests plus the
> package, type and runtime gates, and exact-SHA CI run
> [40650684406](https://github.com/Its-amanjha/Hooklatch/actions/runs/40650684406)
> completed successfully (verify on Node.js 22 and 24; node-floor on Node.js
> 22.0.0; checked 2026-10-29). Tests use reference vectors and synthetic
> signatures; no live provider or delivery testing has been performed. This
> documentation review is dated 2026-10-30 and does not re-run or extend that
> qualification.
> Run `npm run verify` for the full local checks. See
> [verification evidence](docs/verification-evidence.md) for the measured scope,
> provenance and receipt references, and [CONTRIBUTING.md](CONTRIBUTING.md) for
> the implemented layout. The package is unpublished: no npm release or Git tag
> exists.

## Local scaffolding

With a built copy of Hooklatch installed, preview one TypeScript handler
without writing files:

```sh
npx --no-install hooklatch init webhook --provider clerk --framework nextjs --dry-run
```

Remove `--dry-run` to generate it. Existing files are refused. See the
[CLI reference](docs/cli.md) for paths, environment names and filesystem limits.

## Diagnostics

```ts
import { diagnose } from 'hooklatch/diagnostics';

if (!result.ok) console.warn(diagnose(result));
```

The pure helper returns static guidance for a validated reason/provider and
ignores request messages and payloads. Possible causes are suggestions, not
proof of a wrong secret or tampering. See [diagnostics](docs/diagnostics.md).

## Core API

### `verify(request, options)`

```ts
verify(request: WebhookRequest, options: VerifyOptions): Promise<VerificationResult>
```

- `rawBody` — the exact request bytes. Never a re-serialized object.
- `headers` — Web `Headers`, a readonly tuple list, or a record with string
  or string-array values. Lookup is case-insensitive; repeated values are
  comma-combined. Web `Headers` can normalize surrounding whitespace.
- `providerOptions` — trusted application configuration, required for Grafana,
  optional for Polar, and forbidden for other providers. See configured providers below.
- `secrets` — HMAC providers only: every active secret, including old and new
  during rotation.
- `publicKeys` and `expectedUserId` — fal only: trusted raw 32-byte Ed25519
  public keys (1..16) and the required expected signed user ID. Both fields
  belong at the top level; fal forbids `secrets` and `providerOptions`.
- `toleranceSeconds` — signed-timestamp freshness window. Default `5` for
  Paddle Billing, `180` for WorkOS and `300` for the other timestamped providers.
  The boundary is inclusive: a timestamp exactly `toleranceSeconds` old is
  accepted. `0` means a zero-width window (only exact matches), **not** a
  skip of verification.
  Paddle uses Hooklatch's symmetric window, including future rejection; this
  does not promise exact SDK clock or parser parity. Body-only protocols have
  no authenticated timestamp; signature verification alone does not stop replay.
- `now` — clock injection for tests; returns epoch seconds and may be fractional.
  WorkOS and Sanity preserve milliseconds in their default clocks; other default
  clocks use whole seconds. Sanity's 300-second freshness window is Hooklatch
  receiver policy, not an established upstream SDK recency default.
  Request-reading APIs and adapters capture the clock before consuming the body;
  freshness is measured at ingress, not at business-processing time.
- `maxBodyBytes` — body size limit. Default `1048576` (1 MiB). Enforced
  while reading, not just from `Content-Length`.

For fal, supply credentials from trusted application configuration:

```ts
const result = await verify(
  { rawBody, headers },
  {
    provider: 'fal',
    publicKeys: trustedPublicKeys, // 1..16 raw 32-byte Uint8Array values
    expectedUserId: configuredUserId,
  },
);
```

Do not add dummy shared secrets or obtain keys or the expected user ID from
the incoming request. Signature authentication precedes account matching and
freshness checks; only the signed timestamp is returned as public identity.

### `verifyRequest(request, options)`

Consumes a Web `Request` once with bounded reading. Already-consumed bodies
are setup errors (`HooklatchError`). Returns the same `VerificationResult` shape.

### `createVerifier(options)`

Returns a preconfigured asynchronous verifier that takes just the request:

```ts
const verify = createVerifier({ provider: 'github', secrets: [secret] });
const result = await verify({ rawBody, headers });
```

## Configured providers

Grafana requires explicit trusted layout configuration. For example:

```ts
import { createVerifier } from 'hooklatch';

const verifier = createVerifier({
  provider: 'grafana',
  secrets: [secret],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-alert-timestamp' },
});
```

Body mode signs only the raw body and
provides no freshness check. Timestamped mode defaults to an inclusive 300-second
window; neither mode deduplicates requests. Header names are configuration, not
signed domain separation.

Polar defaults to current Base64-decoded keys. Select
`providerOptions: { secretMode: 'legacy' }` for full literal UTF-8 keys. One mode
applies to every active secret; mixed-era rotation is unsupported.

`VerifyOptions` is now a provider-discriminated union. Existing concrete-provider
calls remain valid; broad provider objects and interface extension may need
narrowing. See the [provider guide](docs/providers.md) and
[type migration notes](docs/diagnostics.md#source-typing-migration-impact).

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

Reference test vectors come from [GitHub's webhook verification documentation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
and the [Standard Webhooks JavaScript test suite at a pinned revision](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/javascript/src/webhook.test.ts).
Additional reference tuples come from the [Sanity toolkit tests at a pinned revision](https://github.com/sanity-io/webhook-toolkit/blob/e0c211ed6cd80465a70829e335c9e219f37839ba/test/signature.test.ts).
The [Paddle Node SDK validator tests](https://github.com/PaddleHQ/paddle-node-sdk/blob/651261beddfc65ba5f861729dca17044cbeffb5f/src/__tests__/notifications/webhooks-validator.node.test.ts)
also supply two published reference tuples. These are external reference material;
locally generated cases are separately labelled synthetic.
The Standard Webhooks repository includes an
[MIT notice under `libraries/`](https://github.com/standard-webhooks/standard-webhooks/blob/7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b/libraries/LICENSE).
See [source and history notes](https://github.com/Its-amanjha/Hooklatch/blob/main/CONTRIBUTING.md#source-and-history-notes)
for attribution and review limits.
