# Architecture

Hooklatch is a TypeScript ESM package with a dependency-free verification core and
isolated framework adapters.

## Status

The verification core, six provider descriptors, four adapters, a pure diagnostics
helper and a Node-only CLI are implemented. Run `npm run verify` for local checks.
No live-provider validation or published release is implied.

## Layout

```
src/
  types.ts               Public contract types (frozen, v1)      [exists]
  errors.ts              HooklatchError with error codes              [exists]
  core.ts                Orchestration: verify, verifyRequest, createVerifier
  index.ts               Public exports
  internal/
    bytes.ts             UTF-8 encode, concat, hex/Base64 decode [exists]
    headers.ts           Header normalization (case-insensitive)  [exists]
    options.ts           Options validation and normalization     [exists]
    body.ts              Bounded Request body reading            [exists]
    crypto.ts            Web Crypto HMAC verification             [exists]
    provider.ts          Provider descriptor interface            [exists]
    verification.ts      Signature-first verification and freshness policy
  providers/
    index.ts             Provider descriptor registry
    shared.ts            Protocol parsing helpers
    stripe.ts            Stripe descriptor
    github.ts            GitHub SHA-256 descriptor
    shopify.ts           Shopify HTTPS descriptor
    standard-webhooks.ts Standard Webhooks HMAC v1 descriptor
    standard-webhooks-protocol.ts Shared v1 parsing and secret decoding
    clerk.ts             Branded-header preset
    svix.ts              Complete-family alias policy
  diagnostics/           Pure validated-code guidance on its own subpath
  cli/                   Node-only parser, renderer and exclusive filesystem writer
  adapters/
    express.ts           Node request middleware
    nextjs.ts            App Router POST wrapper
    cloudflare.ts        Workers fetch-handler factory
    hono.ts              Hono middleware
    shared.ts            Node byte-stream utilities
tests/                   Jest suites (offline, deterministic)
examples/                Runnable TypeScript examples
```

## Core flow

1. **Capture** — the caller (or adapter) obtains the exact request bytes
   before any parsing.
2. **Normalize** — headers are lowercased and combined; options are validated.
3. **Parse** — a provider descriptor extracts signatures, signed content, and
   metadata from the headers and body.
4. **Verify** — Web Crypto HMAC tries active secret/signature pairs until one
   matches; no JavaScript string comparison decides cryptographic equality.
5. **Freshness** — if the provider signed a timestamp, the core checks it
   against `now()` with inclusive tolerance.
6. **Result** — success returns verified bytes and identity metadata; only fields
   listed in `authenticatedFields` are covered by the signature. Failure returns
   a machine-readable reason.

## Design rules

- Core and diagnostics never import the CLI. Portable and CLI compiler projects
  emit into `dist/`; the package bin points only at the Node CLI entrypoint.
- The CLI does not overwrite files or install dependencies. It rejects existing
  symlink components; concurrent parent replacement is outside its portable
  checks. A failed write can leave a partial owned file, rather than risk
  unlinking a replacement created by another process.

- **Raw bytes are authoritative.** No JSON helper, no re-serialization, no
  payload-type assertion in the core.
- **Snapshot before async work.** Caller bytes, headers, and secrets are
  captured before any `await`; the verified snapshot is returned, not a
  reference into mutable input.
- **Provider-specific logic lives in descriptors.** Key decoding, header
  grammar, and signed-content construction never leak into the core loop.
- **Request failures return; setup failures throw.** Bad signatures are
  outcomes; misconfiguration is an exception.
