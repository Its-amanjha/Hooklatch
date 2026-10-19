# Provider guide

Reference for six supported provider IDs and three pending additions. Six are
implemented and qualified on the Phase 2 baseline; three (razorpay, paddle
Billing only, lemon-squeezy) are **pending integration and qualification** and
are not yet advertised as supported.

See [CLI scaffolding](cli.md) and [diagnostics](diagnostics.md).

## Implemented providers (qualified on baseline)

These six providers are implemented, tested, and part of the current baseline.

| ID | Header | Signed content | Secret form | Identity |
|---|---|---|---|---|
| stripe | `Stripe-Signature` (`t=...,v1=<hex>`) | `timestamp.body` | Literal string | timestamp authenticated |
| github | `X-Hub-Signature-256: sha256=<hex>` | body only | Literal string | unsigned delivery ID only |
| shopify | `X-Shopify-Hmac-Sha256: <base64>` | body only | Literal string | unsigned webhook/event IDs |
| standard-webhooks | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| clerk | `svix-*` branded triplet only | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |
| svix | `svix-*` or `webhook-*` triplet | `id.timestamp.body` | Base64-decode after `whsec_` strip | eventId + timestamp authenticated |

### Authenticated vs unsigned identity

- **Authenticated identity** fields are covered by the signature and survive
  verification: `eventId`, `timestamp` where the protocol signs them.
- **Unsigned header metadata** (delivery IDs and event IDs on body-only
  protocols) is not covered by the signature. It does not stop replay or prove
  the header value was supplied by the provider. IDs inside signed payload bytes
  have integrity protection, but Hooklatch does not parse or extract them.

Body-only protocols (GitHub, Shopify) sign no timestamp, so freshness checks
and ID headers cannot stop replay on their own. A captured valid body and
signature can be replayed. Applications need their own replay/idempotency policy;
deduplicating an unsigned delivery header alone is not replay protection.

## Pending providers (not yet integrated)

The three descriptors are implemented and directly tested on the integration
branch, but are not registered or publicly qualified. The API policies below
remain pending combined integration and qualification.

| ID | Header | Signed content | Secret form | Identity |
|---|---|---|---|---|
| razorpay | `X-Razorpay-Signature` | body only | Literal string | optional `x-razorpay-event-id` (unsigned, eventId) |
| paddle | `Paddle-Signature` (`ts=...;h1=...`) | `ts:body` | Literal string | timestamp authenticated; no IDs |
| lemon-squeezy | `X-Signature` | body only | Literal string | all identity fields null |

### Razorpay

- **Header:** `X-Razorpay-Signature` — single 64-hex HMAC-SHA256 over the raw
  body.
- **Missing / whitespace-only header** → `missing-signature`. Other invalid
  tokens, comma-combined duplicates, prefixes, or lists → `malformed-signature`.
- **Identity:** optional `x-razorpay-event-id` maps to `eventId`, never
  authenticated; absent or whitespace-only → `null`, otherwise preserved
  without further trim. `deliveryId` and `timestamp` are `null`;
  `authenticatedFields` is empty.
- **Optional metadata does not affect signature acceptance.**
- **Source:** https://razorpay.com/docs/webhooks/validate-test/

### Paddle Billing only

- **Header:** `Paddle-Signature` — semicolon-delimited `key=value` fields.
- Exactly one canonical nonnegative safe decimal `ts`; at least one `h1`, each
  exactly 64 hex. Repeated `h1` values are a Hooklatch accept-set policy, not
  a claim of distinct-key SDK parity. Every `h1` must be valid; a malformed one
  poisons the whole header.
- Unknown nonempty scheme-token fields (such as `h2`) may be ignored after
  validation. Their values must be nonempty printable ASCII without whitespace,
  commas, semicolons, or extra equals signs. Invalid
  key / empty value / empty segment / commas → `malformed-signature`. Duplicate
  `ts` is always malformed.
- Missing/blank header → `missing-signature`; no `h1` but other valid
  signature versions → `unsupported-scheme`; `ts`-only → `missing-signature`;
  valid `h1` but absent `ts` → `missing-timestamp`; malformed present `ts` →
  `malformed-signature`. Structure and all tokens are validated before
  required fields are checked.
- **Signed content:** exact `ts` UTF-8 + `:` + raw body bytes.
- `timestamp` is authenticated; `deliveryId`/`eventId` are `null`. Payload IDs
  are not parsed.
- **Planned default tolerance: 5 seconds, symmetric inclusive Hooklatch
  policy** (not exact SDK millisecond-boundary parity). Explicit override
  allowed; zero remains zero-width. This is stricter than pinned SDK future
  handling. Descriptors never enforce clocks themselves.
- **Source:** https://developer.paddle.com/webhooks/about/signature-verification/

### Lemon Squeezy

- **Header:** `X-Signature` — single 64-hex HMAC-SHA256 over the raw body.
- Same missing/malformed policy as Razorpay.
- All identity fields null; `authenticatedFields` empty.
- Provider UI secret-creation limits are not assumed to be a cryptographic
  verification restriction; use a nonempty literal secret, untrimmed.
- **Source:** https://docs.lemonsqueezy.com/help/webhooks/signing-requests

## Cross-provider rules

- **Exact bytes only:** verification runs over the raw request bytes captured
  before any parsing or re-serialization. Empty, non-JSON, and invalid UTF-8
  bodies are preserved; never decode/re-encode the body to build signed
  content.
- **Key form:** Stripe, GitHub, Shopify and the three pending providers use
  literal nonempty untrimmed UTF-8 secrets. Standard Webhooks, Clerk and Svix
  strip an optional `whsec_` prefix and Base64-decode the key, requiring 24–64
  decoded bytes. A prefix alone never selects a protocol.
- **No payload parsing:** verification never parses or validates the payload
  schema.
- **Rotation:** accept-set, not business idempotency. Multiple active secrets
  are tried until one signature matches; this avoids delivery interruption
  during credential rotation but does not deduplicate business events.
- **Case-insensitive headers** through the normalizer. Repeated names are
  comma-combined; Web `Headers` can normalize surrounding whitespace. These
  transformations are distinct from preserving the signed body bytes.

## What this guide does not cover

- No event extraction beyond the listed identity fields.
- No queue guarantees, retry, DLQ, or delivery semantics.
- No account setup, secret registration, or dashboard flows.
- No new public API, provider auto-detection, or `Provider` union changes.
- No Vercel/SHA-1, new algorithms, or dependency updates.

The three new providers remain pending until combined integration and
qualification pass. The existing six-provider baseline remains supported.
