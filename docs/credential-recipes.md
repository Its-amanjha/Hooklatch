# Credential and configuration recipes

This guide accompanies `examples/phase10/credential-recipes.ts`. Every sample
below is taken from that example and exercised by
`tests/examples/phase10-credential-recipes.test.ts`.

## Portable fal credentials

fal uses raw 32-byte Ed25519 public keys and a required expected user ID. The
SDK does not fetch JWKS, resolve key URLs, or invent a shared secret.

`falOptionsFromEnv(publicKeysValue, expectedUserId)` parses a comma-delimited
environment value into `FalVerifyOptions`:

- 1 to 16 entries.
- Each entry is exactly 43 unpadded Base64url characters.
- Each entry decodes to exactly 32 bytes.
- Unused Base64 bits must be canonical (zero).
- No whitespace trimming, padding, or alternate encodings are accepted.
- `expectedUserId` must be 1 to 1024 visible ASCII characters excluding comma.

```ts
import { falOptionsFromEnv } from './credential-recipes.js';

const options = falOptionsFromEnv(process.env.FAL_WEBHOOK_PUBLIC_KEYS, process.env.FAL_WEBHOOK_USER_ID);
```

Rotation is caller-owned: add the new public key to the comma-delimited list,
deploy, then remove the retired key in a later change. Hooklatch tries every
configured key and validates the signed timestamp against the configured freshness
window. It does not remember delivery IDs or prevent duplicates within that
window. Business idempotency remains caller-owned.

Errors from `falOptionsFromEnv` are generic and never include environment values
or key material.

## Grafana recipes

Grafana requires an explicit mode. There is no implicit default layout and no
key inference.

```ts
import { createGrafanaTimestampedVerifier } from './credential-recipes.js';

const verify = createGrafanaTimestampedVerifier({
  secret: process.env.GRAFANA_WEBHOOK_SECRET!,
  timestampHeader: 'x-grafana-timestamp',
  now: () => Math.floor(Date.now() / 1000),
});
```

A custom signature header and timestamp header can be used instead of the
Grafana defaults. The header names are lookup configuration only; they are not
part of the signed bytes.

```ts
import { createGrafanaCustomHeaderVerifier } from './credential-recipes.js';

const verify = createGrafanaCustomHeaderVerifier({
  secret: process.env.GRAFANA_WEBHOOK_SECRET!,
  signatureHeader: 'x-custom-grafana-signature',
  timestampHeader: 'x-custom-grafana-timestamp',
  now: () => Math.floor(Date.now() / 1000),
});
```

Reserved header names and a signature header that collides with the timestamp
header are rejected when the verifier is created. A MAC present only in an
unselected header is never rescued.

## Polar recipes

Polar has two mutually exclusive secret interpretations. One mode applies to
every secret in the verifier.

```ts
import { createPolarCurrentVerifier, createPolarLegacyVerifier } from './credential-recipes.js';

const current = createPolarCurrentVerifier({
  secrets: [process.env.POLAR_WEBHOOK_SECRET!],
  now: () => Math.floor(Date.now() / 1000),
});

const legacy = createPolarLegacyVerifier({
  secrets: [process.env.POLAR_WEBHOOK_SECRET!],
  now: () => Math.floor(Date.now() / 1000),
});
```

`current` strips an optional `whsec_` prefix and Base64-decodes the remainder.
`legacy` uses the complete secret string as literal UTF-8 bytes, including any
`whsec_` prefix. Mixed-era accept sets are not supported; changing the mode
changes how every configured secret is interpreted. There is no automatic
cross-mode fallback.

## Linear is authentication only

Linear verification authenticates the exact raw body and returns no freshness
or identity fields. Parsing, duplicate-key detection, idempotency, replay
handling, and business policy belong to caller code after a successful result.

```ts
import { createLinearAuthenticationVerifier } from './credential-recipes.js';

const verify = createLinearAuthenticationVerifier([process.env.LINEAR_WEBHOOK_SECRET!]);
```

Call the verifier with the raw request bytes and headers. Reject a failed result
before parsing. After `result.ok` is true, caller code may parse `result.rawBody`
and enforce its own freshness, duplicate-key, and business-idempotency policies.
Hooklatch does not provide a body-extraction API or JSON duplicate-key parser.

## Safety notes

- Keep secrets and public keys in environment or secret storage, not in source.
- Capture raw request bytes before any framework body parsing.
- Treat a successful verification result as authentication only.
- Do not promise exactly-once processing or provider retry behavior.
