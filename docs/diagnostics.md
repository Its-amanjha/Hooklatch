# Diagnostics

Hooklatch diagnostics provide structured, human-readable guidance for verification
failures and setup errors. The `diagnose` helper turns a `VerificationFailure`
or `HooklatchError` into a stable `Diagnostic` object with machine-readable
codes and prose suitable for logging, troubleshooting, and CLI output.

## Installation

Diagnostics are exported from the `hooklatch/diagnostics` subpath:

```ts
import { diagnose } from 'hooklatch/diagnostics';
```

## API

```ts
diagnose(
  input: VerificationFailure | HooklatchError,
  options?: { provider?: Provider; verbose?: boolean },
): Diagnostic
```

### Arguments

- `input` — a `VerificationFailure` (returned by `verify` when `ok` is
  `false`) or a `HooklatchError` (thrown for setup/runtime problems).
- `options.provider` — optional provider context. For a verification failure,
  the failure's own provider is used automatically; a conflicting override
  throws `HooklatchError('invalid-input')`. For a setup error, `options.provider`
  supplies provider-specific verbose detail.
- `options.verbose` — when `true`, includes static expected-header names and
  grammar descriptions for the selected provider. Defaults to `false`.

### Result

```ts
interface Diagnostic {
  readonly code: DiagnosticCode;       // VerificationFailureReason | HooklatchErrorCode
  readonly kind: 'verification' | 'setup';
  readonly provider?: Provider;
  readonly summary: string;
  readonly possibleCauses: readonly string[];
  readonly suggestions: readonly string[];
  readonly detail?: {
    readonly expectedHeaders: readonly string[];
    readonly grammar: string;
  };
}
```

`code` and `kind` are stable machine-readable fields. Prose (`summary`,
`possibleCauses`, `suggestions`) is intended for humans and may evolve between
releases.

## Configured providers — Grafana and Polar

Grafana and Polar diagnostics use static provider guidance. They receive no
application configuration and never infer it from request data.

### Grafana

There is no configuration context at diagnostic time, so `expectedHeaders` is
`[]`. The verbose `grammar` describes the two explicit modes
and configured header roles; they do **not** claim that the default header is
always expected.

- Body mode: `signatureHeader` covers the raw body only; `timestampHeader` is
  forbidden (even when empty or explicitly undefined).
- Timestamped mode: `signatureHeader` plus a required `timestampHeader`;
  timestamp text must be a canonical nonnegative safe decimal integer in
  seconds; missing or blank timestamp → `missing-timestamp`.

### Polar

`expectedHeaders` lists the canonical Standard Webhooks headers
(`webhook-id`, `webhook-timestamp`, `webhook-signature`). The verbose `grammar`
explains that the selected `secretMode` (`current` or `legacy`) is
application configuration and applies to every configured secret in the
accept-set; no mixed-era or dual-key migration is performed.

### Vercel (pending integration)

Static diagnostics only; Vercel is not registered in the current CLI.
`expectedHeaders` lists `x-vercel-signature`. The verbose `grammar` describes
HMAC-SHA1 over the exact raw body with exactly 40 hex characters, either case,
and uppercase acceptance as a Hooklatch receiver policy.

### fal (pending integration)

Static diagnostics only; fal is not registered in the current CLI.
`expectedHeaders` lists `x-fal-webhook-signature`, `x-fal-webhook-request-id`,
`x-fal-webhook-user-id`, `x-fal-webhook-timestamp`. The verbose `grammar`
describes Ed25519 over `requestId + '\n' + userId + '\n' + timestamp + '\n' +
sha256hex(rawBody)`, raw 32-byte public keys (1..16), and a required
`expectedUserId` that must match `userId` exactly after signature
verification. No shared secrets, no JWKS fetch, no key URL from request data.

### Redaction guarantees

Diagnostics never echo:

- Request bodies or payload contents
- Raw signatures or signature values
- Secrets or secret-derived values
- Sensitive identifiers (delivery IDs, event IDs, resource IDs)
- Error `message`, `stack`, or `cause`
- Arbitrary extra properties on input objects

## Verification failure reasons

| Code | Summary |
|------|---------|
| `missing-signature` | The provider signature header was not present. |
| `malformed-signature` | The signature header could not be parsed. |
| `unsupported-scheme` | Only unsupported or legacy schemes were present. |
| `invalid-signature` | The signature was well-formed but did not authenticate. |
| `missing-identity` | A required identity metadata header was absent. |
| `missing-timestamp` | A required signed timestamp header was absent. |
| `timestamp-expired` | The signed timestamp is older than the tolerance. |
| `timestamp-future` | The signed timestamp is newer than the tolerance. |
| `body-too-large` | The request body exceeded the configured size limit. |

An `invalid-signature` result means authentication failed. It does **not**
establish a wrong secret, prove tampering, or indicate a malicious request.
Possible causes include secret mismatch, in-progress rotation, body
modification in transit, wrong provider selection, or a request not from the
provider.

## Setup error codes

| Code | Summary |
|------|---------|
| `unknown-provider` | The specified provider is not supported. |
| `missing-secrets` | No signing secrets were configured. |
| `invalid-secret` | A configured secret failed validation. |
| `invalid-options` | The verification options were malformed. |
| `invalid-input` | The request or header input was malformed. |
| `body-consumed` | The Request body was already read before verification. |
| `body-read-failed` | The request body stream could not be read. |
| `crypto-unavailable` | Web Crypto is not available in this environment. |
| `internal` | An unexpected internal error occurred. |

## Usage examples

### Handling a verification failure

```ts
import { verify } from 'hooklatch';
import { diagnose } from 'hooklatch/diagnostics';

const result = await verify({ rawBody, headers }, options);
if (!result.ok) {
  const diagnostic = diagnose(result);
  // { code: 'invalid-signature', kind: 'verification', ... }
  console.log(diagnostic.possibleCauses);
}
```

### Verbose output for a specific provider

```ts
const diagnostic = diagnose(result, { provider: 'stripe', verbose: true });
// detail: {
//   expectedHeaders: ['Stripe-Signature'],
//   grammar: 'Comma-separated key=value pairs: t=<unix-seconds>,v1=<hex-signature>[,v1=<hex-signature>]',
// }
```

### Handling a setup error

```ts
try {
  createVerifier({ provider: 'stripe', secrets: [] });
} catch (err) {
  if (err instanceof HooklatchError) {
    const diagnostic = diagnose(err);
    // { code: 'missing-secrets', kind: 'setup', ... }
  }
}
```

## Purity

`diagnose` is synchronous and performs no I/O, network access, provider
detection, or freshness bypass. It works in any runtime including Cloudflare
Workers.

## Linear signature authentication

Linear diagnostics list `Linear-Signature` and the bare 64-hex raw-body signature
grammar. They describe signature authentication only. A successful result does
not establish freshness: Hooklatch does not extract the body timestamp, and the
unsigned timestamp header cannot establish it. Diagnostic text is static and
never reproduces the request body, secret, signature, or caller error message.
