# Public API stability

Status: Phase10 release-candidate freeze at base `4b748a2`, 21 provider IDs.
This document records the public source/type surface that exists today. It is
not a published 1.0 compatibility promise, and no npm publication is implied.

The freeze has two reviewable parts:

- `tests/types/phase10-api-freeze/fixtures.mjs` — the pinned inventories,
  independent consumer programs and control mutations.
- `scripts/phase10/api-freeze.mjs` — the driver that packs the built package,
  installs it offline into disposable consumer roots, compiles every program
  against the packed declarations with strict `NodeNext`, exact
  `exactOptionalPropertyTypes`/`noUncheckedIndexedAccess`, and records the
  shipped declaration surface.

The driver also compares the built provider registry with the pinned IDs,
checks the runtime export inventory, and requires every fenced sample below to
be an excerpt of a compiled case. Results are local compiler evidence; they do
not prove runtime behavior, provider SDK parity, cryptographic correctness or
live vendor interoperability.

## Public entrypoints

| Subpath | Runtime export | Consumer peer |
| --- | --- | --- |
| `hooklatch` | `verify`, `verifyRequest`, `createVerifier`, `HooklatchError` | none |
| `hooklatch/diagnostics` | `diagnose` | none |
| `hooklatch/express` | `createWebhookMiddleware` | `express` + `@types/express` |
| `hooklatch/nextjs` | `createWebhookHandler` | none (Web `Request`/`Response`) |
| `hooklatch/cloudflare` | `createWebhookHandler` | none (Web `Request`/`Response`) |
| `hooklatch/hono` | `createWebhookMiddleware` | `hono` |

The package provides ESM and CommonJS on Node `>=22` (including 22.0.0).
See [module compatibility](compatibility.md). The Phase10 CJS prototype was
not shipped support. Internal `dist/` subpaths are not public.

## Credential arms

`VerifyOptions` is a provider-discriminated union. Credential discrimination is
part of the contract, not a convenience: an asymmetric provider must never be
configured with a shared secret, and a shared-secret provider must never carry
public keys or an expected account.

| Arm | Providers | Required credentials | Forbidden |
| --- | --- | --- | --- |
| HMAC accept-set | the other 18 IDs, including `vercel` | `secrets: readonly string[]` | `publicKeys`, `expectedUserId`, `providerOptions` |
| Grafana | `grafana` | `secrets` plus `providerOptions` (`mode: 'body'` or `mode: 'timestamped'`) | `publicKeys`, `expectedUserId` |
| Polar | `polar` | `secrets`; optional `providerOptions: { secretMode?: 'current' | 'legacy' }` | `publicKeys`, `expectedUserId` |
| fal | `fal` | `publicKeys: readonly Uint8Array[]` (raw 32-byte Ed25519 keys, 1..16 at runtime) and `expectedUserId` | `secrets`, `providerOptions` |

`CommonVerifyOptions` adds `toleranceSeconds`, `now` and `maxBodyBytes` to every
arm. All public properties are readonly. Runtime validation still rejects empty
secret arrays, non-positive limits and malformed keys; those inputs remain
compile-valid by design and are not claimed as type rejections.

### Literal HMAC configuration

<!-- compiler-case: core/positive-hmac-apis -->

```ts
import { verify, verifyRequest, createVerifier } from 'hooklatch';
import type {
  VerificationResult, VerificationSuccess, VerificationFailure, VerifyOptions, WebhookRequest,
} from 'hooklatch';
const secrets = ['synthetic-current', 'synthetic-previous'] as const;
const options = {
  provider: 'stripe',
  secrets,
  toleranceSeconds: 300,
  maxBodyBytes: 1_048_576,
  now: () => 1_700_000_000,
} as const satisfies VerifyOptions;
export const verifier = createVerifier(options);
```

`createVerifier` is synchronous: it returns
`(request: WebhookRequest) => Promise<VerificationResult>`. `verify` and
`verifyRequest` are asynchronous request APIs. The compile matrix pins those
function types exactly.

### Grafana modes

<!-- compiler-case: core/positive-grafana-modes -->

```ts
import { createVerifier, verify } from 'hooklatch';
import type { GrafanaOptions, VerifyOptions, WebhookRequest } from 'hooklatch';
const body: GrafanaOptions = { mode: 'body' };
const timestamped: GrafanaOptions = { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' };
export const verifier = createVerifier({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);
```

Body mode signs only the raw body and has no freshness check. Timestamped mode
requires a trusted timestamp header name. Header names are configuration, not
authenticated domain separation.

### Polar secret modes

<!-- compiler-case: core/positive-polar-modes -->

```ts
import type { PolarOptions, VerifyOptions } from 'hooklatch';
const current: PolarOptions = { secretMode: 'current' };
const legacy: PolarOptions = { secretMode: 'legacy' };
export const settings = [
  { provider: 'polar', secrets: ['synthetic'] },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: current },
  { provider: 'polar', secrets: ['synthetic'], providerOptions: legacy },
] as const satisfies readonly VerifyOptions[];
```

One mode applies to the whole accept-set. Mixed-era rotation is not expressed by
this type and is not supported at runtime.

### fal raw keys and account binding

<!-- compiler-case: core/positive-fal-keys-account -->

```ts
import { createVerifier, verify } from 'hooklatch';
import type { FalVerifyOptions, VerifyOptions, WebhookRequest } from 'hooklatch';
const keys: readonly Uint8Array[] = [new Uint8Array(32), new Uint8Array(32).fill(7)];
export const fal: FalVerifyOptions = {
  provider: 'fal',
  publicKeys: keys,
  expectedUserId: 'synthetic-user',
  toleranceSeconds: 300,
  now: () => 1_700_000_000,
};
export const verifier = createVerifier(fal);
```

Keys are raw bytes supplied out of band, never a PEM/JWK/`CryptoKey` and never a
dummy shared secret. `expectedUserId` is required and is checked after signature
verification and before freshness. The public identity exposes only the signed
timestamp for fal.

## Consumer migration

### Concrete-provider calls are unchanged

Calls that already name a literal provider keep their previous shape. The union
only changes what broad or extended types may do.

### Broad `Provider` values must be narrowed

A value typed as the full `Provider` union plus `secrets` is not a
`VerifyOptions`, because the provider could be `fal` or one of the configured
providers. Narrow with a switch, a constrained generic, or `satisfies` on a
literal object:

<!-- compiler-case: core/positive-migration-narrowing -->

```ts
import { createVerifier } from 'hooklatch';
import type { Provider, VerifyOptions } from 'hooklatch';
export function hmacOptions<P extends Exclude<Provider, 'grafana' | 'polar' | 'fal'>>(
  provider: P,
  secrets: readonly string[],
): VerifyOptions {
  return { provider, secrets } satisfies VerifyOptions;
}
export function optionsFor(
  provider: Provider,
  secrets: readonly string[],
  publicKeys: readonly Uint8Array[],
  expectedUserId: string,
): VerifyOptions {
  switch (provider) {
    case 'grafana':
      return { provider, secrets, providerOptions: { mode: 'body' } };
    case 'polar':
      return { provider, secrets, providerOptions: { secretMode: 'current' } };
    case 'fal':
      return { provider, publicKeys, expectedUserId };
    default:
      return { provider, secrets };
  }
}
```

A literal preset map is also a safe migration when every value is checked by
`satisfies`:

<!-- compiler-case: core/positive-migration-narrowing -->

```ts
export const presets = {
  stripe: { provider: 'stripe', secrets: ['synthetic'] },
  github: { provider: 'github', secrets: ['synthetic'] },
  fal: { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user' },
} satisfies Record<string, VerifyOptions>;
```

### fal replaces shared secrets

Migrating a shared-secret configuration to fal is not a secret rename. Remove
`secrets`, add raw public keys and the expected account:

The mixed credential arm is rejected:

<!-- compiler-case: core/negative-fal-secrets -->

```ts
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'fal', publicKeys: [new Uint8Array(32)], expectedUserId: 'synthetic-user', secrets: ['synthetic'] }; // @expect-error TS2322
```

The complete accepted configuration is shown in the fal section above and checked
by `core/positive-fal-keys-account`.

### Omit optional properties, do not pass `undefined`

With `exactOptionalPropertyTypes`, `providerOptions: undefined` is not the same
as omitting the property. This matters for HMAC providers, where
`providerOptions` is `never`, and for optional Polar settings. Omit the property:

<!-- compiler-case: core/negative-own-undefined -->

```ts
import type { VerifyOptions } from 'hooklatch';
export const options: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'], providerOptions: undefined }; // @expect-error TS2375
```

Omitting the property is accepted:

<!-- compiler-case: core/positive-readonly-inputs -->

```ts
const baseOptions: VerifyOptions = { provider: 'stripe', secrets: ['synthetic'] };
```

### Interface extension is not a supported migration

`VerifyOptions` is a union of intersections, so `interface Extended extends
VerifyOptions` is rejected with TS2312. Use narrowing, a generic constrained to
an arm, or an intersection type alias if an application really needs extra
fields; an intersection does not make the extra fields part of the SDK contract.

The rejection is `core/negative-interface-extension`.

## Results and diagnostics

Verification failures are returned; setup/runtime failures throw
`HooklatchError`. Narrow `VerificationResult` before reading authenticated
bytes or identity:

<!-- compiler-case: core/positive-hmac-apis -->

```ts
if (first.ok) {
  const success: VerificationSuccess = first;
  const fields: readonly string[] = success.identity.authenticatedFields;
  return success.provider + ':' + success.rawBody.byteLength + ':' + fields.length;
}
```

Reading `rawBody` without narrowing is rejected with TS2339
(`core/negative-unsafe-result-narrowing`).

Diagnostics accept a validated failure or a `HooklatchError`, never a success
result:

<!-- compiler-case: core/positive-diagnostics -->

```ts
import { diagnose } from 'hooklatch/diagnostics';
import type { Diagnostic, DiagnosticCode, DiagnosticOptions } from 'hooklatch/diagnostics';
import { HooklatchError } from 'hooklatch';
import type { VerificationFailure, VerificationResult } from 'hooklatch';
export function fromResult(result: VerificationResult): Diagnostic | null {
  if (result.ok) return null;

  const failure: VerificationFailure = result;
  const options: DiagnosticOptions = { provider: failure.provider, verbose: true };
  const diagnostic: Diagnostic = diagnose(failure, options);

  return diagnostic;
}
```

The nine failure reasons and nine error codes are closed unions. They are pinned
by `core/positive-provider-and-union-pins`; unknown values are rejected by
`core/negative-unknown-reason` and `core/negative-unknown-error-code`.
`DiagnosticCode` is the 18-value union of both and is pinned by
`core/positive-diagnostics`.

## Adapters

Adapters share the same `VerifyOptions` union. They do not relax credential
discrimination.

<!-- compiler-case: express/positive-express-adapter -->

```ts
import { createWebhookMiddleware } from 'hooklatch/express';
import type { Request, RequestHandler } from 'express';
import type { VerifyOptions } from 'hooklatch';
export const literal: RequestHandler = createWebhookMiddleware({
  provider: 'stripe',
  secrets: ['synthetic'],
} satisfies VerifyOptions);
export const configured: RequestHandler = createWebhookMiddleware({
  provider: 'grafana',
  secrets: ['synthetic'],
  providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
} satisfies VerifyOptions);
```

Next.js and Cloudflare consumers compile in a Web-only environment without
`next` or Workers ambient types (`core/positive-nextjs-adapter`,
`core/positive-cloudflare-adapter`). Hono uses its real pinned peer types
(`hono/positive-hono-adapter`).

## Candidate versioning policy

This is a candidate policy for the release owner to confirm; it is not a
published guarantee.

1. Public entrypoints, exported names and the provider-discriminated credential
   arms are the compatibility surface. Type-level breaks count as breaks.
2. Adding a provider ID is a minor release for readers, but consumers with
   exhaustive `switch` statements and a `never` fallback may need an update.
   The provider list is deliberately pinned so an addition is visible.
3. Adding a failure reason or error code is a minor release; exhaustive
   consumer switches may need a `default`.
4. Removing or renaming an export, removing a subpath, changing an arm's
   required credentials, or accepting credentials the current contract forbids
   is a major release.
5. Changing a default clock, tolerance, size limit or identity field is a
   behavioral break and requires a major release or an explicit opt-in.
6. Adapter option types follow the core union; an adapter may not widen or
   weaken it.
7. Node ESM and CommonJS share the public API through conditional exports.
   Lower Node runtimes and arbitrary browser bundlers remain outside this policy.

## Compiler case index

| Case | What it pins |
| --- | --- |
| `core/positive-provider-and-union-pins` | 21 provider IDs in order, 9 reasons, 9 error codes |
| `core/positive-hmac-apis` | literal HMAC, readonly secrets, three root APIs, exact function types, result narrowing |
| `core/positive-readonly-inputs` | readonly record/tuple/Headers inputs, frozen options and requests |
| `core/positive-grafana-modes` | body/timestamped Grafana, header-name variants |
| `core/positive-polar-modes` | current/legacy/omitted Polar settings |
| `core/positive-fal-keys-account` | raw keys, required account, no secrets |
| `core/positive-migration-narrowing` | broad-`Provider` narrowing and `satisfies` presets |
| `core/positive-diagnostics` | diagnostics inputs/outputs and the 18-value code union |
| `core/positive-nextjs-adapter` | Next.js handler without next/Node types |
| `core/positive-cloudflare-adapter` | Workers handler without Workers types |
| `express/positive-express-adapter` | Express middleware and `Request.webhook` augmentation |
| `hono/positive-hono-adapter` | Hono middleware and `WebhookVariables` |
| `core/negative-broad-provider-secrets` | broad provider plus secrets is rejected |
| `core/negative-fal-missing-account` | fal account is required |
| `core/negative-fal-missing-keys` | fal public keys are required |
| `core/negative-fal-secrets` | fal forbids shared secrets |
| `core/negative-fal-provider-options` | fal forbids providerOptions |
| `core/negative-hmac-public-keys` | HMAC forbids public keys/account |
| `core/negative-hmac-provider-options` | non-configured providers forbid options |
| `core/negative-own-undefined` | own `undefined` is rejected under exact optional types |
| `core/negative-missing-grafana-config` | Grafana options are required |
| `core/negative-grafana-unknown-mode` | Grafana mode is closed |
| `core/negative-grafana-timestamp-required` | timestamped mode requires a header name |
| `core/negative-grafana-body-timestamp-header` | body mode forbids a timestamp header |
| `core/negative-forbidden-legacy-config` | legacy Polar options cannot leak to other providers |
| `core/negative-polar-unknown-mode` | Polar secret mode is closed |
| `core/negative-interface-extension` | interface extension of the union is rejected |
| `core/negative-unsafe-result-narrowing` | bytes require success narrowing |
| `core/negative-unknown-provider-id` | provider union is closed |
| `core/negative-unknown-reason` | failure reason union is closed |
| `core/negative-unknown-error-code` | error code union is closed |
| `diagnostics/negative-success-input` | diagnostics reject success objects |

Controls in `scripts/phase10/api-freeze.mjs` mutate a valid consumer to an
invalid credential arm, import a missing export, inject an unmarked TS2322, and
prove that an unresolved package is classified as infrastructure rather than as
diagnostic evidence.

## Limitations

- The matrix compiles against the packed tarball in disposable roots; it does
  not run provider cryptography, live deliveries or vendor SDKs.
- Runtime validation remains broader than the type surface: empty secret arrays,
  non-positive limits and malformed key material are runtime errors, not type
  errors.
- `skipLibCheck: false` covers the shipped declarations in the tested
  environments, but not every bundler, editor or future TypeScript version.
- The entrypoints and their reachable in-package declaration definitions are
  captured for review; they are not a hash lock over
  internal source files and do not prevent future reviewed changes.
- CommonJS qualification is recorded separately in the compatibility guide.
  No lower-Node support or universal bundler compatibility is claimed.
