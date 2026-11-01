# Getting started

## Requirements

- **Node.js 22 or later.** The 22.0.0 floor was measured on Windows and Linux;
  later 22.x and 24.x were also qualified. Node.js 18 and 20 are not supported.
  See [module compatibility](compatibility.md).
- **ESM or CommonJS on Node.js.** ESM examples use `.mjs` files. CommonJS
  examples use `.cjs` files, or `.js` files inside a `"type": "commonjs"`
  package.
- **Zero runtime dependencies in the core.** Verification does not require a
  framework, a queue, or a provider SDK.
- **Optional peers for two adapters.** `express` and `hono` are optional peer
  dependencies; install them only if you use those adapters. The Next.js and
  Cloudflare adapters use Web `Request`/`Response` and need no framework peer.
- **Workers-compatible runtimes** keep the original neutral ESM graph. This is
  not a universal bundler, browser, Deno or Bun guarantee.

## Install

```bash
npm install hooklatch
```

If you are working from a checkout instead, build and pack it first, then
install the resulting tarball:

```bash
npm ci
npm run build
npm pack
```

The package resolves its public entries under `dist/`. A checkout that has not
been built has no `dist/`, and installing that source directory directly is not
the reviewed path. Use the packed tarball.

## Verify your first webhook (ESM)

The next example is self-contained. It signs a synthetic body locally with
`node:crypto`, then verifies the same bytes through Hooklatch. It does not
contact GitHub or any other provider.

<!-- hooklatch:example:core-esm -->
```js
import { createHmac } from 'node:crypto';
import { verify } from 'hooklatch';

const rawBody = new TextEncoder().encode('hooklatch onboarding');
const secret = 'hooklatch-synthetic-onboarding';
const signature = createHmac('sha256', secret).update(rawBody).digest('hex');
const result = await verify(
  { rawBody, headers: { 'x-hub-signature-256': `sha256=${signature}` } },
  { provider: 'github', secrets: [secret] },
);

if (!result.ok) throw new Error('Verification failed.');
console.log('verified');
```

Save the example as `verify-webhook.mjs` and run `node verify-webhook.mjs`.
The expected output is:

```text
verified
```

The example uses the GitHub provider's `sha256=<hex>` header form. The
`rawBody` is the exact byte sequence that was signed, and `secrets` is an
accept-set: during rotation, pass every active secret. A verification failure is
returned as `{ ok: false, reason }`; setup and runtime problems are thrown as
`HooklatchError`. Check `result.ok` before decoding or parsing the payload.

The HMAC in this example is computed locally with a synthetic secret. That is
local wiring for the example, not a provider delivery and not evidence of live
vendor interoperability. In a real handler, the provider signs the request and
you read the secret from configuration.

## Same check in CommonJS

The next example performs the same verification from a CommonJS file.

<!-- hooklatch:example:core-commonjs -->
```js
const { createHmac } = require('node:crypto');
const { verify } = require('hooklatch');

async function main() {
  const rawBody = new TextEncoder().encode('hooklatch onboarding');
  const secret = 'hooklatch-synthetic-onboarding';
  const signature = createHmac('sha256', secret).update(rawBody).digest('hex');
  const result = await verify(
    { rawBody, headers: { 'x-hub-signature-256': `sha256=${signature}` } },
    { provider: 'github', secrets: [secret] },
  );

  if (!result.ok) throw new Error('Verification failed.');
  console.log('verified');
}

main().catch(() => {
  console.error('Verification failed.');
  process.exitCode = 1;
});
```

Save it as `verify-webhook.cjs` and run `node verify-webhook.cjs`. It also
prints `verified`. Do not mix `import` and `require` in one file. The ESM and
CommonJS entries share one implementation on Node.js, so classes and function
objects keep their identity within one process; see
[same-process identity](compatibility.md#same-process-identity).

## Use it in a real handler

- **Capture the exact request bytes before parsing.** Pass a `Uint8Array` or
  `Buffer` as `rawBody`; never pass a re-serialized object. If a framework body
  parser already consumed the request, you no longer have the signed bytes.
- **Read secrets from configuration.** Use an environment variable or secret
  manager. Do not embed production secrets in source, generated files, logs or
  examples.
- **Verify before parsing.** A successful result authenticates the bytes; it
  does not validate the payload shape. Decode and validate with your own tools
  after `result.ok` is true.
- **Mount adapters before body parsers.** Express and Hono middleware read the
  raw body or an unconsumed stream. See
  [framework adapters](../README.md#framework-adapters) and the
  [generated-file guidance](cli.md#generated-files).
- **Keep the clock at ingress.** Request-reading APIs and adapters capture the
  clock before consuming the body. Freshness applies to signed timestamps only;
  body-only providers have no authenticated timestamp.

## Generate a handler with the CLI

The CLI requires a built copy of the package to be installed. `npx --no-install`
refuses to fetch a package from the registry, so it will fail if Hooklatch is
not already installed.

<!-- hooklatch:example:cli-help -->
```bash
npx --no-install hooklatch --help
```

`--help` prints usage and exits 0. A dry run validates the arguments and the
target path, then prints the relative target path and the generated file
contents without writing anything:

<!-- hooklatch:example:cli-dry-run -->
```bash
npx --no-install hooklatch init webhook --provider github --framework express --dry-run
```

Remove `--dry-run` only when you have chosen the provider, framework and output
directory deliberately. Real generation writes one file and refuses to replace
an existing file. It does not verify webhooks, start a server, install packages
or talk to the network. See the [CLI reference](cli.md) for flags, paths,
environment names and filesystem limits.

## Providers and evidence

Hooklatch exposes 21 provider IDs through one asynchronous API. Algorithms are
fixed per provider: nineteen use HMAC-SHA256, Vercel uses HMAC-SHA1, and fal
uses Ed25519. Request data cannot select the algorithm. See the
[supported protocols table](../README.md#supported-protocols) and the
[provider guide](providers.md).

Evidence has distinct classes, and they should not be merged into one
conformance claim:

- [Reference vectors and local synthetic fixtures](verification-evidence.md#21-provider-evidence-matrix)
  cover all 21 provider IDs.
- Four pinned vendor SDK comparisons are
  [historical offline evidence](verification-evidence.md#historical-pinned-sdk-differential-comparisons)
  from an earlier commit. They are not a fresh comparison, not a 21-SDK
  conformance result, and not live vendor interoperability.
- Every provider's sandbox delivery status remains
  [`not-run`](verification-evidence.md#21-provider-evidence-matrix).
  Local tests and SDK comparisons do not establish that a live provider delivery
  was received or accepted.

## Troubleshooting

### `Cannot find module 'hooklatch'` or a registry 404

Check that `hooklatch` is listed in your `package.json` dependencies and that
`npm install` completed. Hooklatch requires Node.js 22 or later.

### The package resolves but `dist/...` is missing

You are probably using an unbuilt checkout. Run `npm ci` and `npm run build`,
then pack and install the tarball. Do not deep-import `dist` files or rely on
`main`; use the six public subpaths only. See
[public entrypoints](api-stability.md#public-entrypoints).

### An optional peer is missing

`express` and `hono` are needed only by applications that use those frameworks.
The `hooklatch/express` and `hooklatch/hono` adapters import the peer for types
only, so loading the adapter itself does not fail when the peer is absent; your
application supplies its own `express` or `hono` installation. The core and
diagnostics entries do not load either peer. The Next.js and Cloudflare adapters
do not require a framework peer. See [adapters and optional peers](compatibility.md#adapters-and-optional-peers).

### A broad `Provider` value does not type-check

`VerifyOptions` is a provider-discriminated union. Calls that name a concrete
provider keep their previous shape. A value typed as the full `Provider` union
plus `secrets` must be narrowed first, because it could be `fal` or a configured
provider. Use a switch, a constrained generic, or `satisfies` on a literal
object. See
[broad `Provider` values must be narrowed](api-stability.md#broad-provider-values-must-be-narrowed)
and the [source typing migration impact](diagnostics.md#source-typing-migration-impact).

### The raw body was already parsed

Pass the exact bytes, not a parsed object. Mount the adapter before any JSON body
parser; the Express and Hono adapters read the existing raw buffer or an
unconsumed stream and never reconstruct bytes from a parsed object. See
[framework adapters](../README.md#framework-adapters) and
[generated files](cli.md#generated-files).

### Timestamps behave differently by provider

Only providers with a signed timestamp enforce freshness. Body-only protocols
have no authenticated timestamp, so signature verification alone does not stop
replay. Linear authenticates the body signature but does not parse
`webhookTimestamp` or check its freshness; unsigned headers cannot establish
freshness. `toleranceSeconds` is an inclusive window, and `now` exists for
tests. See [Linear signature authentication](providers.md#linear-signature-authentication),
[verification failure reasons](diagnostics.md#verification-failure-reasons) and
[`verify` options](../README.md#core-api).

### fal configuration fails

fal uses 1 to 16 raw 32-byte Ed25519 public keys plus a required
`expectedUserId`. It has no shared-secret arm, no JWKS fetch and no key URL from
request data. Signature verification runs before account matching and freshness.
See [portable fal credentials](credential-recipes.md#portable-fal-credentials)
and the [fal webhook signature](providers.md#fal-webhook-signature).

### Grafana or Polar configuration fails

Grafana requires an explicit mode; there is no implicit layout. Polar uses one
secret interpretation for every secret in a verifier, with no mixed-era
rotation. See the [Grafana recipes](credential-recipes.md#grafana-recipes),
[Polar recipes](credential-recipes.md#polar-recipes) and
[configured provider protocols](providers.md#configured-provider-protocols).
Those pages hold the per-provider details; this guide does not duplicate them.

## Limits

- Verification is authentication only. It does not parse payloads, validate
  schemas, deduplicate deliveries, guarantee exactly-once business effects, or
  provide queues, retries, DLQ or alerting.
- It does not provide replay immunity beyond signed-timestamp freshness where a
  provider actually signs a timestamp. Body-only protocols need application
  policy after a successful result.
- Node.js 18 and 20 are not supported. There is no universal bundler, browser,
  Deno or Bun claim.
- No live provider or sandbox delivery evidence is claimed. The four historical
  SDK comparisons are not a 21-SDK conformance claim.
- Relay and separate delivery integrations are not part of this package. A
  future separately installed Relay package is a proposal, not an available or
  published component.

## Next steps

- [Module compatibility](compatibility.md) — Node ESM/CommonJS, entrypoints and
  type settings.
- [CLI reference](cli.md) — generated files, flags, exit codes and filesystem
  safety.
- [Credential recipes](credential-recipes.md) — fal, Grafana, Polar and Linear
  configuration examples.
- [Public API stability](api-stability.md) — entrypoints, credential arms,
  migration and the candidate versioning policy.
- [Provider guide](providers.md) — exact headers, signed content and identity
  limits.
- [Diagnostics](diagnostics.md) — static failure guidance and setup error codes.
- [Verification evidence](verification-evidence.md) — measured scope, provenance
  and sandbox status.
- [First release checklist](release-checklist.md) — maintainer-only
  prepublication steps; it does not publish anything.
