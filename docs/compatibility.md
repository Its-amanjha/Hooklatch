# Node.js module compatibility

> **Status: locally qualified development build.** Node ESM and CommonJS use
> one shared implementation. No npm publication is implied. Exact-commit CI
> results are recorded separately after a push; local checks do not imply CI success.

## What the current package supports

The package declares `"type": "module"` and `"engines.node": ">=22"`. All six
public subpaths provide separate Node `import` and `require` conditions.
CommonJS loads real `.cjs` modules; ESM facades expose the same references.

| Runtime | Loading form | State |
| --- | --- | --- |
| Node.js 22 or later | `import` | Qualified on 22.0.0, 22.x and 24.x |
| Node.js 22 or later | `require` | Qualified on 22.0.0, 22.x and 24.x |
| Workers-compatible runtime | ESM | Original graph retained and tested in workerd |
| Node.js 18 and Node.js 20 | either | Not supported |
| Browsers and other runtimes | either | Not claimed |

The CommonJS graph does not depend on `require(esm)`, `module-sync` or runtime
flags. The 22.0.0 floor was executed on Windows and Linux, including Ed25519,
all six entrypoints and the installed ESM CLI.

## How Node selects an entry point

Each of the six public subpaths resolves through
conditional exports in this order:

1. `node`, containing nested `import` and `require` branches. Each branch
   carries its own `types` target before its default target.
2. Top-level `types`, for tools that do not match the `node` condition.
3. Top-level `import`, the original ESM entry.
4. Top-level `default`, also the original ESM entry.

Node evaluates export condition keys in object order, and the `node` condition
matches every Node.js process. Inside it, `import` and `require` are mutually
exclusive: the ESM loader takes `import`, and `require()` takes `require`. A
neutral or Workers target does not match `node`, so it keeps the original ESM
graph instead of the Node CommonJS graph or the Node facade. See
[Conditional exports](https://nodejs.org/docs/latest-v22.x/api/packages.html#conditional-exports)
and [Nested conditions](https://nodejs.org/docs/latest-v22.x/api/packages.html#nested-conditions)
in the Node.js v22.x Packages documentation.

The `types` condition is read by TypeScript, not by Node. The Node.js
documentation lists it under
[Community Conditions Definitions](https://nodejs.org/docs/latest-v22.x/api/packages.html#community-conditions-definitions)
and recommends placing it first, which is why the nested branches put `types`
before their runtime target.

`exports` remains the public contract. Consumers must not import internal
`dist` paths or rely on `main` for legacy resolution. The distribution
keeps one Node implementation per module behind an ESM facade rather than two
independent implementations.

## Same-process identity

On one Node.js process, with one installed copy of the package and one realm,
the `import` and `require` entries expose the same bindings:

- `HooklatchError` is one class. An error created through one loading form
  satisfies `instanceof HooklatchError` when the class was obtained through the
  other loading form.
- `createVerifier`, `verify` and `verifyRequest` from the root, and `diagnose`
  from `hooklatch/diagnostics`, are the same function objects in both loading
  forms.
- Error codes, failure reasons and returned result objects cross the boundary
  without translation.

A separately compiled second implementation would create a second class and
break `instanceof`; that layout is rejected by the compatibility contract. The
Node ESM entry exists as a facade over the CommonJS exports object, so both
forms converge on one module instance.

This identity promise is bounded:

- It applies to Node.js loading, not to an arbitrary bundler that rewrites
  conditions or inlines duplicate copies.
- It does not cross realms or isolates, including `worker_threads`, `vm`
  contexts and separate platform isolates.
- It does not apply across separate installed copies, duplicated package
  trees, different package versions or different platform builds.

## Examples

The JavaScript examples use `import` in ESM files and `require` in CommonJS
files. The TypeScript examples use `import` in `.mts` files and TypeScript's
`import ... = require(...)` form in `.cts` files; a plain `require()` call in a
TypeScript file is not the qualified form, and adding `esModuleInterop` does
not create a CommonJS entry point.

### ESM JavaScript (`.mjs`)

Use `import` in `.mjs` files, or in `.js` files inside a `"type": "module"`
package. This is the current supported form and remains unchanged.

<!-- doc-example: esm-javascript -->
```js
import { createVerifier, HooklatchError } from 'hooklatch';
const verifier = createVerifier({ provider: 'github', secrets: ['synthetic-example-only'] });
const setupError = new HooklatchError('invalid-input', 'Example only.');
void verifier;
void setupError;
```

### CommonJS JavaScript (`.cjs`)

Use `require` in `.cjs` files, or in `.js` files inside a `"type": "commonjs"`
package. This form resolves to the canonical Node CommonJS graph.

<!-- doc-example: cjs-javascript -->
```js
const { createVerifier, HooklatchError } = require('hooklatch');
const verifier = createVerifier({ provider: 'github', secrets: ['synthetic-example-only'] });
const setupError = new HooklatchError('invalid-input', 'Example only.');
void verifier;
void setupError;
```

### ESM TypeScript (`.mts`)

`.mts` files are always ESM. With `"module": "nodenext"` and
`"moduleResolution": "nodenext"`, this import resolves the Node ESM branch and
its declarations.

<!-- doc-example: esm-typescript -->
```ts
import { createVerifier, type VerifyOptions } from 'hooklatch';
const options = { provider: 'github', secrets: ['synthetic-example-only'] } satisfies VerifyOptions;
const verifier = createVerifier(options);
void verifier;
```

### CommonJS TypeScript (`.cts`)

`.cts` files are always CommonJS. `import ... = require(...)` resolves the
`require` branch and the `.d.cts` declarations, and the imported namespace
carries both values and types such as `hooklatch.VerifyOptions`. This form
depends on condition-aware TypeScript settings; it is not promised for
arbitrary compiler configurations.

<!-- doc-example: cjs-typescript -->
```ts
import hooklatch = require('hooklatch');
const options = { provider: 'github', secrets: ['synthetic-example-only'] } satisfies hooklatch.VerifyOptions;
const verifier = hooklatch.createVerifier(options);
void verifier;
```

During qualification, the `.mts` and `.cts` samples compile
against the installed package with strict NodeNext settings. The `.mjs` and
`.cjs` samples run in the mixed-format runtime gate, which also
checks exact raw body bytes, error ordering and same-process identity.

## TypeScript settings

The supported TypeScript shape for the CommonJS entry is the NodeNext pair:

- `"module": "nodenext"`
- `"moduleResolution": "nodenext"`

Node16 module and resolution settings are also condition-aware and belong to
the planned type gate, but NodeNext is the documented setting for the samples
above. The type declarations must come from the installed package; do not point
`paths` at internal `dist` files or copy `.d.ts`/`.d.cts` files into your
project. Qualification compiles consumers with `skipLibCheck: false`. See the TypeScript handbook's
[Node16/NodeNext resolution](https://www.typescriptlang.org/docs/handbook/modules/reference.html#node16-nodenext).

Settings and helpers that do not establish CommonJS support:

- `"moduleResolution": "node"` or `"node10"` is not condition-aware and is not
  covered.
- A default import plus `esModuleInterop` or `allowSyntheticDefaultImports` is
  not a substitute for the `require` entry and can hide a wrong import shape.
- `"module": "commonjs"` combined with `.mts`, or a `bundler` resolution mode
  used for Node `require`, is outside the qualified configuration.
- The samples use `satisfies`, which requires TypeScript 4.9 or later. The
  package's compatibility toolchain is TypeScript 6.0.3; other compiler
  versions are not promised.

## Workers and other neutral ESM runtimes

Workers is unchanged. The original ESM graph remains the neutral build, and
adaptive runtimes keep selecting it because their condition set does not
include `node`. Hooklatch's core and Workers adapters do not require Node
built-ins, Node polyfills or the Node CommonJS graph. A Workers bundler should
not alias `hooklatch` to `dist/cjs`, add a `node` condition, or force a Node
platform target for the SDK.

This is not a universal bundler guarantee. Bundlers differ in which conditions
they set, how they deduplicate modules and whether they rewrite package
exports. Confirm your tool resolves the top-level ESM entry and keeps one copy
of the package; report any divergence rather than assuming the Node identity
rules apply.

## CLI

The `hooklatch` CLI remains an ESM program with the existing `bin` entry. It is
invoked by the shell through `npx --no-install hooklatch`, an npm script or a
global install, and shell invocation is independent of whether your application
is ESM or CommonJS. There is no `require('hooklatch/cli')` public entry and no
new CLI flag for module formats. See the [CLI reference](cli.md).

## Adapters and optional peers

The six public entries keep their current boundaries: root, `diagnostics`,
`express`, `nextjs`, `cloudflare` and `hono`. Express and Hono remain optional
peer dependencies; the core and diagnostics entries do not load either peer.
CommonJS support does not install a peer, convert a peer to a required
dependency, or add a Node shim to the Workers adapters. A CommonJS adapter
import still needs its peer installed and supported by the application.

## Providers and credentials are unchanged

The provider surface does not change: the same 21 IDs, in the same order, with
the same algorithms and the same credential arms. The first nineteen use
HMAC-SHA256, `vercel` uses HMAC-SHA1, and `fal` uses Ed25519. Request data
never selects the algorithm. The [supported protocols table](../README.md#supported-protocols)
and the [provider guide](providers.md) remain authoritative.

Credentials are also unchanged:

- `fal` uses static trusted raw 32-byte Ed25519 public keys (1 to 16 entries)
  and a required `expectedUserId`. It has no shared-secret arm, no JWKS fetch
  and no key URL from request data.
- Vercel keeps its scoped HMAC-SHA1 verification over the exact body.
- Grafana and Polar keep their existing configured options and secret modes.
- HMAC providers keep their accept-set rotation behavior.

Module format does not change exact-byte verification, freshness checks,
identity fields, failure reasons or setup error codes. See the
[credential arms](api-stability.md#credential-arms) for the typed contract and
[credential recipes](credential-recipes.md) for configuration examples.

## Typing compatibility

CommonJS support does not widen `VerifyOptions` and does not add a default
export. A broad `Provider` value combined with `secrets` is still rejected,
because the value could be `fal` or a configured provider; narrow it with a
switch, a constrained generic or `satisfies` on a literal object. See
[Broad `Provider` values must be narrowed](api-stability.md#broad-provider-values-must-be-narrowed)
and the [source typing migration impact](diagnostics.md#source-typing-migration-impact).

`VerifyOptions` remains a union of intersections, so `interface Extended
extends VerifyOptions` is still rejected with TS2312. Use narrowing or an
intersection type alias instead; see
[Interface extension is not a supported migration](api-stability.md#interface-extension-is-not-a-supported-migration).
With the `.cts` form, read value and type exports from the imported namespace,
as in the sample above.

## Migration checklist

1. Keep Node.js 22 or later. Node.js 22.0.0 is within the engine promise; Node
   18 and 20 are not supported.
2. In JavaScript, choose `import` for ESM files and `require` for CommonJS
   files. Do not mix the two forms in one file.
3. In TypeScript, use `.mts` with `import` and `.cts` with
   `import ... = require(...)`, with NodeNext module and resolution settings.
4. Keep the application on one installed copy of Hooklatch. Avoid bundler
   configurations that duplicate the package or apply Node conditions to a
   neutral runtime.
5. Keep provider, secret, public-key and account configuration as it is.
   Module format is not a credential migration.
6. Workers applications stay on the original ESM entry and do not need Node
   polyfills.
7. Do not deep-import `dist` files or rely on `main`; use the six public
   subpaths only.

## Limits

The following are explicitly outside this compatibility design:

- Node.js 18 and Node.js 20 support, backports or engine lowering.
- `require(esm)`, `"module-sync"`, `--experimental-require-module` or any
  loader flag as a substitute for the CommonJS graph.
- Cross-realm, cross-thread, cross-version or cross-installation class
  identity.
- A universal bundler, browser, Deno or Bun support claim.
- `.cts` or `.mts` compilation under arbitrary TypeScript module settings.
- A CommonJS entry for the CLI.
- New providers, algorithms, parsing behavior, token authentication, Relay or
  JWKS networking.
- An npm publication or a support promotion before integration.

## Promotion checklist

The status at the top of this page changes only after the coordinator records:

1. A production Node distribution build from current source, with repeat builds
   producing byte-identical Node outputs and no partial graph reported as
   success.
2. Packed declaration checks for the six public entries in `.mts` and `.cts`
   forms, with strict NodeNext/Node16 resolution and `skipLibCheck: false`.
3. Runtime checks on the actual Node.js 22.0.0 floor and on the supported 22.x
   and 24.x lines, covering both loading forms, exact bytes, identity, error
   ordering and the unchanged provider contracts.
4. Workers and framework qualification against the original ESM entry, with no
   Node shim in the Workers path.
5. Conditional-exports and tarball contract checks, including negative deep
   imports.
6. A serial `npm run verify` on the integrated commit and an exact-SHA Node 22
   and 24 CI run.

Local evidence does not replace an exact-SHA remote CI run or a publication
decision. The checklist remains the acceptance policy for future changes.

## References

Node.js v22.x documentation (page version 22.23.4), primary sources for the
condition mechanics:

- [Modules: Packages](https://nodejs.org/docs/latest-v22.x/api/packages.html#modules-packages)
- [Determining module system](https://nodejs.org/docs/latest-v22.x/api/packages.html#determining-module-system)
- [Package entry points](https://nodejs.org/docs/latest-v22.x/api/packages.html#package-entry-points)
- [Conditional exports](https://nodejs.org/docs/latest-v22.x/api/packages.html#conditional-exports)
- [Nested conditions](https://nodejs.org/docs/latest-v22.x/api/packages.html#nested-conditions)
- [Community Conditions Definitions](https://nodejs.org/docs/latest-v22.x/api/packages.html#community-conditions-definitions)
- [Dual CommonJS/ES module packages](https://nodejs.org/docs/latest-v22.x/api/packages.html#dual-commonjses-module-packages)
- [Modules: ECMAScript modules: Interoperability with CommonJS](https://nodejs.org/docs/latest-v22.x/api/esm.html#interoperability-with-commonjs)
- [Modules: CommonJS modules: Loading ECMAScript modules using require](https://nodejs.org/docs/latest-v22.x/api/modules.html#loading-ecmascript-modules-using-require)
  (listed only to scope it out; the CommonJS entry does not depend on it)

TypeScript documentation:

- [Node16/NodeNext resolution](https://www.typescriptlang.org/docs/handbook/modules/reference.html#node16-nodenext)

Package documentation:

- [Public entrypoints](api-stability.md#public-entrypoints)
- [Provider guide](providers.md)
- [CLI reference](cli.md)
