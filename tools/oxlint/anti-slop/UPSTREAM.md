# Vendored anti-slop rules

Source: https://github.com/dmmulroy/anti-slop

Revision: `13909c9e07590f5a85d93c62712259fe14a883f7`.

Copied on 2026-10-19 using that revision's
`skills/install-anti-slop/scripts/install.mjs`. The actual source assets are
`skills/install-anti-slop/assets/anti-slop/` at the same revision. This is the
first installation; no existing local rule implementation was replaced.

Installed entry point: `tools/oxlint/anti-slop/index.ts`. The generic rules run
through `.oxlintrc.json` with matching exact development dependencies
`oxlint@1.88.0` and `@oxlint/plugins@1.88.0`, queried from npm at installation.
The core package has no added runtime dependency. ESLint remains in use.

All generic rules and `oxc/no-accumulating-spread` are enabled as errors.
`no-runtime-typeof` uses its supported `allowInTypeGuards: true` option: this SDK
must validate untrusted JavaScript/HTTP inputs at boundaries, using named
predicates with actual contract checks. Runtime checks elsewhere remain errors.
No active rule implementation or severity has been weakened. On 2026-10-19,
the seven unused opt-in Effect files were removed from the local copy because
Hooklatch has no direct Effect dependency. The generic plugin is unchanged.

The rule sources otherwise match the pinned skill assets. The root source MIT
license is retained here as `LICENSE`. Nested
`vendor/eslint-stylistic/LICENSE` and `vendor/eslint-stylistic/UPSTREAM.md` retain
the upstream stylistic rule's own license and provenance. These tooling files
are excluded from linting themselves and from the SDK's npm package.
