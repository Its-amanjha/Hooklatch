# Hooklatch CLI

The `hooklatch` CLI generates a single TypeScript webhook endpoint file from
the adapters already shipped in this package. It does not verify webhooks,
start servers, install packages, or talk to the network.

## Usage

```text
hooklatch init webhook --provider <id> --framework <id> [--out <dir>]
  [--secret-env <NAME>] [--body-limit <bytes>] [--dry-run]
```

### Required flags

- `--provider <id>` — an implemented provider id: `stripe`, `github`,
  `shopify`, `standard-webhooks`, `clerk`, or `svix`. The list comes from the
  package's internal provider registry; pending providers are not accepted.
- `--framework <id>` — one of `express`, `nextjs`, `hono`, `cloudflare`.

### Optional flags

- `--out <dir>` — output directory, relative to the current working
  directory. Default: `hooklatch`.
- `--secret-env <NAME>` — environment variable the generated file reads the
  signing secret from. Must match `/^[A-Za-z_][A-Za-z0-9_]*$/`. Defaults per
  provider: `STRIPE_WEBHOOK_SECRET`, `GITHUB_WEBHOOK_SECRET`,
  `SHOPIFY_WEBHOOK_SECRET`, `STANDARD_WEBHOOKS_SECRET`,
  `CLERK_WEBHOOK_SIGNING_SECRET`, `SVIX_WEBHOOK_SECRET`.
- `--body-limit <bytes>` — positive safe integer body limit baked into the
  generated options. Default: `1048576`.
- `--dry-run` — validate arguments and the target path, then print the
  relative target path and the file contents without writing anything.
- `-h`, `--help` — print usage and exit 0.

Duplicate flags, unknown flags, missing values, unknown providers/frameworks,
non-integer or non-positive body limits, and malformed `--secret-env` names
are all rejected before any filesystem change.

## Generated files

One file per invocation, named by framework:

| Framework   | File name                 | Export                                             |
| ----------- | ------------------------- | -------------------------------------------------- |
| `express`   | `<provider>.express.ts`   | `createWebhookMiddleware` middleware               |
| `hono`      | `<provider>.hono.ts`      | `createWebhookMiddleware` middleware               |
| `cloudflare`| `<provider>.cloudflare.ts`| fetch handler (`export default { fetch }`)          |
| `nextjs`    | `route.ts`                | `export const POST` from `createWebhookHandler`    |

Generated files read the secret from the chosen environment variable at
runtime; no secret values are embedded. JSON parsing of `rawBody` remains the
caller's post-verification concern. Mount generated middleware before any
body parser in Express, and place `route.ts` in your route directory (for
example `--out app/api/webhooks/stripe`).

## Filesystem safety

- Output is constrained to the current working directory: parent segments
  (`..`), absolute paths, drive letters, UNC paths, `.git`/`node_modules`
  components, NUL bytes, and Windows reserved device names are rejected.
- Spaces and Unicode in directory names are allowed.
- Existing symlink or junction components in the target path are rejected;
  the CLI never follows symlinks.
- An existing target file is always refused (exit 3), even when its contents
  would match. Files are created exclusively; a failed generation never
  replaces another creator's file.

## Exit codes

- `0` — success, dry run, or help.
- `1` — unexpected generation or I/O error.
- `2` — invalid arguments or unsafe path.
- `3` — target file already exists.

Error output is a single static summary line on stderr: no stack traces, no
absolute paths, and no secret environment variable values.
