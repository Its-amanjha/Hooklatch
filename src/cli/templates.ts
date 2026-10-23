import type { ProviderCliOptions } from './args.js';

export type TemplateOptions =
  | { readonly secretEnv: string; readonly bodyLimit: number; readonly providerOptions?: ProviderCliOptions }
  | { readonly publicKeyEnv: string; readonly expectedUserEnv: string; readonly bodyLimit: number; readonly providerOptions?: ProviderCliOptions };

export function renderTemplate(provider: string, framework: string, options: TemplateOptions): string {
  if ('publicKeyEnv' in options) {
    return falTemplate(provider, framework, options.publicKeyEnv, options.expectedUserEnv, options.bodyLimit);
  }

  const { secretEnv, bodyLimit, providerOptions } = options;

  if (framework === 'express') return expressTemplate(provider, secretEnv, bodyLimit, providerOptions);

  if (framework === 'nextjs') return nextjsTemplate(provider, secretEnv, bodyLimit, providerOptions);

  if (framework === 'hono') return honoTemplate(provider, secretEnv, bodyLimit, providerOptions);

  if (framework === 'cloudflare') return cloudflareTemplate(provider, secretEnv, bodyLimit, providerOptions);

  throw new Error('Unsupported framework.');
}

function expressTemplate(
  provider: string,
  secretEnv: string,
  bodyLimit: number,
  providerOptions: ProviderCliOptions | undefined,
): string {
  const identifier = provider.replaceAll('-', '_');

  const providerOptionsLine = renderProviderOptionsLine(providerOptions, '  ');

  return `import { createWebhookMiddleware } from 'hooklatch/express';
import type { VerifyOptions } from 'hooklatch';

// Synthetic placeholder: set ${secretEnv} in your environment before deployment.
const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
  maxBodyBytes: ${bodyLimit},
${providerOptionsLine}};

// Mount this middleware before any body parser (express.json, urlencoded, etc.).
export const ${identifier}ExpressWebhook = createWebhookMiddleware(options);

// Example mounting:
// app.post('/webhooks/${provider}', ${identifier}ExpressWebhook, (req, res) => {
//   const verified = req.webhook;
//   res.status(200).json({ received: true, bytes: verified?.rawBody.byteLength ?? 0 });
// });
`;
}

function nextjsTemplate(
  provider: string,
  secretEnv: string,
  bodyLimit: number,
  providerOptions: ProviderCliOptions | undefined,
): string {
  const providerOptionsLine = renderProviderOptionsLine(providerOptions, '  ');

  return `import { createWebhookHandler } from 'hooklatch/nextjs';
import type { VerifyOptions } from 'hooklatch';

const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
  maxBodyBytes: ${bodyLimit},
${providerOptionsLine}};

export const POST = createWebhookHandler({
  ...options,
  handler: (_request, success) => {
    // Verify first, then parse/validate success.rawBody in your own schema.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});
`;
}

function honoTemplate(
  provider: string,
  secretEnv: string,
  bodyLimit: number,
  providerOptions: ProviderCliOptions | undefined,
): string {
  const identifier = provider.replaceAll('-', '_');

  const providerOptionsLine = renderProviderOptionsLine(providerOptions, '  ');

  return `import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from 'hooklatch/hono';
import type { VerifyOptions } from 'hooklatch';

const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
  maxBodyBytes: ${bodyLimit},
${providerOptionsLine}};

export const ${identifier}HonoWebhook = createWebhookMiddleware(options);

// Mount manually:
// const app = new Hono<{ Variables: WebhookVariables }>();
// app.post('/webhooks/${provider}', ${identifier}HonoWebhook, (c) => {
//   const verified = c.get('webhook');
//   return c.json({ received: true, bytes: verified.rawBody.byteLength });
// });
`;
}

function cloudflareTemplate(
  provider: string,
  secretEnv: string,
  bodyLimit: number,
  providerOptions: ProviderCliOptions | undefined,
): string {
  const providerOptionsLine = renderProviderOptionsLine(providerOptions, '    ');

  return `import { createWebhookHandler } from 'hooklatch/cloudflare';
import type { VerifyOptions } from 'hooklatch';

interface Env {
  ${secretEnv}: string;
}

export const fetch = createWebhookHandler<Env>({
  options: (env) => ({
    provider: '${provider}',
    secrets: [env.${secretEnv}],
    maxBodyBytes: ${bodyLimit},
${providerOptionsLine}  }),
  handler: (_request, _env, _ctx, success) => {
    // Verify first, then parse/validate success.rawBody in your own schema.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});

export default { fetch };
`;
}

function falDecoder(publicKeyEnv: string): string {
  return `function decodePublicKeys(value: string): Uint8Array[] {
  if (value.length === 0) throw new Error('${publicKeyEnv}' + ' must not be empty');

  const entries = value.split(',');

  if (entries.length < 1 || entries.length > 16) {
    throw new Error('${publicKeyEnv}' + ' must contain 1 to 16 keys');
  }

  return entries.map((entry, index) => {
    if (entry.length === 0) throw new Error('${publicKeyEnv}' + ' entry ' + index + ' is blank');

    if (!/^[A-Za-z0-9_-]+$/.test(entry)) {
      throw new Error('${publicKeyEnv}' + ' entry ' + index + ' is not valid Base64url');
    }

    let base64 = entry.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    base64 += '='.repeat(padLength);

    let binary: string;

    try {
      binary = atob(base64);
    } catch {
      throw new Error('${publicKeyEnv}' + ' entry ' + index + ' is invalid Base64');
    }

    if (btoa(binary) !== base64) {
      throw new Error('${publicKeyEnv}' + ' entry ' + index + ' is not canonical Base64url');
    }

    if (binary.length !== 32) {
      throw new Error('${publicKeyEnv}' + ' entry ' + index + ' must decode to 32 bytes');
    }

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    return bytes;
  });
}`;
}

function falTemplate(provider: string, framework: string, publicKeyEnv: string, expectedUserEnv: string, bodyLimit: number): string {
  const identifier = provider.replaceAll('-', '_');

  if (framework === 'express') {
    return `import { createWebhookMiddleware } from 'hooklatch/express';
import type { VerifyOptions } from 'hooklatch';

// Synthetic placeholder: set ${publicKeyEnv} and ${expectedUserEnv} in your
// environment before deployment. Keys are comma-separated canonical Base64url
// (no padding), each decoding to exactly 32 bytes, 1 to 16 entries.

${falDecoder(publicKeyEnv)}

const options: VerifyOptions = {
  provider: '${provider}',
  publicKeys: decodePublicKeys(process.env.${publicKeyEnv}!),
  expectedUserId: process.env.${expectedUserEnv}!,
  maxBodyBytes: ${bodyLimit},
};

// Mount this middleware before any body parser (express.json, urlencoded, etc.).
export const ${identifier}ExpressWebhook = createWebhookMiddleware(options);

// Example mounting:
// app.post('/webhooks/${provider}', ${identifier}ExpressWebhook, (req, res) => {
//   const verified = req.webhook;
//   res.status(200).json({ received: true, bytes: verified?.rawBody.byteLength ?? 0 });
// });
`;
  }

  if (framework === 'nextjs') {
    return `import { createWebhookHandler } from 'hooklatch/nextjs';
import type { VerifyOptions } from 'hooklatch';

${falDecoder(publicKeyEnv)}

const options: VerifyOptions = {
  provider: '${provider}',
  publicKeys: decodePublicKeys(process.env.${publicKeyEnv}!),
  expectedUserId: process.env.${expectedUserEnv}!,
  maxBodyBytes: ${bodyLimit},
};

export const POST = createWebhookHandler({
  ...options,
  handler: (_request, success) => {
    // Verify first, then parse/validate success.rawBody in your own schema.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});
`;
  }

  if (framework === 'hono') {
    return `import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from 'hooklatch/hono';
import type { VerifyOptions } from 'hooklatch';

${falDecoder(publicKeyEnv)}

const options: VerifyOptions = {
  provider: '${provider}',
  publicKeys: decodePublicKeys(process.env.${publicKeyEnv}!),
  expectedUserId: process.env.${expectedUserEnv}!,
  maxBodyBytes: ${bodyLimit},
};

export const ${identifier}HonoWebhook = createWebhookMiddleware(options);

// Mount manually:
// const app = new Hono<{ Variables: WebhookVariables }>();
// app.post('/webhooks/${provider}', ${identifier}HonoWebhook, (c) => {
//   const verified = c.get('webhook');
//   return c.json({ received: true, bytes: verified.rawBody.byteLength });
// });
`;
  }

  if (framework === 'cloudflare') {
    return `import { createWebhookHandler } from 'hooklatch/cloudflare';
import type { VerifyOptions } from 'hooklatch';

interface Env {
  ${publicKeyEnv}: string;
  ${expectedUserEnv}: string;
}

${falDecoder(publicKeyEnv)}

export const fetch = createWebhookHandler<Env>({
  options: (env) => ({
    provider: '${provider}',
    publicKeys: decodePublicKeys(env.${publicKeyEnv}),
    expectedUserId: env.${expectedUserEnv},
    maxBodyBytes: ${bodyLimit},
  }),
  handler: (_request, _env, _ctx, success) => {
    // Verify first, then parse/validate success.rawBody in your own schema.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});

export default { fetch };
`;
  }

  throw new Error('Unsupported framework.');
}


/**
 * Render one `providerOptions` property line, or nothing for providers without
 * typed configuration. Existing provider output stays byte-identical.
 */
function renderProviderOptionsLine(providerOptions: ProviderCliOptions | undefined, indent: string): string {
  if (providerOptions === undefined) return '';

  if (providerOptions.provider === 'grafana') {
    const { mode, signatureHeader, timestampHeader } = providerOptions.options;
    const entries = [`mode: ${quoteStringLiteral(mode)}`];

    if (signatureHeader !== undefined) entries.push(`signatureHeader: ${quoteStringLiteral(signatureHeader)}`);

    if (timestampHeader !== undefined) entries.push(`timestampHeader: ${quoteStringLiteral(timestampHeader)}`);

    return `${indent}providerOptions: { ${entries.join(', ')} },\n`;
  }

  if (providerOptions.provider === 'polar') {
    return `${indent}providerOptions: { secretMode: ${quoteStringLiteral(providerOptions.options.secretMode)} },\n`;
  }

  return '';
}

/**
 * Serialize a configuration value as a double-quoted TypeScript string. Header
 * names are RFC 9110 tokens, but escaping is still explicit so accepted values
 * such as apostrophes and backticks cannot change generated syntax.
 */
function quoteStringLiteral(value: string): string {
  let literal = '"';

  for (const character of value) {
    const code = character.charCodeAt(0);

    if (character === '\\') literal += '\\\\';
    else if (character === '"') literal += '\\"';
    else if (character === '\n') literal += '\\n';
    else if (character === '\r') literal += '\\r';
    else if (character === '\t') literal += '\\t';
    else if (code < 0x20 || code === 0x7f || character === '\u2028' || character === '\u2029') {
      literal += `\\u${code.toString(16).padStart(4, '0')}`;
    } else literal += character;
  }

  return `${literal}"`;
}
