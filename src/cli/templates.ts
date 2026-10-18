export interface TemplateOptions {
  readonly secretEnv: string;
  readonly bodyLimit: number;
}

export function renderTemplate(provider: string, framework: string, options: TemplateOptions): string {
  const { secretEnv, bodyLimit } = options;

  if (framework === 'express') return expressTemplate(provider, secretEnv, bodyLimit);

  if (framework === 'nextjs') return nextjsTemplate(provider, secretEnv, bodyLimit);

  if (framework === 'hono') return honoTemplate(provider, secretEnv, bodyLimit);

  if (framework === 'cloudflare') return cloudflareTemplate(provider, secretEnv, bodyLimit);
  throw new Error('Unsupported framework.');
}

function expressTemplate(provider: string, secretEnv: string, bodyLimit: number): string {
  return `import { createWebhookMiddleware } from 'hooklatch/express';
import type { VerifyOptions } from 'hooklatch';

// Synthetic placeholder: set ${secretEnv} in your environment before deployment.
const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
  maxBodyBytes: ${bodyLimit},
};

// Mount this middleware before any body parser (express.json, urlencoded, etc.).
export const ${provider}ExpressWebhook = createWebhookMiddleware(options);

// Example mounting:
// app.post('/webhooks/${provider}', ${provider}ExpressWebhook, (req, res) => {
//   const verified = req.webhook;
//   res.status(200).json({ received: true, bytes: verified?.rawBody.byteLength ?? 0 });
// });
`;
}

function nextjsTemplate(provider: string, secretEnv: string, bodyLimit: number): string {
  return `import { createWebhookHandler } from 'hooklatch/nextjs';
import type { VerifyOptions } from 'hooklatch';

const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
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

function honoTemplate(provider: string, secretEnv: string, bodyLimit: number): string {
  return `import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from 'hooklatch/hono';
import type { VerifyOptions } from 'hooklatch';

const options: VerifyOptions = {
  provider: '${provider}',
  secrets: [process.env.${secretEnv}!],
  maxBodyBytes: ${bodyLimit},
};

export const ${provider}HonoWebhook = createWebhookMiddleware(options);

// Mount manually:
// const app = new Hono<{ Variables: WebhookVariables }>();
// app.post('/webhooks/${provider}', ${provider}HonoWebhook, (c) => {
//   const verified = c.get('webhook');
//   return c.json({ received: true, bytes: verified.rawBody.byteLength });
// });
`;
}

function cloudflareTemplate(provider: string, secretEnv: string, bodyLimit: number): string {
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
  }),
  handler: (_request, _env, _ctx, success) => {
    // Verify first, then parse/validate success.rawBody in your own schema.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});

export default { fetch };
`;
}
