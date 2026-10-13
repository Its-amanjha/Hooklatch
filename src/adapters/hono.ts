import type { MiddlewareHandler } from 'hono';
import { verifyRequest } from '../index.js';
import type { VerificationSuccess, VerifyOptions } from '../types.js';

declare module 'hono' {
  interface ContextVariableMap {
    webhook?: VerificationSuccess;
  }
}

export type WebhookVariables = { webhook: VerificationSuccess };

export function createWebhookMiddleware(options: VerifyOptions): MiddlewareHandler {
  return async (c, next) => {
    try {
      const encoding = c.req.raw.headers.get('content-encoding');
      if (encoding && encoding.toLowerCase() !== 'identity') {
        return c.text('Bad Request', 400);
      }
      const result = await verifyRequest(c.req.raw, options);
      if (!result.ok) {
        if (result.reason === 'body-too-large') {
          return c.text('Payload Too Large', 413);
        }
        return c.text('Bad Request', 400);
      }
      c.set('webhook', result);
    } catch (err) {
      if (err instanceof Error && err.name === 'TernError') {
        return c.text('Internal Server Error', 500);
      }
      throw err;
    }
    await next();
  };
}
