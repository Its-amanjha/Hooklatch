/**
 * Express adapter: raw bytes, middleware ordering, compression rejection.
 *
 * Uses the implemented contract v1 adapter and root public types.
 *
 * Key rules:
 * - Mount createWebhookMiddleware BEFORE any body-parser middleware.
 * - The adapter reads the existing raw Buffer/Uint8Array or an unconsumed
 *   request stream; it never reconstructs bytes from a parsed object.
 * - Unsupported compressed bodies are rejected explicitly (no implicit
 *   decompression policy).
 * - Success attaches the result to req.webhook and calls next().
 * - Verification failures respond 400; setup failures 500.
 * - User handler errors follow Express; they are never signature failures.
 */

import type { Express, Request, Response, NextFunction } from 'express';
import { createWebhookMiddleware } from 'hooklatch/express';
import type { VerifyOptions } from 'hooklatch';
import { isIdentifiedEvent } from './event-validation.js';

// Synthetic placeholder — replace with your real secret.
const TEST_SECRET = 'TEST0express0secret0placeholder';

const options: VerifyOptions = {
  provider: 'stripe',
  secrets: [TEST_SECRET],
  maxBodyBytes: 1048576,
};

/**
 * Express app setup.
 *
 * IMPORTANT: The webhook route must be registered before any global
 * body-parser middleware (express.json(), express.urlencoded(), etc.).
 */
export function setupExpressWebhook(app: Express): void {
  app.post(
    '/webhooks/stripe',
    // Verification middleware — runs before any JSON parser.
    createWebhookMiddleware(options),
    // Handler — req.webhook is the VerificationSuccess.
    (req: Request, res: Response, _next: NextFunction) => {
      const success = req.webhook;

      if (!success) {
        return res.status(500).json({ error: 'Verification did not run' });
      }

      const payload: unknown = JSON.parse(new TextDecoder().decode(success.rawBody));

      if (!isIdentifiedEvent(payload)) {
        return res.status(400).json({ error: 'Expected an event with an id' });
      }

      return res.json({ received: true, id: payload.id });
    },
  );
}
