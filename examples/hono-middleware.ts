import { Hono } from 'hono';
import { createWebhookMiddleware, type WebhookVariables } from 'hooklatch/hono';

const app = new Hono<{ Variables: WebhookVariables }>();

app.post('/webhooks/github', createWebhookMiddleware({
  provider: 'github', secrets: ['TEST_synthetic_replace_before_deployment'],
}), (c) => {
  const verified = c.get('webhook');

  return c.json({ received: true, bytes: verified.rawBody.byteLength });
});

export default app;
