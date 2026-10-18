import express from 'express';
import { createWebhookMiddleware } from 'hooklatch/express';

const app = express();
app.post('/hook', createWebhookMiddleware({
  provider: 'github', secrets: ['TEST_synthetic_replace_before_deployment'],
}), (req, res) => {
  // Inferred route Request types must include the adapter's optional property.
  if (!req.webhook) return res.sendStatus(500);
  return res.json({ received: true, bytes: req.webhook.rawBody.byteLength });
});
export default app;
