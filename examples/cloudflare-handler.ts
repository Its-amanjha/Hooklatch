import { createWebhookHandler } from 'hooklatch/cloudflare';

interface Env { GITHUB_SECRET: string }

const fetch = createWebhookHandler<Env>({
  options: (env) => ({ provider: 'github', secrets: [env.GITHUB_SECRET] }),
  handler: (_request, _env, _ctx, success) => {
    // Parse or validate success.rawBody here before applying business effects.
    return Response.json({ received: true, bytes: success.rawBody.byteLength });
  },
});

export default { fetch };
