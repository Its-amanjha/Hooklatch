import { createStandardWebhooksProtocol } from './standard-webhooks-protocol.js';

/**
 * GitLab signing-token mode (introduced in 19.0 behind a default-enabled flag
 * and generally available in 19.1) sends the canonical Standard Webhooks
 * `webhook-id`, `webhook-timestamp` and `webhook-signature` headers. The
 * secret is Base64-decoded (an optional `whsec_` prefix is stripped) and must
 * decode to 24-64 bytes; the signature covers the exact
 * `${webhook-id}.${webhook-timestamp}.` bytes followed by the raw body.
 *
 * The legacy `X-Gitlab-Token` header is a shared string comparison, not an
 * authenticated body signature. It is deliberately ignored: a legacy-token-only
 * request fails closed, and adding that header can neither repair a canonical
 * defect nor change which bytes were authenticated.
 *
 * No GitLab-published signing-token vector is claimed; the direct tests use
 * synthetic anchors. Source:
 * https://docs.gitlab.com/user/project/integrations/webhooks/#signing-tokens
 */
export const gitlabDescriptor = createStandardWebhooksProtocol(
  'gitlab',
  'GitLab',
  {
    id: 'webhook-id',
    timestamp: 'webhook-timestamp',
    signature: 'webhook-signature',
  },
);
