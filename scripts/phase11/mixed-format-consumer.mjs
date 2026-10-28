/**
 * Phase 11 — Mixed-format runtime consumer and independent anchor generator.
 *
 * Implements the independent cryptographic anchors for all 21 providers,
 * the 3-API matrix (verify, verifyRequest, createVerifier), both valid and
 * tampered states, and the pinned runtime edge cases:
 *   - Configured Grafana (body and timestamped)
 *   - Polar (current and legacy)
 *   - Fal account mismatch
 *   - Wrong-MAC-before-stale (auth before freshness)
 *   - Explicit-zero tolerance
 *   - Multi-key rotation
 *
 * All signing and anchor verification is independent of the SDK implementation.
 */
import assert from 'node:assert/strict';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createRequire } from 'node:module';

export const PROVIDERS = Object.freeze([
  'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
  'razorpay', 'paddle', 'lemon-squeezy', 'dodo-payments', 'gitlab',
  'replicate', 'workos', 'sentry', 'doppler', 'sanity', 'grafana',
  'polar', 'linear', 'vercel', 'fal',
]);

export const SUBPATHS = Object.freeze([
  { subpath: '.', exports: Object.freeze(['HooklatchError', 'createVerifier', 'verify', 'verifyRequest']) },
  { subpath: './diagnostics', exports: Object.freeze(['diagnose']) },
  { subpath: './express', exports: Object.freeze(['createWebhookMiddleware']) },
  { subpath: './nextjs', exports: Object.freeze(['createWebhookHandler']) },
  { subpath: './cloudflare', exports: Object.freeze(['createWebhookHandler']) },
  { subpath: './hono', exports: Object.freeze(['createWebhookMiddleware']) },
]);

export const FORBIDDEN_SUBPATHS = Object.freeze([
  'hooklatch/package.json',
  'hooklatch/dist/index.js',
  'hooklatch/dist/cjs/index.cjs',
  'hooklatch/dist/node/index.js',
  'hooklatch/src/index.ts',
  'hooklatch/internal/crypto.js',
]);

const FAL_SEED_AUTHENTIC = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex');
const FAL_SEED_SECONDARY = Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex');

function deriveFalKeyPair(seed) {
  const pkcs8Der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privKey = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const pubKey = createPublicKey(privKey);
  const rawPub = new Uint8Array(pubKey.export({ format: 'der', type: 'spki' }).subarray(12));

  return { privKey, pubKey, rawPub };
}

const FAL_KEYS_AUTHENTIC = deriveFalKeyPair(FAL_SEED_AUTHENTIC);
const FAL_KEYS_SECONDARY = deriveFalKeyPair(FAL_SEED_SECONDARY);

/**
 * Builds deterministic independent test anchors for all 21 providers,
 * plus specific pinned cases.
 */
export function buildIndependentAnchors() {
  const now = 1700000000;
  const falNow = 1792742400;
  const cases = [];

  // 1. stripe
  {
    const body = Buffer.from('{"id":"evt_stripe_p11","type":"payment_intent.succeeded"}', 'utf8');
    const secret = 'whsec_stripe_test_secret_p11';
    const signedPayload = Buffer.concat([Buffer.from(`${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');
    cases.push({
      provider: 'stripe',
      name: 'stripe-standard',
      body,
      headers: { 'stripe-signature': `t=${now},v1=${sig}` },
      options: { provider: 'stripe', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // 2. github
  {
    const body = Buffer.from('{"action":"opened","issue":{"number":101}}', 'utf8');
    const secret = 'github_test_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'github',
      name: 'github-standard',
      body,
      headers: { 'x-hub-signature-256': `sha256=${sig}` },
      options: { provider: 'github', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 3. shopify
  {
    const body = Buffer.from('{"id":8209829119283,"email":"shopper@example.invalid"}', 'utf8');
    const secret = 'shopify_test_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('base64');
    cases.push({
      provider: 'shopify',
      name: 'shopify-standard',
      body,
      headers: { 'x-shopify-hmac-sha256': sig },
      options: { provider: 'shopify', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 4. standard-webhooks
  {
    const body = Buffer.from('{"event":"user.created","id":"usr_std_001"}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_std_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'standard-webhooks',
      name: 'standard-webhooks-standard',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: { provider: 'standard-webhooks', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 5. clerk
  {
    const body = Buffer.from('{"data":{"id":"user_clerk_001"},"type":"user.created"}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_clerk_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'clerk',
      name: 'clerk-standard',
      body,
      headers: { 'svix-id': id, 'svix-timestamp': String(now), 'svix-signature': `v1,${sig}` },
      options: { provider: 'clerk', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 6. svix
  {
    const body = Buffer.from('{"event_type":"invoice.paid","app_id":"app_001"}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_svix_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'svix',
      name: 'svix-standard',
      body,
      headers: { 'svix-id': id, 'svix-timestamp': String(now), 'svix-signature': `v1,${sig}` },
      options: { provider: 'svix', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 7. razorpay
  {
    const body = Buffer.from('{"entity":"event","event":"payment.captured"}', 'utf8');
    const secret = 'razorpay_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'razorpay',
      name: 'razorpay-standard',
      body,
      headers: { 'x-razorpay-signature': sig },
      options: { provider: 'razorpay', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 8. paddle
  {
    const body = Buffer.from('{"event_id":"evt_paddle_p11","event_type":"subscription.created"}', 'utf8');
    const secret = 'paddle_secret_p11';
    const signedPayload = Buffer.concat([Buffer.from(`${now}:`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');
    cases.push({
      provider: 'paddle',
      name: 'paddle-standard',
      body,
      headers: { 'paddle-signature': `ts=${now};h1=${sig}` },
      options: { provider: 'paddle', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // 9. lemon-squeezy
  {
    const body = Buffer.from('{"meta":{"event_name":"order_created"}}', 'utf8');
    const secret = 'lemon_squeezy_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'lemon-squeezy',
      name: 'lemon-squeezy-standard',
      body,
      headers: { 'x-signature': sig },
      options: { provider: 'lemon-squeezy', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 10. dodo-payments
  {
    const body = Buffer.from('{"event":"payment_succeeded","data":{"payment_id":"pay_001"}}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_dodo_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'dodo-payments',
      name: 'dodo-payments-standard',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: { provider: 'dodo-payments', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 11. gitlab
  {
    const body = Buffer.from('{"object_kind":"push","project_id":123}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_gitlab_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'gitlab',
      name: 'gitlab-standard',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: { provider: 'gitlab', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 12. replicate
  {
    const body = Buffer.from('{"id":"pred_001","status":"succeeded"}', 'utf8');
    const secret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_replicate_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'replicate',
      name: 'replicate-standard',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: { provider: 'replicate', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 13. workos
  {
    const body = Buffer.from('{"event":"connection.activated","data":{"id":"conn_001"}}', 'utf8');
    const secret = 'workos_secret_p11';
    const nowMs = now * 1000;
    const signedPayload = Buffer.concat([Buffer.from(`${nowMs}.`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');
    cases.push({
      provider: 'workos',
      name: 'workos-standard',
      body,
      headers: { 'workos-signature': `t=${nowMs},v1=${sig}` },
      options: { provider: 'workos', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // 14. sentry
  {
    const body = Buffer.from('{"action":"created","data":{"issue":{"id":"10"}}}', 'utf8');
    const secret = 'sentry_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'sentry',
      name: 'sentry-standard',
      body,
      headers: { 'sentry-hook-signature': sig },
      options: { provider: 'sentry', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 15. doppler
  {
    const body = Buffer.from('{"event":"workplace.updated","type":"v1"}', 'utf8');
    const secret = 'doppler_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'doppler',
      name: 'doppler-standard',
      body,
      headers: { 'x-doppler-signature': `sha256=${sig}` },
      options: { provider: 'doppler', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 16. sanity
  {
    const body = Buffer.from('{"_id":"drafts.item_p11","_type":"article"}', 'utf8');
    const secret = 'sanity_secret_p11';
    const nowMs = now * 1000;
    const signedPayload = Buffer.concat([Buffer.from(`${nowMs}.`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('base64url');
    cases.push({
      provider: 'sanity',
      name: 'sanity-standard',
      body,
      headers: { 'sanity-webhook-signature': `t=${nowMs},v1=${sig}` },
      options: { provider: 'sanity', secrets: [secret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // 17. grafana (body mode in main 21 inventory)
  {
    const body = Buffer.from('{"alert":"cpu_high","state":"alerting"}', 'utf8');
    const secret = 'grafana_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'grafana',
      name: 'grafana-body',
      body,
      headers: { 'x-grafana-alerting-signature': sig },
      options: { provider: 'grafana', secrets: [secret], providerOptions: { mode: 'body' } },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 18. polar (current mode in main 21 inventory)
  {
    const body = Buffer.from('{"type":"subscription.created","data":{"id":"sub_p11"}}', 'utf8');
    const secret = 'whsec_aG9va2xhdGNoX3N0YWdlX2FfcG9sYXJfY3VycmVudF9rZXlfb2xk';
    const rawKey = Buffer.from(secret.slice(6), 'base64');
    const id = 'msg_phase11_polar_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    cases.push({
      provider: 'polar',
      name: 'polar-current',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: { provider: 'polar', secrets: [secret], providerOptions: { secretMode: 'current' }, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // 19. linear
  {
    const body = Buffer.from('{"action":"create","type":"Issue","data":{"id":"LIN-101"}}', 'utf8');
    const secret = 'linear_secret_p11';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    cases.push({
      provider: 'linear',
      name: 'linear-standard',
      body,
      headers: { 'linear-signature': sig },
      options: { provider: 'linear', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 20. vercel
  {
    const body = Buffer.from('{"type":"deployment.ready","payload":{"id":"dpl_p11"}}', 'utf8');
    const secret = 'vercel_secret_p11';
    const sig = createHmac('sha1', secret).update(body).digest('hex');
    cases.push({
      provider: 'vercel',
      name: 'vercel-standard',
      body,
      headers: { 'x-vercel-signature': sig },
      options: { provider: 'vercel', secrets: [secret] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    });
  }

  // 21. fal
  {
    const body = Buffer.from('{"request_id":"req_fal_p11","status":"COMPLETED"}', 'utf8');
    const requestId = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';
    const userId = 'usr_hooklatch_stage11';
    const bodySha = createHash('sha256').update(body).digest('hex');
    const msg = `${requestId}\n${userId}\n${falNow}\n${bodySha}`;
    const sig = sign(null, Buffer.from(msg, 'utf8'), FAL_KEYS_AUTHENTIC.privKey).toString('hex');
    cases.push({
      provider: 'fal',
      name: 'fal-standard',
      body,
      headers: {
        'x-fal-webhook-signature': sig,
        'x-fal-webhook-request-id': requestId,
        'x-fal-webhook-user-id': userId,
        'x-fal-webhook-timestamp': String(falNow),
      },
      options: {
        provider: 'fal',
        publicKeys: [FAL_KEYS_AUTHENTIC.rawPub],
        expectedUserId: userId,
        now: () => falNow,
      },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: falNow, authenticatedFields: ['timestamp'] },
    });
  }

  // Pinned additional variants
  const pinned = [];

  // Pinned: Grafana timestamped mode
  {
    const body = Buffer.from('{"alert":"mem_high","state":"alerting"}', 'utf8');
    const secret = 'grafana_timestamped_secret_p11';
    const signedPayload = Buffer.concat([Buffer.from(`${now}:`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');
    pinned.push({
      provider: 'grafana',
      name: 'grafana-timestamped',
      body,
      headers: { 'x-grafana-alerting-signature': sig, 'x-grafana-timestamp': String(now) },
      options: {
        provider: 'grafana',
        secrets: [secret],
        providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' },
        now: () => now,
      },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // Pinned: Polar legacy mode
  {
    const body = Buffer.from('{"type":"order.created","data":{"id":"ord_legacy_001"}}', 'utf8');
    const secret = 'polar_legacy_secret_literal_p11';
    const rawKey = Buffer.from(secret, 'utf8');
    const id = 'msg_polar_legacy_001';
    const signedPayload = Buffer.concat([Buffer.from(`${id}.${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', rawKey).update(signedPayload).digest('base64');
    pinned.push({
      provider: 'polar',
      name: 'polar-legacy',
      body,
      headers: { 'webhook-id': id, 'webhook-timestamp': String(now), 'webhook-signature': `v1,${sig}` },
      options: {
        provider: 'polar',
        secrets: [secret],
        providerOptions: { secretMode: 'legacy' },
        now: () => now,
      },
      expectedIdentity: { deliveryId: null, eventId: id, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    });
  }

  // Pinned: Fal account mismatch
  {
    const body = Buffer.from('{"request_id":"req_fal_mismatch","status":"OK"}', 'utf8');
    const requestId = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';
    const userId = 'usr_hooklatch_stage11';
    const bodySha = createHash('sha256').update(body).digest('hex');
    const msg = `${requestId}\n${userId}\n${falNow}\n${bodySha}`;
    const sig = sign(null, Buffer.from(msg, 'utf8'), FAL_KEYS_AUTHENTIC.privKey).toString('hex');
    pinned.push({
      provider: 'fal',
      name: 'fal-account-mismatch',
      body,
      headers: {
        'x-fal-webhook-signature': sig,
        'x-fal-webhook-request-id': requestId,
        'x-fal-webhook-user-id': userId,
        'x-fal-webhook-timestamp': String(falNow),
      },
      options: {
        provider: 'fal',
        publicKeys: [FAL_KEYS_AUTHENTIC.rawPub],
        expectedUserId: 'usr_different_target_p11',
        now: () => falNow,
      },
      expectedFailure: 'invalid-signature',
    });
  }

  // Pinned: Wrong-MAC-before-stale
  {
    const body = Buffer.from('{"event":"charge.captured"}', 'utf8');
    const staleTime = now - 100000;
    pinned.push({
      provider: 'stripe',
      name: 'wrong-mac-before-stale',
      body,
      headers: { 'stripe-signature': `t=${staleTime},v1=${'a'.repeat(64)}` },
      options: { provider: 'stripe', secrets: ['whsec_stripe_test_secret_p11'], now: () => now },
      expectedFailure: 'invalid-signature',
    });
  }

  // Pinned: Explicit-zero tolerance
  {
    const body = Buffer.from('{"id":"evt_zero"}', 'utf8');
    const secret = 'whsec_stripe_zero';
    const signedPayload = Buffer.concat([Buffer.from(`${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');
    pinned.push({
      provider: 'stripe',
      name: 'explicit-zero-tolerance',
      body,
      headers: { 'stripe-signature': `t=${now},v1=${sig}` },
      options: { provider: 'stripe', secrets: [secret], toleranceSeconds: 0, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });

    for (const drift of [-1, 1]) {
      pinned.push({
        provider: 'stripe', name: `zero-drift-${drift}`, body,
        headers: { 'stripe-signature': `t=${now},v1=${sig}` },
        options: { provider: 'stripe', secrets: [secret], toleranceSeconds: 0, now: () => now + drift },
        expectedFailure: drift > 0 ? 'timestamp-expired' : 'timestamp-future',
      });
    }
  }

  // Pinned: Multi-key rotation
  {
    const body = Buffer.from('{"id":"evt_multi"}', 'utf8');
    const activeSecret = 'whsec_stripe_active';
    const retiredSecret = 'whsec_stripe_retired';
    const signedPayload = Buffer.concat([Buffer.from(`${now}.`, 'utf8'), body]);
    const sig = createHmac('sha256', activeSecret).update(signedPayload).digest('hex');
    pinned.push({
      provider: 'stripe',
      name: 'multi-key-rotation',
      body,
      headers: { 'stripe-signature': `t=${now},v1=${sig}` },
      options: { provider: 'stripe', secrets: [retiredSecret, activeSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    });
  }

  // Pinned: Fal multi-key rotation
  {
    const body = Buffer.from('{"request_id":"req_fal_rot","status":"OK"}', 'utf8');
    const requestId = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';
    const userId = 'usr_hooklatch_stage11';
    const bodySha = createHash('sha256').update(body).digest('hex');
    const msg = `${requestId}\n${userId}\n${falNow}\n${bodySha}`;
    const sig = sign(null, Buffer.from(msg, 'utf8'), FAL_KEYS_SECONDARY.privKey).toString('hex');
    pinned.push({
      provider: 'fal',
      name: 'fal-multi-key-rotation',
      body,
      headers: {
        'x-fal-webhook-signature': sig,
        'x-fal-webhook-request-id': requestId,
        'x-fal-webhook-user-id': userId,
        'x-fal-webhook-timestamp': String(falNow),
      },
      options: {
        provider: 'fal',
        publicKeys: [FAL_KEYS_AUTHENTIC.rawPub, FAL_KEYS_SECONDARY.rawPub],
        expectedUserId: userId,
        now: () => falNow,
      },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: falNow, authenticatedFields: ['timestamp'] },
    });
  }

  return { cases, pinned };
}

/**
 * Asserts verification success outcome field-by-field.
 */
export function assertSuccess(result, expectedProvider, expectedRawBody, expectedIdentity, label) {
  assert.equal(result.ok, true, `${label}: expected ok: true`);
  assert.equal(result.provider, expectedProvider, `${label}: provider mismatch`);
  assert.deepEqual([...result.rawBody], [...expectedRawBody], `${label}: rawBody bytes mismatch`);
  assert.equal(result.identity.deliveryId, expectedIdentity.deliveryId, `${label}: deliveryId mismatch`);
  assert.equal(result.identity.eventId, expectedIdentity.eventId, `${label}: eventId mismatch`);
  assert.equal(result.identity.timestamp, expectedIdentity.timestamp, `${label}: timestamp mismatch`);
  assert.deepEqual([...result.identity.authenticatedFields], [...expectedIdentity.authenticatedFields], `${label}: authenticatedFields mismatch`);
  assert.equal(result.reason, undefined, `${label}: unexpected reason on success`);
  assert.equal(result.message, undefined, `${label}: unexpected message on success`);
}

/**
 * Asserts verification failure outcome and ensures no rawBody or identity is leaked.
 */
export function assertFailure(result, expectedProvider, expectedReason, label) {
  assert.equal(result.ok, false, `${label}: expected ok: false`);
  assert.equal(result.provider, expectedProvider, `${label}: provider mismatch`);
  assert.ok(String(result.reason) === result.reason && result.reason.length > 0, `${label}: reason must be a string`);
  assert.ok(String(result.message) === result.message && result.message.length > 0, `${label}: message must be a string`);

  if (expectedReason !== null) {
    assert.equal(result.reason, expectedReason, `${label}: reason mismatch`);
  }

  assert.equal(result.rawBody, undefined, `${label}: rawBody must be absent on failure`);
  assert.equal(result.identity, undefined, `${label}: identity must be absent on failure`);

  const keys = Object.keys(result).sort();
  const allowed = ['message', 'ok', 'provider', 'reason'].sort();
  assert.deepEqual(keys, allowed, `${label}: invented failure fields detected`);
}

/**
 * Executes one test case across the 3 APIs: verify, verifyRequest, createVerifier.
 */
export async function executeTriplet(hooklatch, testCase, isTampered, format) {
  const { provider, body, headers, options, expectedIdentity, expectedFailure } = testCase;
  const rawBody = isTampered ? new Uint8Array(body.map((byte, idx) => (idx === 0 ? byte ^ 0x01 : byte))) : new Uint8Array(body);
  const expectedOk = !isTampered && expectedFailure === undefined;
  const expectedReason = isTampered ? 'invalid-signature' : (expectedFailure ?? null);
  const executedTuples = [];

  // API 1: verify
  {
    const label = `${format}:${provider}:verify:${isTampered ? 'tampered' : 'valid'}`;
    const result = await hooklatch.verify({ rawBody, headers }, options);

    if (expectedOk) {
      assertSuccess(result, provider, rawBody, expectedIdentity, label);
    } else {
      assertFailure(result, provider, expectedReason, label);
    }

    executedTuples.push({ format, provider, caseId: testCase.name ?? 'primary', api: 'verify', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  // API 2: verifyRequest
  {
    const label = `${format}:${provider}:verifyRequest:${isTampered ? 'tampered' : 'valid'}`;

    const request = new Request('https://synthetic.invalid/webhook', {
      method: 'POST',
      body: rawBody,
      headers: Object.fromEntries(Object.entries(headers)),
    });

    const result = await hooklatch.verifyRequest(request, options);

    if (expectedOk) {
      assertSuccess(result, provider, rawBody, expectedIdentity, label);
    } else {
      assertFailure(result, provider, expectedReason, label);
    }

    executedTuples.push({ format, provider, caseId: testCase.name ?? 'primary', api: 'verifyRequest', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  // API 3: createVerifier
  {
    const label = `${format}:${provider}:createVerifier:${isTampered ? 'tampered' : 'valid'}`;

    const verifier = hooklatch.createVerifier(options);
    assert.ok(verifier instanceof Function, `${label}: createVerifier must return function synchronously`);

    const result = await verifier({ rawBody, headers });

    if (expectedOk) {
      assertSuccess(result, provider, rawBody, expectedIdentity, label);
    } else {
      assertFailure(result, provider, expectedReason, label);
    }

    executedTuples.push({ format, provider, caseId: testCase.name ?? 'primary', api: 'createVerifier', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  return executedTuples;
}

/**
 * Runs the complete provider matrix and pinned cases for one module instance (ESM or CJS).
 */
export async function runMatrixForModule(hooklatch, format) {
  const { cases, pinned } = buildIndependentAnchors();
  const allTuples = [];

  // 21 providers * 2 states (valid, tampered) * 3 APIs = 126 tuples per format
  for (const c of cases) {
    const validTuples = await executeTriplet(hooklatch, c, false, format);
    allTuples.push(...validTuples);

    const tamperedTuples = await executeTriplet(hooklatch, c, true, format);
    allTuples.push(...tamperedTuples);
  }

  // Pinned cases
  const pinnedResults = [];

  for (const p of pinned) {
    const isTampered = false;
    const tuples = await executeTriplet(hooklatch, p, isTampered, format);
    pinnedResults.push({ name: p.name, provider: p.provider, tuples });
  }

  return { tuples: allTuples, pinnedResults };
}

/**
 * Runs reference equality across all 6 subpaths and verifies HooklatchError identity.
 */
export async function verifyExportReferenceEquality(esmRoots, cjsRoots) {
  const checked = [];

  for (const { subpath, exports: names } of SUBPATHS) {
    const esmMod = esmRoots[subpath];
    const cjsMod = cjsRoots[subpath];

    assert.ok(esmMod !== undefined, `ESM export missing for subpath ${subpath}`);
    assert.ok(cjsMod !== undefined, `CJS export missing for subpath ${subpath}`);

    for (const name of names) {
      assert.equal(
        esmMod[name],
        cjsMod[name],
        `Reference equality failed for ${subpath} export: ${name}`,
      );
      checked.push({ subpath, name, match: true });
    }
  }

  // HooklatchError class identity & cross-format diagnostics
  const esmErrClass = esmRoots['.'].HooklatchError;
  const cjsErrClass = cjsRoots['.'].HooklatchError;
  assert.equal(esmErrClass, cjsErrClass, 'HooklatchError class reference mismatch');

  const esmDiagnose = esmRoots['./diagnostics'].diagnose;
  const cjsDiagnose = cjsRoots['./diagnostics'].diagnose;
  assert.equal(esmDiagnose, cjsDiagnose, 'diagnose function reference mismatch');

  // Error constructed from ESM
  const errFromEsm = new esmErrClass('invalid-secret', 'Constructed via ESM');
  assert.ok(errFromEsm instanceof esmErrClass, 'errFromEsm instanceof esmErrClass failed');
  assert.ok(errFromEsm instanceof cjsErrClass, 'errFromEsm instanceof cjsErrClass failed');
  assert.deepEqual(esmDiagnose(errFromEsm), cjsDiagnose(errFromEsm), 'Cross diagnose mismatch for errFromEsm');

  // Error constructed from CJS
  const errFromCjs = new cjsErrClass('invalid-options', 'Constructed via CJS');
  assert.ok(errFromCjs instanceof cjsErrClass, 'errFromCjs instanceof cjsErrClass failed');
  assert.ok(errFromCjs instanceof esmErrClass, 'errFromCjs instanceof esmErrClass failed');
  assert.deepEqual(esmDiagnose(errFromCjs), cjsDiagnose(errFromCjs), 'Cross diagnose mismatch for errFromCjs');

  // Thrown setup errors
  try {
    esmRoots['.'].createVerifier({ provider: 'stripe', secrets: [] });
    assert.fail('createVerifier should have thrown');
  } catch (caught) {
    assert.ok(caught instanceof esmErrClass, 'thrown ESM setup error instanceof esmErrClass failed');
    assert.ok(caught instanceof cjsErrClass, 'thrown ESM setup error instanceof cjsErrClass failed');
    assert.deepEqual(esmDiagnose(caught), cjsDiagnose(caught), 'diagnose mismatch on thrown ESM error');
  }

  try {
    cjsRoots['.'].createVerifier({ provider: 'stripe', secrets: [] });
    assert.fail('createVerifier should have thrown');
  } catch (caught) {
    assert.ok(caught instanceof cjsErrClass, 'thrown CJS setup error instanceof cjsErrClass failed');
    assert.ok(caught instanceof esmErrClass, 'thrown CJS setup error instanceof esmErrClass failed');
    assert.deepEqual(esmDiagnose(caught), cjsDiagnose(caught), 'diagnose mismatch on thrown CJS error');
  }

  return { checked, errorIdentity: true };
}

/**
 * Checks negative deep subpath imports for ERR_PACKAGE_PATH_NOT_EXPORTED.
 */
export async function verifyNegativeSubpaths(requireFn) {
  const rejected = [];

  for (const forbidden of FORBIDDEN_SUBPATHS) {
    // ESM import
    let esmCode = null;

    try {
      await import(forbidden);
    } catch (err) {
      esmCode = err?.code ?? null;
    }

    assert.equal(esmCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', `ESM ${forbidden} did not fail with ERR_PACKAGE_PATH_NOT_EXPORTED`);

    // CJS require
    let cjsCode = null;

    try {
      requireFn(forbidden);
    } catch (err) {
      cjsCode = err?.code ?? null;
    }

    assert.equal(cjsCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', `CJS ${forbidden} did not fail with ERR_PACKAGE_PATH_NOT_EXPORTED`);

    rejected.push({ forbidden, esmCode, cjsCode });
  }

  return rejected;
}

/**
 * Code generator for the pure CommonJS consumer script.
 */
export function generateCjsConsumerScript() {
  return `'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const process = require('node:process');

const hooklatch = require('hooklatch');
const diagnostics = require('hooklatch/diagnostics');

const PROVIDERS = ${JSON.stringify(PROVIDERS)};

const FAL_SEED_AUTHENTIC = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex');
const pkcs8Der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), FAL_SEED_AUTHENTIC]);
const falPriv = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
const falPub = crypto.createPublicKey(falPriv);
const falRawPub = new Uint8Array(falPub.export({ format: 'der', type: 'spki' }).subarray(12));

const now = 1700000000;
const falNow = 1792742400;

function assertSuccess(result, expectedProvider, expectedRawBody, expectedIdentity, label) {
  assert.equal(result.ok, true, label + ': ok true');
  assert.equal(result.provider, expectedProvider, label + ': provider mismatch');
  assert.deepEqual([...result.rawBody], [...expectedRawBody], label + ': rawBody mismatch');
  assert.equal(result.identity.deliveryId, expectedIdentity.deliveryId, label + ': deliveryId mismatch');
  assert.equal(result.identity.eventId, expectedIdentity.eventId, label + ': eventId mismatch');
  assert.equal(result.identity.timestamp, expectedIdentity.timestamp, label + ': timestamp mismatch');
  assert.deepEqual([...result.identity.authenticatedFields], [...expectedIdentity.authenticatedFields], label + ': auth fields mismatch');
  assert.equal(result.reason, undefined, label + ': reason present on success');
  assert.equal(result.message, undefined, label + ': message present on success');
}

function assertFailure(result, expectedProvider, expectedReason, label) {
  assert.equal(result.ok, false, label + ': ok false');
  assert.equal(result.provider, expectedProvider, label + ': provider mismatch');
  assert.equal(typeof result.reason, 'string', label + ': reason string');
  assert.equal(typeof result.message, 'string', label + ': message string');
  if (expectedReason !== null) assert.equal(result.reason, expectedReason, label + ': reason match');
  assert.equal(result.rawBody, undefined, label + ': rawBody present on failure');
  assert.equal(result.identity, undefined, label + ': identity present on failure');
}

async function executeTriplet(testCase, isTampered) {
  const { provider, body, headers, options, expectedIdentity, expectedFailure } = testCase;
  const rawBody = isTampered ? new Uint8Array(body.map((byte, idx) => (idx === 0 ? byte ^ 0x01 : byte))) : new Uint8Array(body);
  const expectedOk = !isTampered && expectedFailure === undefined;
  const expectedReason = isTampered ? 'invalid-signature' : (expectedFailure || null);
  const tuples = [];

  // 1. verify
  {
    const label = 'cjs:' + provider + ':verify:' + (isTampered ? 'tampered' : 'valid');
    const result = await hooklatch.verify({ rawBody, headers }, options);
    if (expectedOk) assertSuccess(result, provider, rawBody, expectedIdentity, label);
    else assertFailure(result, provider, expectedReason, label);
    tuples.push({ format: 'require', provider, caseId: testCase.name || 'primary', api: 'verify', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  // 2. verifyRequest
  {
    const label = 'cjs:' + provider + ':verifyRequest:' + (isTampered ? 'tampered' : 'valid');
    const request = new Request('https://synthetic.invalid/webhook', {
      method: 'POST', body: rawBody, headers: Object.fromEntries(Object.entries(headers)),
    });
    const result = await hooklatch.verifyRequest(request, options);
    if (expectedOk) assertSuccess(result, provider, rawBody, expectedIdentity, label);
    else assertFailure(result, provider, expectedReason, label);
    tuples.push({ format: 'require', provider, caseId: testCase.name || 'primary', api: 'verifyRequest', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  // 3. createVerifier
  {
    const label = 'cjs:' + provider + ':createVerifier:' + (isTampered ? 'tampered' : 'valid');
    const verifier = hooklatch.createVerifier(options);
    assert.equal(typeof verifier, 'function', label + ': synchronous function');
    const result = await verifier({ rawBody, headers });
    if (expectedOk) assertSuccess(result, provider, rawBody, expectedIdentity, label);
    else assertFailure(result, provider, expectedReason, label);
    tuples.push({ format: 'require', provider, caseId: testCase.name || 'primary', api: 'createVerifier', state: isTampered ? 'tampered' : 'valid', ok: result.ok });
  }

  return tuples;
}

async function main() {
  const stdSecret = 'whsec_MfKQ9r8GKYqrTwjmtUTnUgfaffhnTrrrQ1vKcwKqH4s=';
  const stdKey = Buffer.from(stdSecret.slice(6), 'base64');
  const stdId = 'msg_phase11_cjs_std';
  const stdSigned = (b) => Buffer.concat([Buffer.from(stdId + '.' + now + '.'), b]);
  const stdSig = (b) => crypto.createHmac('sha256', stdKey).update(stdSigned(b)).digest('base64');

  const cases = [
    {
      provider: 'stripe',
      body: Buffer.from('{"id":"evt_cjs_stripe"}'),
      headers: { 'stripe-signature': 't=' + now + ',v1=' + crypto.createHmac('sha256', 'sec_s').update(Buffer.concat([Buffer.from(now + '.'), Buffer.from('{"id":"evt_cjs_stripe"}')])).digest('hex') },
      options: { provider: 'stripe', secrets: ['sec_s'], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    },
    {
      provider: 'github',
      body: Buffer.from('{"action":"opened"}'),
      headers: { 'x-hub-signature-256': 'sha256=' + crypto.createHmac('sha256', 'sec_g').update(Buffer.from('{"action":"opened"}')).digest('hex') },
      options: { provider: 'github', secrets: ['sec_g'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'shopify',
      body: Buffer.from('{"id":1}'),
      headers: { 'x-shopify-hmac-sha256': crypto.createHmac('sha256', 'sec_sh').update(Buffer.from('{"id":1}')).digest('base64') },
      options: { provider: 'shopify', secrets: ['sec_sh'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'standard-webhooks',
      body: Buffer.from('{"event":"test"}'),
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + stdSig(Buffer.from('{"event":"test"}')) },
      options: { provider: 'standard-webhooks', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'clerk',
      body: Buffer.from('{"data":{}}'),
      headers: { 'svix-id': stdId, 'svix-timestamp': String(now), 'svix-signature': 'v1,' + stdSig(Buffer.from('{"data":{}}')) },
      options: { provider: 'clerk', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'svix',
      body: Buffer.from('{"type":"t"}'),
      headers: { 'svix-id': stdId, 'svix-timestamp': String(now), 'svix-signature': 'v1,' + stdSig(Buffer.from('{"type":"t"}')) },
      options: { provider: 'svix', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'razorpay',
      body: Buffer.from('{"entity":"event"}'),
      headers: { 'x-razorpay-signature': crypto.createHmac('sha256', 'sec_rz').update(Buffer.from('{"entity":"event"}')).digest('hex') },
      options: { provider: 'razorpay', secrets: ['sec_rz'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'paddle',
      body: Buffer.from('{"event_id":"e1"}'),
      headers: { 'paddle-signature': 'ts=' + now + ';h1=' + crypto.createHmac('sha256', 'sec_p').update(Buffer.concat([Buffer.from(now + ':'), Buffer.from('{"event_id":"e1"}')])).digest('hex') },
      options: { provider: 'paddle', secrets: ['sec_p'], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    },
    {
      provider: 'lemon-squeezy',
      body: Buffer.from('{"meta":{}}'),
      headers: { 'x-signature': crypto.createHmac('sha256', 'sec_ls').update(Buffer.from('{"meta":{}}')).digest('hex') },
      options: { provider: 'lemon-squeezy', secrets: ['sec_ls'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'dodo-payments',
      body: Buffer.from('{"event":"d"}'),
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + stdSig(Buffer.from('{"event":"d"}')) },
      options: { provider: 'dodo-payments', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'gitlab',
      body: Buffer.from('{"project_id":1}'),
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + stdSig(Buffer.from('{"project_id":1}')) },
      options: { provider: 'gitlab', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'replicate',
      body: Buffer.from('{"id":"rep1"}'),
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + stdSig(Buffer.from('{"id":"rep1"}')) },
      options: { provider: 'replicate', secrets: [stdSecret], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'workos',
      body: Buffer.from('{"event":"w"}'),
      headers: { 'workos-signature': 't=' + (now * 1000) + ',v1=' + crypto.createHmac('sha256', 'sec_w').update(Buffer.concat([Buffer.from((now * 1000) + '.'), Buffer.from('{"event":"w"}')])).digest('hex') },
      options: { provider: 'workos', secrets: ['sec_w'], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    },
    {
      provider: 'sentry',
      body: Buffer.from('{"action":"s"}'),
      headers: { 'sentry-hook-signature': crypto.createHmac('sha256', 'sec_sn').update(Buffer.from('{"action":"s"}')).digest('hex') },
      options: { provider: 'sentry', secrets: ['sec_sn'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'doppler',
      body: Buffer.from('{"event":"d"}'),
      headers: { 'x-doppler-signature': 'sha256=' + crypto.createHmac('sha256', 'sec_dp').update(Buffer.from('{"event":"d"}')).digest('hex') },
      options: { provider: 'doppler', secrets: ['sec_dp'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'sanity',
      body: Buffer.from('{"_id":"s1"}'),
      headers: { 'sanity-webhook-signature': 't=' + (now * 1000) + ',v1=' + crypto.createHmac('sha256', 'sec_sa').update(Buffer.concat([Buffer.from((now * 1000) + '.'), Buffer.from('{"_id":"s1"}')])).digest('base64url') },
      options: { provider: 'sanity', secrets: ['sec_sa'], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    },
    {
      provider: 'grafana',
      body: Buffer.from('{"alert":"g"}'),
      headers: { 'x-grafana-alerting-signature': crypto.createHmac('sha256', 'sec_gr').update(Buffer.from('{"alert":"g"}')).digest('hex') },
      options: { provider: 'grafana', secrets: ['sec_gr'], providerOptions: { mode: 'body' } },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'polar',
      body: Buffer.from('{"id":"pol1"}'),
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + stdSig(Buffer.from('{"id":"pol1"}')) },
      options: { provider: 'polar', secrets: [stdSecret], providerOptions: { secretMode: 'current' }, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    },
    {
      provider: 'linear',
      body: Buffer.from('{"action":"l"}'),
      headers: { 'linear-signature': crypto.createHmac('sha256', 'sec_lin').update(Buffer.from('{"action":"l"}')).digest('hex') },
      options: { provider: 'linear', secrets: ['sec_lin'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'vercel',
      body: Buffer.from('{"type":"v"}'),
      headers: { 'x-vercel-signature': crypto.createHmac('sha1', 'sec_ver').update(Buffer.from('{"type":"v"}')).digest('hex') },
      options: { provider: 'vercel', secrets: ['sec_ver'] },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    },
    {
      provider: 'fal',
      body: Buffer.from('{"status":"OK"}'),
      headers: (() => {
        const reqId = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';
        const uId = 'usr_hooklatch_stage11';
        const bSha = crypto.createHash('sha256').update(Buffer.from('{"status":"OK"}')).digest('hex');
        const m = reqId + '\\n' + uId + '\\n' + falNow + '\\n' + bSha;
        const s = crypto.sign(null, Buffer.from(m, 'utf8'), falPriv).toString('hex');
        return {
          'x-fal-webhook-signature': s,
          'x-fal-webhook-request-id': reqId,
          'x-fal-webhook-user-id': uId,
          'x-fal-webhook-timestamp': String(falNow),
        };
      })(),
      options: { provider: 'fal', publicKeys: [falRawPub], expectedUserId: 'usr_hooklatch_stage11', now: () => falNow },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: falNow, authenticatedFields: ['timestamp'] },
    },
  ];

  assert.equal(cases.length, 21, 'Must have all 21 providers');
  const allTuples = [];

  for (const c of cases) {
    const v = await executeTriplet(c, false);
    allTuples.push(...v);
    const t = await executeTriplet(c, true);
    allTuples.push(...t);
  }

  // Pinned: Grafana timestamped
  {
    const b = Buffer.from('{"alert":"ts"}');
    const s = crypto.createHmac('sha256', 'sec_gr_ts').update(Buffer.concat([Buffer.from(now + ':'), b])).digest('hex');
    const v = await executeTriplet({
      provider: 'grafana', body: b,
      headers: { 'x-grafana-alerting-signature': s, 'x-grafana-timestamp': String(now) },
      options: { provider: 'grafana', secrets: ['sec_gr_ts'], providerOptions: { mode: 'timestamped', timestampHeader: 'x-grafana-timestamp' }, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    }, false);
    allTuples.push(...v);
  }

  // Pinned: Polar legacy
  {
    const b = Buffer.from('{"id":"leg"}');
    const sec = 'literal_polar_legacy';
    const s = crypto.createHmac('sha256', Buffer.from(sec, 'utf8')).update(Buffer.concat([Buffer.from(stdId + '.' + now + '.'), b])).digest('base64');
    const v = await executeTriplet({
      provider: 'polar', body: b,
      headers: { 'webhook-id': stdId, 'webhook-timestamp': String(now), 'webhook-signature': 'v1,' + s },
      options: { provider: 'polar', secrets: [sec], providerOptions: { secretMode: 'legacy' }, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: stdId, timestamp: now, authenticatedFields: ['eventId', 'timestamp'] },
    }, false);
    allTuples.push(...v);
  }

  // Pinned: Fal account mismatch
  {
    const b = Buffer.from('{"status":"OK"}');
    const reqId = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';
    const uId = 'usr_hooklatch_stage11';
    const bSha = crypto.createHash('sha256').update(b).digest('hex');
    const m = reqId + '\\n' + uId + '\\n' + falNow + '\\n' + bSha;
    const s = crypto.sign(null, Buffer.from(m, 'utf8'), falPriv).toString('hex');
    const v = await executeTriplet({
      provider: 'fal', body: b,
      headers: { 'x-fal-webhook-signature': s, 'x-fal-webhook-request-id': reqId, 'x-fal-webhook-user-id': uId, 'x-fal-webhook-timestamp': String(falNow) },
      options: { provider: 'fal', publicKeys: [falRawPub], expectedUserId: 'usr_mismatch', now: () => falNow },
      expectedFailure: 'invalid-signature',
    }, false);
    allTuples.push(...v);
  }

  // Pinned: Wrong-MAC-before-stale
  {
    const v = await executeTriplet({
      provider: 'stripe', body: Buffer.from('{"id":1}'),
      headers: { 'stripe-signature': 't=' + (now - 100000) + ',v1=' + 'b'.repeat(64) },
      options: { provider: 'stripe', secrets: ['sec_s'], now: () => now },
      expectedFailure: 'invalid-signature',
    }, false);
    allTuples.push(...v);
  }

  // Pinned: Explicit zero tolerance
  {
    const b = Buffer.from('{"id":"zero"}');
    const s = crypto.createHmac('sha256', 'sec_s').update(Buffer.concat([Buffer.from(now + '.'), b])).digest('hex');
    const v = await executeTriplet({
      provider: 'stripe', body: b,
      headers: { 'stripe-signature': 't=' + now + ',v1=' + s },
      options: { provider: 'stripe', secrets: ['sec_s'], toleranceSeconds: 0, now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    }, false);
    allTuples.push(...v);
  }

  for (const drift of [-1, 1]) {
    const b = Buffer.from('{"id":"zero-drift"}');
    const s = crypto.createHmac('sha256', 'zero_sec').update(Buffer.concat([Buffer.from(now + '.'), b])).digest('hex');
    allTuples.push(...await executeTriplet({
      provider: 'stripe', name: 'zero-drift-' + drift, body: b,
      headers: { 'stripe-signature': 't=' + now + ',v1=' + s },
      options: { provider: 'stripe', secrets: ['zero_sec'], toleranceSeconds: 0, now: () => now + drift },
      expectedFailure: drift > 0 ? 'timestamp-expired' : 'timestamp-future',
    }, false));
  }

  // Pinned: Multi-key rotation
  {
    const b = Buffer.from('{"id":"rot"}');
    const s = crypto.createHmac('sha256', 'valid_sec').update(Buffer.concat([Buffer.from(now + '.'), b])).digest('hex');
    const v = await executeTriplet({
      provider: 'stripe', body: b,
      headers: { 'stripe-signature': 't=' + now + ',v1=' + s },
      options: { provider: 'stripe', secrets: ['wrong_sec', 'valid_sec'], now: () => now },
      expectedIdentity: { deliveryId: null, eventId: null, timestamp: now, authenticatedFields: ['timestamp'] },
    }, false);
    allTuples.push(...v);
  }

  console.log(JSON.stringify({ ok: true, format: 'require', runtime: process.version, tuples: allTuples, totalTuples: allTuples.length }));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
`;
}

/**
 * Script for import-first reference equality subprocess.
 */
export function generateImportFirstScript() {
  return `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import * as hooklatch from 'hooklatch';
import * as diagnostics from 'hooklatch/diagnostics';
import * as express from 'hooklatch/express';
import * as nextjs from 'hooklatch/nextjs';
import * as cloudflare from 'hooklatch/cloudflare';
import * as hono from 'hooklatch/hono';

const req = createRequire(import.meta.url);
const hooklatchReq = req('hooklatch');
const diagReq = req('hooklatch/diagnostics');
const expReq = req('hooklatch/express');
const nextReq = req('hooklatch/nextjs');
const cfReq = req('hooklatch/cloudflare');
const honoReq = req('hooklatch/hono');

// 1. Reference equality
assert.equal(hooklatch.HooklatchError, hooklatchReq.HooklatchError, 'root HooklatchError mismatch');
assert.equal(hooklatch.verify, hooklatchReq.verify, 'root verify mismatch');
assert.equal(hooklatch.verifyRequest, hooklatchReq.verifyRequest, 'root verifyRequest mismatch');
assert.equal(hooklatch.createVerifier, hooklatchReq.createVerifier, 'root createVerifier mismatch');

assert.equal(diagnostics.diagnose, diagReq.diagnose, 'diagnostics diagnose mismatch');
assert.equal(express.createWebhookMiddleware, expReq.createWebhookMiddleware, 'express middleware mismatch');
assert.equal(nextjs.createWebhookHandler, nextReq.createWebhookHandler, 'nextjs handler mismatch');
assert.equal(cloudflare.createWebhookHandler, cfReq.createWebhookHandler, 'cloudflare handler mismatch');
assert.equal(hono.createWebhookMiddleware, honoReq.createWebhookMiddleware, 'hono middleware mismatch');

// 2. Error instanceof both ways
const esmErr = new hooklatch.HooklatchError('invalid-secret', 'Constructed via import');
assert.ok(esmErr instanceof hooklatch.HooklatchError);
assert.ok(esmErr instanceof hooklatchReq.HooklatchError);
assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(esmErr), diagReq.diagnose(esmErr)));

const cjsErr = new hooklatchReq.HooklatchError('invalid-options', 'Constructed via require');
assert.ok(cjsErr instanceof hooklatchReq.HooklatchError);
assert.ok(cjsErr instanceof hooklatch.HooklatchError);
assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(cjsErr), diagReq.diagnose(cjsErr)));

// 3. Setup errors thrown by each
try {
  hooklatch.createVerifier({ provider: 'stripe', secrets: [] });
  assert.fail('createVerifier should fail with empty secrets');
} catch (e) {
  assert.ok(e instanceof hooklatch.HooklatchError);
  assert.ok(e instanceof hooklatchReq.HooklatchError);
  assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(e), diagReq.diagnose(e)));
}

try {
  hooklatchReq.createVerifier({ provider: 'stripe', secrets: [] });
  assert.fail('createVerifier should fail with empty secrets');
} catch (e) {
  assert.ok(e instanceof hooklatchReq.HooklatchError);
  assert.ok(e instanceof hooklatch.HooklatchError);
  assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(e), diagReq.diagnose(e)));
}

console.log(JSON.stringify({ ok: true, process: 'import-first', subpathsChecked: 6 }));
`;
}

/**
 * Script for require-first reference equality subprocess.
 */
export function generateRequireFirstScript() {
  return `'use strict';
const assert = require('node:assert/strict');

const hooklatchReq = require('hooklatch');
const diagReq = require('hooklatch/diagnostics');
const expReq = require('hooklatch/express');
const nextReq = require('hooklatch/nextjs');
const cfReq = require('hooklatch/cloudflare');
const honoReq = require('hooklatch/hono');

(async () => {
  const hooklatch = await import('hooklatch');
  const diagnostics = await import('hooklatch/diagnostics');
  const express = await import('hooklatch/express');
  const nextjs = await import('hooklatch/nextjs');
  const cloudflare = await import('hooklatch/cloudflare');
  const hono = await import('hooklatch/hono');

  // 1. Reference equality
  assert.equal(hooklatch.HooklatchError, hooklatchReq.HooklatchError, 'root HooklatchError mismatch');
  assert.equal(hooklatch.verify, hooklatchReq.verify, 'root verify mismatch');
  assert.equal(hooklatch.verifyRequest, hooklatchReq.verifyRequest, 'root verifyRequest mismatch');
  assert.equal(hooklatch.createVerifier, hooklatchReq.createVerifier, 'root createVerifier mismatch');

  assert.equal(diagnostics.diagnose, diagReq.diagnose, 'diagnostics diagnose mismatch');
  assert.equal(express.createWebhookMiddleware, expReq.createWebhookMiddleware, 'express middleware mismatch');
  assert.equal(nextjs.createWebhookHandler, nextReq.createWebhookHandler, 'nextjs handler mismatch');
  assert.equal(cloudflare.createWebhookHandler, cfReq.createWebhookHandler, 'cloudflare handler mismatch');
  assert.equal(hono.createWebhookMiddleware, honoReq.createWebhookMiddleware, 'hono middleware mismatch');

  // 2. Error instanceof both ways
  const cjsErr = new hooklatchReq.HooklatchError('invalid-options', 'Constructed via require first');
  assert.ok(cjsErr instanceof hooklatchReq.HooklatchError);
  assert.ok(cjsErr instanceof hooklatch.HooklatchError);
  assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(cjsErr), diagReq.diagnose(cjsErr)));

  const esmErr = new hooklatch.HooklatchError('invalid-secret', 'Constructed via import second');
  assert.ok(esmErr instanceof hooklatch.HooklatchError);
  assert.ok(esmErr instanceof hooklatchReq.HooklatchError);
  assert.doesNotThrow(() => assert.deepEqual(diagnostics.diagnose(esmErr), diagReq.diagnose(esmErr)));

  console.log(JSON.stringify({ ok: true, process: 'require-first', subpathsChecked: 6 }));
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`;
}

/**
 * Script for testing negative subpaths rejection.
 */
export function generateNegativeSubpathsScript() {
  return `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const req = createRequire(import.meta.url);
const forbidden = ${JSON.stringify(FORBIDDEN_SUBPATHS)};

// Installed root is first known-good
const rootEsm = await import('hooklatch');
const rootCjs = req('hooklatch');
assert.ok(rootEsm.verify && rootCjs.verify, 'Root must load successfully first');

const rejected = [];

for (const subpath of forbidden) {
  let esmCode = null;
  try {
    await import(subpath);
  } catch (err) {
    esmCode = err?.code ?? null;
  }
  assert.equal(esmCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ESM did not reject ' + subpath);

  let cjsCode = null;
  try {
    req(subpath);
  } catch (err) {
    cjsCode = err?.code ?? null;
  }
  assert.equal(cjsCode, 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'CJS did not reject ' + subpath);

  rejected.push({ subpath, esmCode, cjsCode });
}

console.log(JSON.stringify({ ok: true, process: 'negative-subpaths', rejectedCount: rejected.length }));
`;
}

/**
 * Main consumer runner when executed directly inside the consumer root.
 */
async function main() {
  const req = createRequire(import.meta.url);
  const hooklatchEsm = await import('hooklatch');
  const hooklatchCjs = req('hooklatch');

  const esmMatrix = await runMatrixForModule(hooklatchEsm, 'import');
  const cjsMatrix = await runMatrixForModule(hooklatchCjs, 'require');

  console.log(JSON.stringify({
    ok: true,
    format: 'mixed-mjs',
    runtime: process.version,
    tuples: [...esmMatrix.tuples, ...cjsMatrix.tuples],
    pinned: [...esmMatrix.pinnedResults, ...cjsMatrix.pinnedResults],
    esmTuples: esmMatrix.tuples.length,
    cjsTuples: cjsMatrix.tuples.length,
    totalTuples: esmMatrix.tuples.length + cjsMatrix.tuples.length,
  }));
}

const isMainModule = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));

if (isMainModule) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
