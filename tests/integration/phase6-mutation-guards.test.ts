import { createHmac } from 'node:crypto';
import { verify } from '../../src/index.js';
import type { VerificationResult, VerifyOptions, WebhookRequest } from '../../src/index.js';

const body = new TextEncoder().encode('synthetic-phase6-public-contract');
const literalSecret = 'synthetic-phase6-public-contract-secret';

// Keep setup failures observable at the assertion: an unexpected throw must not
// disappear into an unclassified test-helper error before the contract is checked.
interface UnexpectedSetupFailure { readonly unexpectedSetupFailure: true }

async function observedVerification(request: WebhookRequest, options: VerifyOptions): Promise<VerificationResult | UnexpectedSetupFailure> {
  try { return await verify(request, options); }
  catch { return { unexpectedSetupFailure: true }; }
}

test('Doppler raw header whitespace remains malformed', async () => {
  const signature = createHmac('sha256', literalSecret).update(body).digest('hex');

  const result = await observedVerification({ rawBody: body, headers: {
    'x-doppler-signature': ` sha256=${signature} `,
  } }, { provider: 'doppler', secrets: [literalSecret] });

  expect(result).toMatchObject({ ok: false, reason: 'malformed-signature' });
});

test('Sentry never accepts a scheme-prefixed signature', async () => {
  const signature = createHmac('sha256', literalSecret).update(body).digest('hex');

  const result = await observedVerification({ rawBody: body, headers: {
    'sentry-hook-signature': `sha256=${signature}`,
  } }, { provider: 'sentry', secrets: [literalSecret] });

  expect(result).toMatchObject({ ok: false, reason: 'malformed-signature' });
});

test('Standard Webhooks prefixed secret decodes before public verification', async () => {
  const key = Buffer.from('synthetic-standard-key-32-bytes!!');
  const id = 'synthetic-phase6-message';
  const timestamp = '1700000000';
  const signature = createHmac('sha256', key).update(`${id}.${timestamp}.`).update(body).digest('base64');

  const result = await observedVerification({ rawBody: body, headers: {
    'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': `v1,${signature}`,
  } }, { provider: 'standard-webhooks', secrets: [`whsec_${key.toString('base64')}`], now: () => Number(timestamp) });

  expect(result).toMatchObject({ ok: true, provider: 'standard-webhooks' });
});

test('Sanity rejects unused Base64url pad bits even for the same decoded digest', async () => {
  const timestamp = '1700000000000';
  const signature = createHmac('sha256', literalSecret).update(`${timestamp}.`).update(body).digest('base64url');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const lastIndex = alphabet.indexOf(signature.charAt(signature.length - 1));
  const noncanonical = signature.slice(0, -1) + alphabet.charAt(lastIndex + 1);

  expect(Buffer.from(noncanonical, 'base64url')).toEqual(Buffer.from(signature, 'base64url'));

  const result = await observedVerification({ rawBody: body, headers: {
    'sanity-webhook-signature': `t=${timestamp},v1=${noncanonical}`,
  } }, { provider: 'sanity', secrets: [literalSecret], now: () => Number(timestamp) / 1000 });

  expect(result).toMatchObject({ ok: false, reason: 'malformed-signature' });
});
