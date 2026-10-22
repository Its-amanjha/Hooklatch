import { verify } from '../../src/index.js';
import { diagnose } from '../../src/diagnostics/index.js';

const BODY_CANARY = 'diagnostic-body-sensitive-synthetic-canary';
const MESSAGE_CANARY = 'diagnostic-message-sensitive-synthetic-canary';
const HEADER_CANARY = 'x-diagnostic-custom-sensitive-header';
const ID_CANARY = 'diagnostic-delivery-sensitive-synthetic-canary';
const BODY = new TextEncoder().encode(BODY_CANARY);
const NOW = 1700000100;

test('Grafana diagnostics describe header roles without exposing configured names or input data', async () => {
  const secret = 'diagnostic-secret-sensitive-synthetic-canary';
  const signature = '0'.repeat(64);

  const result = await verify({ rawBody: BODY, headers: { [HEADER_CANARY]: signature } }, {
    provider: 'grafana', secrets: [secret], providerOptions: { mode: 'body', signatureHeader: HEADER_CANARY },
  });

  if (result.ok) throw new Error('Expected signature failure');
  expect(result.reason).toBe('invalid-signature');
  const tainted = { ...result, message: MESSAGE_CANARY, payload: BODY_CANARY, secret, signature, deliveryId: ID_CANARY };
  const diagnostic = diagnose(tainted, { verbose: true });
  expect(diagnostic.provider).toBe('grafana');
  expect(diagnostic.detail?.expectedHeaders).toEqual([]);
  expect(diagnostic.detail?.grammar).toMatch(/configured signature header/i);
  expect(diagnostic.detail?.grammar).toMatch(/timestamped/i);

  for (const canary of [BODY_CANARY, MESSAGE_CANARY, HEADER_CANARY, ID_CANARY, secret, signature]) {
    expect(JSON.stringify(diagnostic)).not.toContain(canary);
  }
});

test.each(['current', 'legacy'] as const)('Polar %s diagnostics retain canonical roles and redact request/setup data', async (secretMode) => {
  const secret = `whsec_${Buffer.alloc(24, 42).toString('base64')}`;
  const signature = `v1,${Buffer.alloc(32).toString('base64')}`;

  const result = await verify({ rawBody: BODY, headers: {
    'webhook-id': ID_CANARY, 'webhook-timestamp': String(NOW), 'webhook-signature': signature,
  } }, { provider: 'polar', secrets: [secret], providerOptions: { secretMode }, now: () => NOW });

  if (result.ok) throw new Error('Expected signature failure');
  expect(result.reason).toBe('invalid-signature');
  const tainted = { ...result, message: MESSAGE_CANARY, payload: BODY_CANARY, secret, signature, deliveryId: ID_CANARY };
  const diagnostic = diagnose(tainted, { verbose: true });
  expect(diagnostic.provider).toBe('polar');
  expect(diagnostic.detail?.expectedHeaders).toEqual(['webhook-id', 'webhook-timestamp', 'webhook-signature']);
  expect(diagnostic.detail?.grammar).toMatch(/current or legacy/);

  for (const canary of [BODY_CANARY, MESSAGE_CANARY, ID_CANARY, secret, signature]) {
    expect(JSON.stringify(diagnostic)).not.toContain(canary);
  }
});
