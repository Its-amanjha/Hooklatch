import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { verify, verifyRequest, createVerifier, HooklatchError } from '../../src/index.js';
import type {
  VerifyOptions,
  GrafanaOptions,
  PolarOptions,
  WebhookRequest,
} from '../../src/index.js';

// Synthetic test vectors for Phase 7 Stage B contract tests.
// No credentials or live endpoints are used.
const GRAFANA_SECRET = 'grafana-public-config-synthetic-secret-2026';
const POLAR_CURRENT_SECRET = 'whsec_c3VwZXItc2VjcmV0LWJhc2U2NC1rZXktZm9yLXBvbGFyLTIwMjY=';
const POLAR_LEGACY_SECRET = 'polar-legacy-literal-string-secret-2026';
const TIMESTAMP = 1792368000;
const TIMESTAMP_STR = String(TIMESTAMP);
const EVENT_ID = 'evt_phase7_config_001';
const RAW_BODY = new TextEncoder().encode('{"alert":"cpu_high","value":98.6}');

const DEFAULT_GRAFANA_HEADER = 'x-grafana-alerting-signature';
const CUSTOM_SIG_HEADER = 'x-custom-alert-signature';
const TIMESTAMP_HEADER = 'x-alert-timestamp';

const RESERVED_HEADER_NAMES: readonly string[] = [
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'trailer',
  'te',
  'proxy-authorization',
  'proxy-authenticate',
  'authorization',
  'cookie',
  'set-cookie',
];

/** Independent node:crypto HMAC-SHA256 hex signer for Grafana. */
function signGrafana(
  body: Uint8Array,
  secret: string = GRAFANA_SECRET,
  timestamp?: string,
): string {
  const content = timestamp === undefined
    ? body
    : Buffer.concat([Buffer.from(`${timestamp}:`, 'utf8'), Buffer.from(body)]);

  return createHmac('sha256', secret).update(content).digest('hex');
}

/** Independent node:crypto HMAC-SHA256 Base64 signer for Polar. */
function signPolar(
  body: Uint8Array,
  id: string,
  timestamp: string,
  secret: string,
  isLegacy: boolean,
): string {
  const content = Buffer.concat([
    Buffer.from(`${id}.${timestamp}.`, 'utf8'),
    Buffer.from(body),
  ]);

  const key = isLegacy
    ? Buffer.from(secret, 'utf8')
    : Buffer.from(secret.startsWith('whsec_') ? secret.slice(6) : secret, 'base64');

  return createHmac('sha256', key).update(content).digest('base64');
}

function expectInvalidOptionsSync(run: () => void, canary?: string): void {
  let thrown: unknown;

  try {
    run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);
  // SAFETY: thrown was asserted to be HooklatchError above.
  const err = thrown as HooklatchError;
  expect(err.code).toBe('invalid-options');
  expect(err.message.length).toBeGreaterThan(0);

  if (canary) {
    expect(err.message.includes(canary)).toBe(false);
  }
}

async function expectInvalidOptionsAsync<Value>(run: () => Promise<Value>, canary?: string): Promise<void> {
  let thrown: unknown;

  try {
    await run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);
  // SAFETY: thrown was asserted to be HooklatchError above.
  const err = thrown as HooklatchError;
  expect(err.code).toBe('invalid-options');
  expect(err.message.length).toBeGreaterThan(0);

  if (canary) {
    expect(err.message.includes(canary)).toBe(false);
  }
}

describe('Phase 7 Stage B — Public Configuration Contract', () => {
  describe('Valid configurations across verify, verifyRequest, and createVerifier', () => {
    test('Grafana body mode with default signature header', async () => {
      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);
      const headers = { [DEFAULT_GRAFANA_HEADER]: sig };
      const grafanaConfig: GrafanaOptions = { mode: 'body' };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: grafanaConfig,
      };

      // 1. verify
      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const resultVerify = await verify(req, options);
      expect(resultVerify.ok).toBe(true);

      if (resultVerify.ok) {
        expect(resultVerify.provider).toBe('grafana');
        expect(Buffer.from(resultVerify.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
        expect(resultVerify.identity).toEqual({
          deliveryId: null,
          eventId: null,
          timestamp: null,
          authenticatedFields: [],
        });
      }

      // 2. verifyRequest
      const webReq = new Request('http://localhost/webhook', {
        method: 'POST',
        headers,
        body: RAW_BODY,
      });

      const resultReq = await verifyRequest(webReq, options);
      expect(resultReq.ok).toBe(true);

      if (resultReq.ok) {
        expect(resultReq.provider).toBe('grafana');
        expect(Buffer.from(resultReq.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }

      // 3. createVerifier
      const verifier = createVerifier(options);
      const resultCreated = await verifier(req);
      expect(resultCreated.ok).toBe(true);

      if (resultCreated.ok) {
        expect(resultCreated.provider).toBe('grafana');
        expect(Buffer.from(resultCreated.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }
    });

    test('Grafana body mode with custom signature header', async () => {
      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);
      const headers = { [CUSTOM_SIG_HEADER]: sig };

      const grafanaConfig: GrafanaOptions = {
        mode: 'body',
        signatureHeader: CUSTOM_SIG_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: grafanaConfig,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }
    });

    test('Grafana timestamped mode with default signature header and required timestamp header', async () => {
      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      const headers = {
        [DEFAULT_GRAFANA_HEADER]: sig,
        [TIMESTAMP_HEADER]: TIMESTAMP_STR,
      };

      const grafanaConfig: GrafanaOptions = {
        mode: 'timestamped',
        timestampHeader: TIMESTAMP_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP,
        providerOptions: grafanaConfig,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
        expect(result.identity).toEqual({
          deliveryId: null,
          eventId: null,
          timestamp: TIMESTAMP,
          authenticatedFields: ['timestamp'],
        });
      }

      const verifier = createVerifier(options);
      const resultCreated = await verifier(req);
      expect(resultCreated.ok).toBe(true);
    });

    test('Grafana timestamped mode with custom signature header', async () => {
      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      const headers = {
        [CUSTOM_SIG_HEADER]: sig,
        [TIMESTAMP_HEADER]: TIMESTAMP_STR,
      };

      const grafanaConfig: GrafanaOptions = {
        mode: 'timestamped',
        signatureHeader: CUSTOM_SIG_HEADER,
        timestampHeader: TIMESTAMP_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP,
        providerOptions: grafanaConfig,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
        expect(result.identity.timestamp).toBe(TIMESTAMP);
      }
    });

    test('Polar current mode with omitted providerOptions (defaults to current)', async () => {
      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false);

      const headers = {
        'webhook-id': EVENT_ID,
        'webhook-timestamp': TIMESTAMP_STR,
        'webhook-signature': `v1,${sig}`,
      };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        now: () => TIMESTAMP,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('polar');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
        expect(result.identity).toEqual({
          deliveryId: null,
          eventId: EVENT_ID,
          timestamp: TIMESTAMP,
          authenticatedFields: ['eventId', 'timestamp'],
        });
      }

      const webReq = new Request('http://localhost/polar', {
        method: 'POST',
        headers,
        body: RAW_BODY,
      });

      const resultReq = await verifyRequest(webReq, options);
      expect(resultReq.ok).toBe(true);
    });

    test('Polar current mode with explicit providerOptions', async () => {
      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false);

      const headers = {
        'webhook-id': EVENT_ID,
        'webhook-timestamp': TIMESTAMP_STR,
        'webhook-signature': `v1,${sig}`,
      };

      const polarConfig: PolarOptions = { secretMode: 'current' };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        now: () => TIMESTAMP,
        providerOptions: polarConfig,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('polar');
        expect(result.identity.eventId).toBe(EVENT_ID);
      }
    });

    test('Polar legacy mode with literal string secret', async () => {
      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_LEGACY_SECRET, true);

      const headers = {
        'webhook-id': EVENT_ID,
        'webhook-timestamp': TIMESTAMP_STR,
        'webhook-signature': `v1,${sig}`,
      };

      const polarConfig: PolarOptions = { secretMode: 'legacy' };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_LEGACY_SECRET],
        now: () => TIMESTAMP,
        providerOptions: polarConfig,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);
      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('polar');
        expect(result.identity.eventId).toBe(EVENT_ID);
      }

      const verifier = createVerifier(options);
      const resultCreated = await verifier(req);
      expect(resultCreated.ok).toBe(true);
    });
  });

  describe('Configuration validation — invalid options must throw HooklatchError(invalid-options)', () => {
    test('rejects non-object options, null, arrays, and primitives', async () => {
      const dummyReq: WebhookRequest = { rawBody: RAW_BODY, headers: {} };

      // SAFETY: Deliberately invalid options type to assert runtime validation boundary.
      expectInvalidOptionsSync(() => createVerifier(null as never));
      // SAFETY: Deliberately invalid options type to assert runtime validation boundary.
      expectInvalidOptionsSync(() => createVerifier([] as never));
      // SAFETY: Deliberately invalid options type to assert runtime validation boundary.
      expectInvalidOptionsSync(() => createVerifier('bad' as never));
      // SAFETY: Deliberately invalid options type to assert runtime validation boundary.
      expectInvalidOptionsSync(() => createVerifier(123 as never));

      // SAFETY: Deliberately invalid options type to assert runtime validation boundary.
      await expectInvalidOptionsAsync(() => verify(dummyReq, null as never));
    });

    test('rejects null and array providerOptions', () => {
      // SAFETY: Deliberately invalid null providerOptions to verify runtime rejection.
      const grafanaNull: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: null as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaNull));

      // SAFETY: Deliberately invalid array providerOptions to verify runtime rejection.
      const grafanaArray: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: [] as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaArray));

      // SAFETY: Deliberately invalid null providerOptions to verify runtime rejection.
      const polarNull: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: null as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarNull));

      // SAFETY: Deliberately invalid array providerOptions to verify runtime rejection.
      const polarArray: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: [] as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarArray));
    });

    test('Grafana requires providerOptions; omission is invalid rather than defaulted', () => {
      // SAFETY: Deliberately omitting required providerOptions to verify runtime rejection.
      const grafanaNoOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
      } as never;

      expectInvalidOptionsSync(() => createVerifier(grafanaNoOptions));
    });

    test('Public supplied providerOptions: undefined is invalid across providers', () => {
      // SAFETY: Explicit undefined providerOptions is prohibited by contract; callers must omit it.
      const grafanaUndefined: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: undefined as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaUndefined));

      // SAFETY: Explicit undefined providerOptions on polar is prohibited by contract.
      const polarUndefined: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: undefined as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarUndefined));

      // SAFETY: Explicit undefined providerOptions on existing provider is prohibited by contract.
      const stripeUndefined: VerifyOptions = {
        provider: 'stripe',
        secrets: ['whsec_test'],
        providerOptions: undefined as never,
      };

      expectInvalidOptionsSync(() => createVerifier(stripeUndefined));
    });

    test('Grafana requires explicit own mode property', () => {
      // SAFETY: Deliberately empty providerOptions to verify missing mode rejection.
      const emptyMode: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {} as never,
      };

      expectInvalidOptionsSync(() => createVerifier(emptyMode));

      // SAFETY: Deliberately unknown mode value to verify runtime rejection.
      const unknownMode: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: { mode: 'invalid' } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(unknownMode));

      // SAFETY: Deliberately inherited mode to assert own property requirement.
      const inheritedProto = { mode: 'body' as const };
      const inheritedModeObj = Object.create(inheritedProto);

      const inheritedMode: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        // SAFETY: Inherited mode deliberately violates own-property requirement.
        providerOptions: inheritedModeObj as never,
      };

      expectInvalidOptionsSync(() => createVerifier(inheritedMode));

      // SAFETY: Own mode: undefined must be rejected.
      const ownUndefinedMode: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: { mode: undefined } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(ownUndefinedMode));
    });

    test('Grafana body mode rejects ANY own timestampHeader, including undefined', () => {
      // SAFETY: Body mode explicitly forbids any own timestampHeader.
      const bodyWithHeader: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          timestampHeader: 'x-timestamp',
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(bodyWithHeader));

      // SAFETY: Body mode forbids own timestampHeader even when set to undefined.
      const bodyWithUndefinedHeader: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          timestampHeader: undefined,
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(bodyWithUndefinedHeader));
    });

    test('Grafana timestamped mode requires own timestampHeader', () => {
      // SAFETY: Timestamped mode missing required timestampHeader.
      const missingTsHeader: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'timestamped',
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(missingTsHeader));

      // SAFETY: Timestamped mode with inherited timestampHeader must be rejected.
      const proto = { timestampHeader: 'x-ts' };
      const inheritedObj = Object.assign(Object.create(proto), { mode: 'timestamped' as const });

      const inheritedTsHeader: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        // SAFETY: Inherited timestampHeader deliberately violates own-property requirement.
        providerOptions: inheritedObj as never,
      };

      expectInvalidOptionsSync(() => createVerifier(inheritedTsHeader));

      // SAFETY: Timestamped mode with own undefined timestampHeader must be rejected.
      const undefinedTsHeader: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'timestamped',
          timestampHeader: undefined,
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(undefinedTsHeader));
    });

    test('Grafana rejects reserved header names case-insensitively', () => {
      for (const reserved of RESERVED_HEADER_NAMES) {
        // Test as signatureHeader in body mode
        // SAFETY: Deliberately reserved header name to assert policy rejection.
        const sigReserved: VerifyOptions = {
          provider: 'grafana',
          secrets: [GRAFANA_SECRET],
          providerOptions: {
            mode: 'body',
            signatureHeader: reserved,
          },
        };

        expectInvalidOptionsSync(() => createVerifier(sigReserved));

        // Test uppercase reserved name
        // SAFETY: Deliberately uppercase reserved header name to assert case-insensitive rejection.
        const sigUpper: VerifyOptions = {
          provider: 'grafana',
          secrets: [GRAFANA_SECRET],
          providerOptions: {
            mode: 'body',
            signatureHeader: reserved.toUpperCase(),
          },
        };

        expectInvalidOptionsSync(() => createVerifier(sigUpper));

        // Test as timestampHeader in timestamped mode
        // SAFETY: Deliberately reserved header name as timestampHeader to assert rejection.
        const tsReserved: VerifyOptions = {
          provider: 'grafana',
          secrets: [GRAFANA_SECRET],
          providerOptions: {
            mode: 'timestamped',
            timestampHeader: reserved,
          },
        };

        expectInvalidOptionsSync(() => createVerifier(tsReserved));
      }
    });

    test('Grafana rejects malformed header names (whitespace, empty, non-token chars)', () => {
      const invalidNames = ['', '   ', 'sig header', 'sig:header', 'sig/header', 'sig\n'];

      for (const badName of invalidNames) {
        // SAFETY: Deliberately malformed RFC 9110 token to assert validation boundary.
        const badSig: VerifyOptions = {
          provider: 'grafana',
          secrets: [GRAFANA_SECRET],
          providerOptions: {
            mode: 'body',
            signatureHeader: badName,
          },
        };

        expectInvalidOptionsSync(() => createVerifier(badSig));

        // SAFETY: Deliberately malformed RFC 9110 token to assert validation boundary.
        const badTs: VerifyOptions = {
          provider: 'grafana',
          secrets: [GRAFANA_SECRET],
          providerOptions: {
            mode: 'timestamped',
            timestampHeader: badName,
          },
        };

        expectInvalidOptionsSync(() => createVerifier(badTs));
      }
    });

    test('Grafana rejects colliding signatureHeader and timestampHeader case-insensitively', () => {
      // SAFETY: Colliding custom signatureHeader and timestampHeader.
      const directCollision: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'timestamped',
          signatureHeader: 'X-Alert-Signature',
          timestampHeader: 'x-alert-signature',
        },
      };

      expectInvalidOptionsSync(() => createVerifier(directCollision));

      // SAFETY: Colliding default signatureHeader and custom timestampHeader.
      const defaultCollision: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'timestamped',
          timestampHeader: DEFAULT_GRAFANA_HEADER.toUpperCase(),
        },
      };

      expectInvalidOptionsSync(() => createVerifier(defaultCollision));
    });

    test('Grafana rejects own signatureHeader: undefined', () => {
      // SAFETY: Explicit own signatureHeader: undefined must be rejected; omission is required to default.
      const ownUndefinedSig: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          signatureHeader: undefined,
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(ownUndefinedSig));
    });

    test('Polar rejects invalid own modes and ignores inherited mode', async () => {
      // SAFETY: Deliberately unknown secretMode value to verify rejection.
      const badMode: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: { secretMode: 'auto' as never },
      };

      expectInvalidOptionsSync(() => createVerifier(badMode));

      // SAFETY: Inherited secretMode must not be recognized.
      const proto = { secretMode: 'legacy' as const };
      const inheritedObj = Object.create(proto);

      const inheritedMode: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        // SAFETY: Inherited secretMode deliberately violates own-property requirement.
        providerOptions: inheritedObj as never,
      };

      const inheritedResult = await verify({ rawBody: RAW_BODY, headers: {
        'webhook-id': EVENT_ID,
        'webhook-timestamp': TIMESTAMP_STR,
        'webhook-signature': `v1,${signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false)}`,
      } }, { ...inheritedMode, now: () => TIMESTAMP });

      expect(inheritedResult.ok).toBe(true);

      // SAFETY: Explicit own secretMode: undefined must be rejected.
      const undefinedMode: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: { secretMode: undefined } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(undefinedMode));
    });

    test('Rejects unknown enumerable string and Symbol keys on providerOptions', () => {
      // Unknown string key on Grafana
      // SAFETY: Unexpected enumerable string key on Grafana options.
      const grafanaExtraStr: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          unrecognizedKey: 'extra',
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaExtraStr));

      // Unknown Symbol key on Grafana
      const CANARY_SYM = Symbol('canary-symbol');

      // SAFETY: Unexpected enumerable Symbol key on Grafana options.
      const grafanaExtraSym: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          [CANARY_SYM]: 'canary-value',
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaExtraSym));

      // Unknown string key on Polar
      // SAFETY: Unexpected enumerable string key on Polar options.
      const polarExtraStr: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: {
          secretMode: 'current',
          extraField: 42,
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarExtraStr));

      // Unknown Symbol key on Polar
      // SAFETY: Unexpected enumerable Symbol key on Polar options.
      const polarExtraSym: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: {
          secretMode: 'current',
          [CANARY_SYM]: 'canary-value',
        } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarExtraSym));
    });

    test('Known non-enumerable own fields remain valid configuration', async () => {
      const nonEnumGrafana = {};
      Object.defineProperty(nonEnumGrafana, 'mode', {
        value: 'body',
        enumerable: false,
        configurable: true,
      });

      // SAFETY: defineProperty above supplies the required own body-mode value.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: nonEnumGrafana as never,
      };

      const result = await verify({ rawBody: RAW_BODY, headers: {
        [DEFAULT_GRAFANA_HEADER]: signGrafana(RAW_BODY),
      } }, opts);

      expect(result.ok).toBe(true);
    });

    test('Throwing getters and revoked proxies emerge only as generic static invalid-options', () => {
      const CANARY_MESSAGE = 'CANARY_SENSITIVE_LEAK_TOKEN_7381';

      // Throwing standard Error with canary
      const throwingObj = {
        get mode(): never {
          throw new Error(`Secret leaked canary: ${CANARY_MESSAGE}`);
        },
      };

      // SAFETY: Accessing throwing getter must be caught and redacted.
      const throwingOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: throwingObj as never,
      };

      expectInvalidOptionsSync(() => createVerifier(throwingOpts), CANARY_MESSAGE);

      // Throwing forged HooklatchError object with different error code
      const forgedObj = {
        get mode(): never {
          throw new HooklatchError('crypto-unavailable', 'forged-internal-exploit');
        },
      };

      // SAFETY: Forged internal HooklatchError must be replaced with static invalid-options.
      const forgedOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: forgedObj as never,
      };

      expectInvalidOptionsSync(() => createVerifier(forgedOpts));

      // Revoked proxy
      // SAFETY: Target object satisfies GrafanaOptions shape before revocation.
      const { proxy, revoke } = Proxy.revocable({ mode: 'body' as const }, {});
      revoke();

      // SAFETY: Revoked proxy throws TypeError on trap access, must be contained.
      const proxyOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: proxy,
      };

      expectInvalidOptionsSync(() => createVerifier(proxyOpts));
    });

    test('Rejects wrong-provider configuration', () => {
      // Existing provider (Stripe) given providerOptions
      // SAFETY: Provider other than grafana or polar supplied with providerOptions.
      const stripeWithConfig: VerifyOptions = {
        provider: 'stripe',
        secrets: ['whsec_test'],
        providerOptions: { mode: 'body' } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(stripeWithConfig));

      // Existing provider (GitHub) given empty providerOptions
      // SAFETY: Provider other than grafana or polar supplied with providerOptions.
      const githubWithConfig: VerifyOptions = {
        provider: 'github',
        secrets: ['gh_secret'],
        providerOptions: {} as never,
      };

      expectInvalidOptionsSync(() => createVerifier(githubWithConfig));

      // Grafana given Polar options
      // SAFETY: Grafana given Polar secretMode options lacks required mode.
      const grafanaWithPolar: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: { secretMode: 'current' } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(grafanaWithPolar));

      // Polar given Grafana options
      // SAFETY: Polar given Grafana mode options has unexpected key mode.
      const polarWithGrafana: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        providerOptions: { mode: 'body' } as never,
      };

      expectInvalidOptionsSync(() => createVerifier(polarWithGrafana));
    });

    test('Asserts actual error code and never leaks secret in error message', () => {
      const SECRET_CANARY = 'ultra-sensitive-canary-secret-never-leak';

      // SAFETY: Malformed provider options to trigger error while testing message redaction.
      const malformedOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [SECRET_CANARY],
        providerOptions: { mode: 'bad-mode' as never },
      };

      expectInvalidOptionsSync(() => createVerifier(malformedOpts), SECRET_CANARY);
    });
  });
});
