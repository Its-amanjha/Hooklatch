import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { verify, verifyRequest, createVerifier } from '../../src/index.js';
import type {
  VerifyOptions,
  GrafanaOptions,
  PolarOptions,
  WebhookRequest,
} from '../../src/index.js';

// Synthetic test vectors for Phase 7 Stage B snapshot and tolerance tests.
const GRAFANA_SECRET = 'grafana-snapshots-synthetic-secret-2026';
const POLAR_CURRENT_SECRET = 'whsec_c3VwZXItc2VjcmV0LWJhc2U2NC1rZXktZm9yLXBvbGFyLTIwMjY=';
const POLAR_LEGACY_SECRET = 'polar-legacy-literal-string-secret-2026';
const TIMESTAMP = 1792368000;
const TIMESTAMP_STR = String(TIMESTAMP);
const EVENT_ID = 'evt_phase7_snapshot_001';
const RAW_BODY = new TextEncoder().encode('{"event":"snapshot_probe","active":true}');

const DEFAULT_GRAFANA_HEADER = 'x-grafana-alerting-signature';
const CUSTOM_SIG_HEADER = 'x-custom-snapshot-signature';
const TIMESTAMP_HEADER = 'x-snapshot-timestamp';

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

interface MutableGrafanaConfig {
  mode: 'body';
  signatureHeader?: string;
}

interface StreamRequestInit extends RequestInit {
  duplex: 'half';
}

const STREAM_MODE: StreamRequestInit = { duplex: 'half' };

describe('Phase 7 Stage B — Configuration Snapshots and Immutability', () => {
  describe('Options, secret array, and header mutation isolation', () => {
    test('mutating secrets array after creating verifier does not affect verification', async () => {
      const secrets = [GRAFANA_SECRET];
      const grafanaConfig: GrafanaOptions = { mode: 'body' };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets,
        providerOptions: grafanaConfig,
      };

      const verifier = createVerifier(options);

      // Mutate the caller's secrets array after verifier instantiation.
      secrets[0] = 'tampered-secret-value';
      secrets.push('extra-secret');

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);

      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: { [DEFAULT_GRAFANA_HEADER]: sig },
      };

      const result = await verifier(req);

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }
    });

    test('mutating providerOptions object after creating verifier does not affect verification', async () => {
      const grafanaConfig: MutableGrafanaConfig = {
        mode: 'body',
        signatureHeader: CUSTOM_SIG_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: grafanaConfig,
      };

      const verifier = createVerifier(options);

      // Mutate caller's config object property after verifier creation.
      grafanaConfig.signatureHeader = 'x-tampered-header';

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);

      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: { [CUSTOM_SIG_HEADER]: sig },
      };

      const result = await verifier(req);

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
      }
    });

    test('Grafana header names are snapshotted in lowercase and matched case-insensitively', async () => {
      const grafanaConfig: GrafanaOptions = {
        mode: 'timestamped',
        signatureHeader: 'X-MixedCase-Alert-Signature',
        timestampHeader: 'X-MixedCase-Alert-Timestamp',
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP,
        providerOptions: grafanaConfig,
      };

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      // Incoming request headers with varying casing.
      const headers = {
        'x-mixedcase-alert-signature': sig,
        'X-MIXEDCASE-ALERT-TIMESTAMP': TIMESTAMP_STR,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };
      const result = await verify(req, options);

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.identity.timestamp).toBe(TIMESTAMP);
      }
    });

    test('verifies exact visible Uint8Array slice when backing buffer contains surrounding bytes', async () => {
      // Allocate larger backing array with sentinel prefix and suffix bytes.
      const backing = new Uint8Array(RAW_BODY.length + 32);
      backing.fill(0xee, 0, 16);
      backing.fill(0xff, 16 + RAW_BODY.length);
      backing.set(RAW_BODY, 16);

      // Subarray represents the exact visible slice.
      const bodySlice = backing.subarray(16, 16 + RAW_BODY.length);

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);
      const headers = { [DEFAULT_GRAFANA_HEADER]: sig };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: { mode: 'body' },
      };

      const req: WebhookRequest = { rawBody: bodySlice, headers };
      const result = await verify(req, options);

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.rawBody.length).toBe(RAW_BODY.length);
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }

      // Mutate padding outside the slice in backing array; must not affect verifier output.
      backing[0] = 0x11;
      backing[backing.length - 1] = 0x22;

      const resultSecond = await verify(req, options);

      expect(resultSecond.ok).toBe(true);

      if (resultSecond.ok) {
        expect(Buffer.from(resultSecond.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }
    });

    test('pre-read choices are captured before async body reading begins', async () => {
      let resolveChunkBarrier!: () => void;

      const barrierPromise = new Promise<void>((resolve) => {
        resolveChunkBarrier = resolve;
      });

      const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
          await barrierPromise;
          controller.enqueue(RAW_BODY);
          controller.close();
        },
      });

      const secrets = [GRAFANA_SECRET];

      const grafanaConfig: MutableGrafanaConfig = {
        mode: 'body',
        signatureHeader: CUSTOM_SIG_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets,
        providerOptions: grafanaConfig,
      };

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET);

      const webReq = new Request('http://localhost/async-probe', {
        method: 'POST',
        headers: { [CUSTOM_SIG_HEADER]: sig },
        body: stream,
        ...STREAM_MODE,
      } satisfies StreamRequestInit);

      // Start async verifyRequest; body reading will suspend at pull barrier.
      const verifyPromise = verifyRequest(webReq, options);

      // While body reading is suspended, mutate the caller's options and secrets.
      secrets[0] = 'corrupted-secret-while-suspended';
      grafanaConfig.signatureHeader = 'x-tampered-header';

      // Release body read barrier.
      resolveChunkBarrier();

      const result = await verifyPromise;

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('grafana');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_BODY))).toBe(true);
      }
    });
  });

  describe('Repeated normalization idempotence and preservation', () => {
    test('normalizing options multiple times preserves providerOptions and secrets identically', async () => {
      const polarConfig: PolarOptions = { secretMode: 'current' };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        toleranceSeconds: 120,
        now: () => TIMESTAMP,
        providerOptions: polarConfig,
      };

      const verifierFirst = createVerifier(options);
      const verifierSecond = createVerifier(options);

      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false);

      const headers = {
        'webhook-id': EVENT_ID,
        'webhook-timestamp': TIMESTAMP_STR,
        'webhook-signature': `v1,${sig}`,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };

      const res1 = await verifierFirst(req);
      const res2 = await verifierSecond(req);

      expect(res1.ok).toBe(true);
      expect(res2.ok).toBe(true);

      if (res1.ok && res2.ok) {
        expect(res1.provider).toBe('polar');
        expect(res2.provider).toBe('polar');
        expect(res1.identity.timestamp).toBe(TIMESTAMP);
        expect(res2.identity.timestamp).toBe(TIMESTAMP);
      }
    });

    test('express-style normalized handoff passes verified configuration intact', async () => {
      const grafanaConfig: GrafanaOptions = {
        mode: 'timestamped',
        timestampHeader: TIMESTAMP_HEADER,
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        toleranceSeconds: 60,
        now: () => TIMESTAMP,
        providerOptions: grafanaConfig,
      };

      // Simulates adapter/middleware handoff where options pass through normalization
      // before execution by core verifier.
      const verifier = createVerifier(options);

      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      const headers = {
        [DEFAULT_GRAFANA_HEADER]: sig,
        [TIMESTAMP_HEADER]: TIMESTAMP_STR,
      };

      const req: WebhookRequest = { rawBody: RAW_BODY, headers };

      const result = await verifier(req);

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.identity.timestamp).toBe(TIMESTAMP);
      }
    });
  });

  describe('Explicit toleranceSeconds: 0 stays strictly zero-width', () => {
    test('Grafana timestamped mode: tolerance 0 matches exact second and rejects ±1 second', async () => {
      const grafanaConfig: GrafanaOptions = {
        mode: 'timestamped',
        timestampHeader: TIMESTAMP_HEADER,
      };

      // 1. Exact match (delta = 0) succeeds.
      const exactOptions: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        toleranceSeconds: 0,
        now: () => TIMESTAMP,
        providerOptions: grafanaConfig,
      };

      const sigExact = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      const reqExact: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          [DEFAULT_GRAFANA_HEADER]: sigExact,
          [TIMESTAMP_HEADER]: TIMESTAMP_STR,
        },
      };

      const resExact = await verify(reqExact, exactOptions);

      expect(resExact.ok).toBe(true);

      // 2. Stale timestamp by 1 second fails with timestamp-expired.
      const staleOptions: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        toleranceSeconds: 0,
        now: () => TIMESTAMP + 1,
        providerOptions: grafanaConfig,
      };

      const resStale = await verify(reqExact, staleOptions);

      expect(resStale.ok).toBe(false);

      if (!resStale.ok) {
        expect(resStale.reason).toBe('timestamp-expired');
      }

      // 3. Future timestamp by 1 second fails with timestamp-future.
      const futureOptions: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        toleranceSeconds: 0,
        now: () => TIMESTAMP - 1,
        providerOptions: grafanaConfig,
      };

      const resFuture = await verify(reqExact, futureOptions);

      expect(resFuture.ok).toBe(false);

      if (!resFuture.ok) {
        expect(resFuture.reason).toBe('timestamp-future');
      }
    });

    test('Polar current and legacy modes: tolerance 0 matches exact second and rejects offset', async () => {
      // Polar current mode
      const polarCurrentOpts: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        toleranceSeconds: 0,
        now: () => TIMESTAMP,
        providerOptions: { secretMode: 'current' },
      };

      const sigCurrent = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false);

      const reqCurrent: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${sigCurrent}`,
        },
      };

      const resCurrentOk = await verify(reqCurrent, polarCurrentOpts);

      expect(resCurrentOk.ok).toBe(true);

      const polarCurrentStale: VerifyOptions = {
        ...polarCurrentOpts,
        now: () => TIMESTAMP + 1,
      };

      const resCurrentStale = await verify(reqCurrent, polarCurrentStale);

      expect(resCurrentStale.ok).toBe(false);

      if (!resCurrentStale.ok) {
        expect(resCurrentStale.reason).toBe('timestamp-expired');
      }

      // Polar legacy mode
      const polarLegacyOpts: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_LEGACY_SECRET],
        toleranceSeconds: 0,
        now: () => TIMESTAMP,
        providerOptions: { secretMode: 'legacy' },
      };

      const sigLegacy = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_LEGACY_SECRET, true);

      const reqLegacy: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${sigLegacy}`,
        },
      };

      const resLegacyOk = await verify(reqLegacy, polarLegacyOpts);

      expect(resLegacyOk.ok).toBe(true);

      const polarLegacyFuture: VerifyOptions = {
        ...polarLegacyOpts,
        now: () => TIMESTAMP - 1,
      };

      const resLegacyFuture = await verify(reqLegacy, polarLegacyFuture);

      expect(resLegacyFuture.ok).toBe(false);

      if (!resLegacyFuture.ok) {
        expect(resLegacyFuture.reason).toBe('timestamp-future');
      }
    });
  });

  describe('Reason precedence and rejection of layout/era/header rescue', () => {
    test('Grafana body mode does not inspect or rescue timestamp headers', async () => {
      // In body mode, signature must sign rawBody only.
      // If signature was calculated over timestamped layout, body mode fails with invalid-signature.
      const timestampedSig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          [DEFAULT_GRAFANA_HEADER]: timestampedSig,
          [TIMESTAMP_HEADER]: TIMESTAMP_STR,
        },
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        providerOptions: { mode: 'body' },
      };

      const result = await verify(req, options);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('invalid-signature');
      }
    });

    test('Grafana timestamped mode does not fall back to default header when custom signatureHeader is configured', async () => {
      const sig = signGrafana(RAW_BODY, GRAFANA_SECRET, TIMESTAMP_STR);

      // Signature placed in default header, but verifier is configured with CUSTOM_SIG_HEADER.
      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          [DEFAULT_GRAFANA_HEADER]: sig,
          [TIMESTAMP_HEADER]: TIMESTAMP_STR,
        },
      };

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP,
        providerOptions: {
          mode: 'timestamped',
          signatureHeader: CUSTOM_SIG_HEADER,
          timestampHeader: TIMESTAMP_HEADER,
        },
      };

      const result = await verify(req, options);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('missing-signature');
      }
    });

    test('Polar current mode does not attempt legacy literal secret decoding', async () => {
      // Sign with literal string bytes, but verify with Polar current mode (Base64 decode).
      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, true);

      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${sig}`,
        },
      };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        now: () => TIMESTAMP,
        providerOptions: { secretMode: 'current' },
      };

      const result = await verify(req, options);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('invalid-signature');
      }
    });

    test('Polar legacy mode does not attempt current Base64 key derivation', async () => {
      // Sign with current Base64 key, but verify with Polar legacy mode.
      const sig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false);

      const req: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${sig}`,
        },
      };

      const options: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        now: () => TIMESTAMP,
        providerOptions: { secretMode: 'legacy' },
      };

      const result = await verify(req, options);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('invalid-signature');
      }
    });

    test('MAC failure precedes expired timestamp across timestamped providers', async () => {
      const WRONG_SECRET = 'completely-wrong-synthetic-secret-999';

      // 1. Grafana timestamped mode: bad MAC + expired timestamp (stale by 10,000s)
      const badGrafanaSig = signGrafana(RAW_BODY, WRONG_SECRET, TIMESTAMP_STR);

      const grafanaReq: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          [DEFAULT_GRAFANA_HEADER]: badGrafanaSig,
          [TIMESTAMP_HEADER]: TIMESTAMP_STR,
        },
      };

      const grafanaOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP + 10000,
        providerOptions: {
          mode: 'timestamped',
          timestampHeader: TIMESTAMP_HEADER,
        },
      };

      const grafanaResult = await verify(grafanaReq, grafanaOpts);

      expect(grafanaResult.ok).toBe(false);

      if (!grafanaResult.ok) {
        expect(grafanaResult.reason).toBe('invalid-signature');
      }

      // 2. Polar current mode: bad MAC + expired timestamp
      const badPolarSig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, POLAR_CURRENT_SECRET, false)
        .replace(/^[A-Za-z0-9]/, 'Z');

      const polarReq: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${badPolarSig}`,
        },
      };

      const polarOpts: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_CURRENT_SECRET],
        now: () => TIMESTAMP + 10000,
        providerOptions: { secretMode: 'current' },
      };

      const polarResult = await verify(polarReq, polarOpts);

      expect(polarResult.ok).toBe(false);

      if (!polarResult.ok) {
        expect(polarResult.reason).toBe('invalid-signature');
      }
    });

    test('MAC failure precedes future timestamp across timestamped providers', async () => {
      const WRONG_SECRET = 'completely-wrong-synthetic-secret-999';

      // 1. Grafana timestamped mode: bad MAC + future timestamp (future by 10,000s)
      const badGrafanaSig = signGrafana(RAW_BODY, WRONG_SECRET, TIMESTAMP_STR);

      const grafanaReq: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          [DEFAULT_GRAFANA_HEADER]: badGrafanaSig,
          [TIMESTAMP_HEADER]: TIMESTAMP_STR,
        },
      };

      const grafanaOpts: VerifyOptions = {
        provider: 'grafana',
        secrets: [GRAFANA_SECRET],
        now: () => TIMESTAMP - 10000,
        providerOptions: {
          mode: 'timestamped',
          timestampHeader: TIMESTAMP_HEADER,
        },
      };

      const grafanaResult = await verify(grafanaReq, grafanaOpts);

      expect(grafanaResult.ok).toBe(false);

      if (!grafanaResult.ok) {
        expect(grafanaResult.reason).toBe('invalid-signature');
      }

      // 2. Polar legacy mode: bad MAC + future timestamp
      const badPolarSig = signPolar(RAW_BODY, EVENT_ID, TIMESTAMP_STR, 'different-literal-signing-key', true);

      const polarReq: WebhookRequest = {
        rawBody: RAW_BODY,
        headers: {
          'webhook-id': EVENT_ID,
          'webhook-timestamp': TIMESTAMP_STR,
          'webhook-signature': `v1,${badPolarSig}`,
        },
      };

      const polarOpts: VerifyOptions = {
        provider: 'polar',
        secrets: [POLAR_LEGACY_SECRET],
        now: () => TIMESTAMP - 10000,
        providerOptions: { secretMode: 'legacy' },
      };

      const polarResult = await verify(polarReq, polarOpts);

      expect(polarResult.ok).toBe(false);

      if (!polarResult.ok) {
        expect(polarResult.reason).toBe('invalid-signature');
      }
    });
  });
});
