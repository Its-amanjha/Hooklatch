import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { verify, verifyRequest, createVerifier, HooklatchError } from '../../src/index.js';
import type {
  HeaderInput,
  VerificationResult,
  VerifyOptions,
  WebhookRequest,
} from '../../src/index.js';

interface StreamRequestInit extends RequestInit {
  duplex: 'half';
}

const STREAM_MODE: StreamRequestInit = { duplex: 'half' };

const LINEAR_SECRET = 'linear-public-synthetic-secret-2026';
const ROTATED_SECRET = 'linear-rotated-synthetic-secret-2026';
const OUTSIDER_SECRET = 'linear-outsider-synthetic-secret-2026';

const RAW_PAYLOAD = new TextEncoder().encode('{"action":"create","type":"Issue","data":{"id":"issue_123"}}');
const EMPTY_PAYLOAD = new Uint8Array(0);
const BINARY_PAYLOAD = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0x7f, 0x01, 0x02, 0x03]);
const INVALID_JSON_PAYLOAD = new TextEncoder().encode('not-json-payload-{{{');

/** Independent test-only HMAC-SHA256 hex signer for Linear. */
function signLinear(
  body: Uint8Array,
  secret: string = LINEAR_SECRET,
): string {
  return createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(body)
    .digest('hex');
}

function expectErrorCodeSync(run: () => void, expectedCode: string): void {
  let thrown: unknown;

  try {
    run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);
  // SAFETY: thrown was asserted to be HooklatchError above.
  const err = thrown as HooklatchError;
  expect(err.code).toBe(expectedCode);
}

async function expectErrorCodeAsync(
  run: () => Promise<VerificationResult | void>,
  expectedCode: string,
): Promise<void> {
  let thrown: unknown;

  try {
    await run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);
  // SAFETY: thrown was asserted to be HooklatchError above.
  const err = thrown as HooklatchError;
  expect(err.code).toBe(expectedCode);
}

describe('Phase 8 Stage A — Linear Public-Root Verification Contract', () => {
  describe('Public API Entry Points (verify, verifyRequest, createVerifier)', () => {
    test('verifies standard payload across all three public entry points', async () => {
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);
      const headers = { 'linear-signature': sig };

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // 1. verify(request, options)
      const req: WebhookRequest = { rawBody: RAW_PAYLOAD, headers };
      const resVerify = await verify(req, options);

      expect(resVerify.ok).toBe(true);

      if (resVerify.ok) {
        expect(resVerify.provider).toBe('linear');
        expect(Buffer.from(resVerify.rawBody).equals(Buffer.from(RAW_PAYLOAD))).toBe(true);
        expect(resVerify.identity).toEqual({
          deliveryId: null,
          eventId: null,
          timestamp: null,
          authenticatedFields: [],
        });
      }

      // 2. verifyRequest(webRequest, options)
      const webReq = new Request('http://localhost/webhook/linear', {
        method: 'POST',
        headers,
        body: RAW_PAYLOAD,
      });

      const resWeb = await verifyRequest(webReq, options);

      expect(resWeb.ok).toBe(true);

      if (resWeb.ok) {
        expect(resWeb.provider).toBe('linear');
        expect(Buffer.from(resWeb.rawBody).equals(Buffer.from(RAW_PAYLOAD))).toBe(true);
        expect(resWeb.identity.deliveryId).toBeNull();
        expect(resWeb.identity.eventId).toBeNull();
        expect(resWeb.identity.timestamp).toBeNull();
        expect(resWeb.identity.authenticatedFields).toEqual([]);
      }

      // 3. createVerifier(options)(request)
      const verifier = createVerifier(options);
      const resCreated = await verifier(req);

      expect(resCreated.ok).toBe(true);

      if (resCreated.ok) {
        expect(resCreated.provider).toBe('linear');
        expect(Buffer.from(resCreated.rawBody).equals(Buffer.from(RAW_PAYLOAD))).toBe(true);
      }
    });
  });

  describe('Input Representations & Headers Trimming Outcomes', () => {
    test('verifies case-insensitive header lookup across record and tuple inputs', async () => {
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Mixed-case header in Record
      const recordReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'Linear-Signature': sig },
      };

      const resRecord = await verify(recordReq, options);

      expect(resRecord.ok).toBe(true);

      // Uppercase header in tuple array
      const tupleHeaders: HeaderInput = [['LINEAR-SIGNATURE', sig]];

      const tupleReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: tupleHeaders,
      };

      const resTuple = await verify(tupleReq, options);

      expect(resTuple.ok).toBe(true);

      // WHATWG Headers object
      const webHeaders = new Headers({ 'linear-signature': sig });

      const headersReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: webHeaders,
      };

      const resHeaders = await verify(headersReq, options);

      expect(resHeaders.ok).toBe(true);
    });

    test('explicit trimming outcome: padded signature fails in raw record but passes via Headers', async () => {
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);
      const paddedSig = `  ${sig}  `;

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Raw record preserves outer whitespace; Linear requires strict 64 hex characters -> malformed-signature
      const rawReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': paddedSig },
      };

      const resRaw = await verify(rawReq, options);

      expect(resRaw.ok).toBe(false);

      if (!resRaw.ok) {
        expect(resRaw.reason).toBe('malformed-signature');
      }

      // Tuple representation also preserves outer whitespace -> malformed-signature
      const tupleReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: [['linear-signature', paddedSig]],
      };

      const resTuple = await verify(tupleReq, options);

      expect(resTuple.ok).toBe(false);

      if (!resTuple.ok) {
        expect(resTuple.reason).toBe('malformed-signature');
      }

      // WHATWG Headers constructor normalizes header values by trimming outer whitespace according to RFC spec
      // When consumed as Headers, the value becomes exactly 64 hex characters -> ok: true
      const webHeaders = new Headers({ 'linear-signature': paddedSig });

      const webReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: webHeaders,
      };

      const resWeb = await verify(webReq, options);

      expect(resWeb.ok).toBe(true);
    });
  });

  describe('Signature Grammar Boundaries (Missing vs Malformed vs Invalid)', () => {
    test('missing or trim-blank signature header yields missing-signature', async () => {
      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Completely absent header
      const absentReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: {},
      };

      const resAbsent = await verify(absentReq, options);

      expect(resAbsent.ok).toBe(false);

      if (!resAbsent.ok) {
        expect(resAbsent.reason).toBe('missing-signature');
      }

      // Empty string
      const emptyReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': '' },
      };

      const resEmpty = await verify(emptyReq, options);

      expect(resEmpty.ok).toBe(false);

      if (!resEmpty.ok) {
        expect(resEmpty.reason).toBe('missing-signature');
      }

      // Trim-blank string
      const blankReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': '   \t  ' },
      };

      const resBlank = await verify(blankReq, options);

      expect(resBlank.ok).toBe(false);

      if (!resBlank.ok) {
        expect(resBlank.reason).toBe('missing-signature');
      }
    });

    test('malformed signature: wrong length, non-hex, prefixes, commas', async () => {
      const validSig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      const malformedCases: readonly string[] = [
        `sha256=${validSig}`,
        `v1=${validSig}`,
        `v1,${validSig}`,
        validSig.slice(0, 63), // 63 chars (too short)
        `${validSig}a`, // 65 chars (too long)
        validSig.replace(/[a-f0-9]/, 'x'), // non-hex character
        validSig.replace(/[a-f0-9]/, 'z'), // non-hex character
        `${validSig},${validSig}`, // comma-separated list
      ];

      for (const badSig of malformedCases) {
        const req: WebhookRequest = {
          rawBody: RAW_PAYLOAD,
          headers: { 'linear-signature': badSig },
        };

        const res = await verify(req, options);

        expect(res.ok).toBe(false);

        if (!res.ok) {
          expect(res.reason).toBe('malformed-signature');
        }
      }
    });

    test('accepts uppercase and mixed-case 64-character ASCII hex signatures', async () => {
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Uppercase hex
      const upperReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sig.toUpperCase() },
      };

      const resUpper = await verify(upperReq, options);

      expect(resUpper.ok).toBe(true);

      // Mixed-case hex
      const mixedSig = sig.split('').map((char, i) => (i % 2 === 0 ? char.toUpperCase() : char.toLowerCase())).join('');

      const mixedReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': mixedSig },
      };

      const resMixed = await verify(mixedReq, options);

      expect(resMixed.ok).toBe(true);
    });

    test('well-formed 64-hex signature from non-matching secret yields invalid-signature', async () => {
      const outsiderSig = signLinear(RAW_PAYLOAD, OUTSIDER_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      const req: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': outsiderSig },
      };

      const res = await verify(req, options);

      expect(res.ok).toBe(false);

      if (!res.ok) {
        expect(res.reason).toBe('invalid-signature');
      }
    });
  });

  describe('Exact Raw-Byte Authentication & No JSON/Freshness Parsing', () => {
    test('authenticates arbitrary binary, empty, and invalid-JSON payloads when MAC matches', async () => {
      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Binary payload
      const binarySig = signLinear(BINARY_PAYLOAD, LINEAR_SECRET);

      const binaryReq: WebhookRequest = {
        rawBody: BINARY_PAYLOAD,
        headers: { 'linear-signature': binarySig },
      };

      const resBinary = await verify(binaryReq, options);

      expect(resBinary.ok).toBe(true);

      if (resBinary.ok) {
        expect(Buffer.from(resBinary.rawBody).equals(Buffer.from(BINARY_PAYLOAD))).toBe(true);
      }

      // Empty payload
      const emptySig = signLinear(EMPTY_PAYLOAD, LINEAR_SECRET);

      const emptyReq: WebhookRequest = {
        rawBody: EMPTY_PAYLOAD,
        headers: { 'linear-signature': emptySig },
      };

      const resEmpty = await verify(emptyReq, options);

      expect(resEmpty.ok).toBe(true);

      if (resEmpty.ok) {
        expect(resEmpty.rawBody.length).toBe(0);
      }

      // Invalid JSON payload
      const invalidJsonSig = signLinear(INVALID_JSON_PAYLOAD, LINEAR_SECRET);

      const invalidJsonReq: WebhookRequest = {
        rawBody: INVALID_JSON_PAYLOAD,
        headers: { 'linear-signature': invalidJsonSig },
      };

      const resInvalidJson = await verify(invalidJsonReq, options);

      expect(resInvalidJson.ok).toBe(true);

      if (resInvalidJson.ok) {
        expect(Buffer.from(resInvalidJson.rawBody).equals(Buffer.from(INVALID_JSON_PAYLOAD))).toBe(true);
      }
    });

    test('signed JSON with stale timestamp and fresh unsigned headers does not perform freshness validation', async () => {
      // Body contains a stale timestamp in JSON claims; unsigned header contains fresh timestamp.
      // Linear verification is body-only authentication; no JSON parsing or freshness enforcement.
      const staleBodyText = JSON.stringify({
        action: 'Issue.update',
        webhookTimestamp: 1000000000000,
        webhookId: 'hooklatch-linear-webhook-configuration',
        data: { id: 'iss_stale' },
      });

      const staleBody = new TextEncoder().encode(staleBodyText);
      const sig = signLinear(staleBody, LINEAR_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
        // toleranceSeconds and now must not trigger freshness rejection for Linear
        toleranceSeconds: 60,
        now: () => 1792368000,
      };

      const req: WebhookRequest = {
        rawBody: staleBody,
        headers: {
          'linear-signature': sig,
          'linear-timestamp': '1792368000000',
          'Linear-Delivery': 'del_12345',
          'Linear-Event': 'Issue',
        },
      };

      const res = await verify(req, options);

      expect(res.ok).toBe(true);

      if (res.ok) {
        expect(res.provider).toBe('linear');
        expect(Buffer.from(res.rawBody).equals(Buffer.from(staleBody))).toBe(true);
        // Identity fields must remain null; no extraction from body or headers
        expect(res.identity).toEqual({
          deliveryId: null,
          eventId: null,
          timestamp: null,
          authenticatedFields: [],
        });
      }
    });
  });

  describe('Secret Rotation, Literal Secrets, and Caller Snapshots', () => {
    test('secret rotation: verifies against any valid key in secrets array', async () => {
      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [ROTATED_SECRET, LINEAR_SECRET],
      };

      // Signed with primary secret
      const sigPrimary = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const reqPrimary: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sigPrimary },
      };

      const resPrimary = await verify(reqPrimary, options);

      expect(resPrimary.ok).toBe(true);

      // Signed with rotated secret
      const sigRotated = signLinear(RAW_PAYLOAD, ROTATED_SECRET);

      const reqRotated: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sigRotated },
      };

      const resRotated = await verify(reqRotated, options);

      expect(resRotated.ok).toBe(true);

      // Signed with outsider secret
      const sigOutsider = signLinear(RAW_PAYLOAD, OUTSIDER_SECRET);

      const reqOutsider: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sigOutsider },
      };

      const resOutsider = await verify(reqOutsider, options);

      expect(resOutsider.ok).toBe(false);

      if (!resOutsider.ok) {
        expect(resOutsider.reason).toBe('invalid-signature');
      }
    });

    test('literal untrimmed and non-ASCII secrets are preserved exactly', async () => {
      const spacedSecret = '  spaced secret key  ';
      const sigSpaced = signLinear(RAW_PAYLOAD, spacedSecret);

      const optionsSpaced: VerifyOptions = {
        provider: 'linear',
        secrets: [spacedSecret],
      };

      const reqSpaced: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sigSpaced },
      };

      const resSpaced = await verify(reqSpaced, optionsSpaced);

      expect(resSpaced.ok).toBe(true);

      // Non-ASCII UTF-8 secret
      const unicodeSecret = 'linear-secret-🔑-認証鍵';
      const sigUnicode = signLinear(RAW_PAYLOAD, unicodeSecret);

      const optionsUnicode: VerifyOptions = {
        provider: 'linear',
        secrets: [unicodeSecret],
      };

      const reqUnicode: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sigUnicode },
      };

      const resUnicode = await verify(reqUnicode, optionsUnicode);

      expect(resUnicode.ok).toBe(true);
    });

    test('mutating secrets array after creating verifier does not affect verification', async () => {
      const secrets = [LINEAR_SECRET];

      const options: VerifyOptions = {
        provider: 'linear',
        secrets,
      };

      const verifier = createVerifier(options);

      // Mutate caller array
      secrets[0] = 'corrupted-secret';
      secrets.push('extra-key');

      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const req: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: { 'linear-signature': sig },
      };

      const res = await verifier(req);

      expect(res.ok).toBe(true);
    });

    test('verifies exact visible Uint8Array slice regardless of surrounding buffer mutations', async () => {
      const backing = new Uint8Array(RAW_PAYLOAD.length + 32);
      backing.fill(0xaa, 0, 16);
      backing.fill(0xbb, 16 + RAW_PAYLOAD.length);
      backing.set(RAW_PAYLOAD, 16);

      const slice = backing.subarray(16, 16 + RAW_PAYLOAD.length);
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      const req: WebhookRequest = {
        rawBody: slice,
        headers: { 'linear-signature': sig },
      };

      const res = await verify(req, options);

      expect(res.ok).toBe(true);

      if (res.ok) {
        expect(res.rawBody.length).toBe(RAW_PAYLOAD.length);
        expect(Buffer.from(res.rawBody).equals(Buffer.from(RAW_PAYLOAD))).toBe(true);
      }

      // Mutate buffer outside visible slice
      backing[0] = 0x12;
      backing[backing.length - 1] = 0x34;

      const resSecond = await verify(req, options);

      expect(resSecond.ok).toBe(true);
    });

    test('captures options and secret snapshot before async streaming body reading begins', async () => {
      let resolveChunkBarrier!: () => void;

      const barrierPromise = new Promise<void>((resolve) => {
        resolveChunkBarrier = resolve;
      });

      const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
          await barrierPromise;
          controller.enqueue(RAW_PAYLOAD);
          controller.close();
        },
      });

      const secrets = [LINEAR_SECRET];

      const options: VerifyOptions = {
        provider: 'linear',
        secrets,
      };

      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const webReq = new Request('http://localhost/async-linear', {
        method: 'POST',
        headers: { 'linear-signature': sig },
        body: stream,
        ...STREAM_MODE,
      } satisfies StreamRequestInit);

      const verifyPromise = verifyRequest(webReq, options);

      // Mutate caller's secrets while stream is suspended at barrier
      secrets[0] = 'corrupted-key-during-suspend';

      resolveChunkBarrier();

      const result = await verifyPromise;

      expect(result.ok).toBe(true);

      if (result.ok) {
        expect(result.provider).toBe('linear');
        expect(Buffer.from(result.rawBody).equals(Buffer.from(RAW_PAYLOAD))).toBe(true);
      }
    });
  });

  describe('Selected-Provider Isolation, Body Limits, and Setup Ordering', () => {
    test('linear verifier isolates from alien provider signature headers', async () => {
      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
      };

      // Request with Stripe and GitHub signature headers but no linear-signature
      const alienReq: WebhookRequest = {
        rawBody: RAW_PAYLOAD,
        headers: {
          'stripe-signature': 't=123,v1=abcdef',
          'x-hub-signature-256': 'sha256=abcdef',
          'webhook-signature': 'v1,abcdef',
        },
      };

      const res = await verify(alienReq, options);

      expect(res.ok).toBe(false);

      if (!res.ok) {
        expect(res.reason).toBe('missing-signature');
      }
    });

    test('enforces maxBodyBytes limits on verifyRequest', async () => {
      const sig = signLinear(RAW_PAYLOAD, LINEAR_SECRET);

      const webReq = new Request('http://localhost/limit-test', {
        method: 'POST',
        headers: { 'linear-signature': sig },
        body: RAW_PAYLOAD,
      });

      const options: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
        maxBodyBytes: 10, // payload is > 10 bytes
      };

      const res = await verifyRequest(webReq, options);

      expect(res.ok).toBe(false);

      if (!res.ok) {
        expect(res.reason).toBe('body-too-large');
      }
    });

    test('linear provider accepts NO providerOptions (throws invalid-options)', () => {
      // Linear is a simple body-only provider and accepts no providerOptions.
      // SAFETY: Deliberately passing providerOptions to verify rejection on Linear.
      const optsWithConfig: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
        providerOptions: { mode: 'body' } as never,
      };

      expectErrorCodeSync(() => createVerifier(optsWithConfig), 'invalid-options');

      // SAFETY: Empty providerOptions object must also be rejected.
      const optsWithEmptyConfig: VerifyOptions = {
        provider: 'linear',
        secrets: [LINEAR_SECRET],
        providerOptions: {} as never,
      };

      expectErrorCodeSync(() => createVerifier(optsWithEmptyConfig), 'invalid-options');
    });

    test('setup ordering: basic secret validation precedes configuration rejection', () => {
      // Empty secrets throws missing-secrets
      const emptySecretsOpts: VerifyOptions = {
        provider: 'linear',
        secrets: [],
      };

      expectErrorCodeSync(() => createVerifier(emptySecretsOpts), 'missing-secrets');

      // Empty secret string throws invalid-secret
      const invalidSecretOpts: VerifyOptions = {
        provider: 'linear',
        secrets: [''],
      };

      expectErrorCodeSync(() => createVerifier(invalidSecretOpts), 'invalid-secret');

      // Empty secrets takes precedence even if invalid providerOptions are supplied
      // SAFETY: Empty secrets with invalid providerOptions to test precedence.
      const precedenceOpts: VerifyOptions = {
        provider: 'linear',
        secrets: [],
        providerOptions: { invalid: true } as never,
      };

      expectErrorCodeSync(() => createVerifier(precedenceOpts), 'missing-secrets');
    });

    test('verifyRequest rejects setup errors before any stream consumption', async () => {
      let pulls = 0;

      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          controller.enqueue(RAW_PAYLOAD);
          controller.close();
        },
      }, { highWaterMark: 0 });

      const request = new Request('https://hooklatch.test/webhook', {
        ...STREAM_MODE, method: 'POST', body,
      });

      const missingSecretsOpts: VerifyOptions = {
        provider: 'linear',
        secrets: [],
      };

      await expectErrorCodeAsync(() => verifyRequest(request, missingSecretsOpts), 'missing-secrets');
      expect(pulls).toBe(0);
      expect(request.bodyUsed).toBe(false);
      await body.cancel();
    });
  });
});
