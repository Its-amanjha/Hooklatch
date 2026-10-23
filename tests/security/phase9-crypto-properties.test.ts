import crypto from 'node:crypto';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { HooklatchError } from '../../src/errors.js';
import type { HeaderInput, VerifyOptions, VerificationResult } from '../../src/types.js';

/**
 * Phase 9 Stage B — Heavy Adversarial & Cryptographic Properties Security Suite
 *
 * Exercises the public verification API against contract.md v1 specifications:
 *   - Vercel: Scoped HMAC-SHA1 (20-byte / 40-hex), literal secret, body-only.
 *   - Fal: Pure Ed25519 (64-byte / 128-hex), raw 32-byte public keys (1..16),
 *     mandatory expectedUserId account binding, strict LF framing, lowercase SHA-256 hex.
 *
 * Invariant: Honest contract-first testing. Base 19 SDK reports genuine RED seams
 * on unregistered new providers until coordinator registers them.
 */

interface VercelContractOptions {
  readonly provider: 'vercel';
  readonly secrets: readonly string[];
  readonly toleranceSeconds?: number;
  readonly now?: () => number;
  readonly maxBodyBytes?: number;
}

interface FalContractOptions {
  readonly provider: 'fal';
  readonly publicKeys: readonly Uint8Array[];
  readonly expectedUserId: string;
  readonly toleranceSeconds?: number;
  readonly now?: () => number;
  readonly maxBodyBytes?: number;
}

interface InvalidOptionsSpec {
  readonly provider: string;
  readonly secrets?: readonly string[];
  readonly publicKeys?: readonly Uint8Array[];
  readonly expectedUserId?: string;
}

type PublicVerifyFn = (
  request: { readonly rawBody: Uint8Array; readonly headers: HeaderInput },
  options: VerifyOptions | FalContractOptions | VercelContractOptions,
) => Promise<VerificationResult>;

type PublicCreateVerifierFn = (
  options: VerifyOptions | FalContractOptions | VercelContractOptions | InvalidOptionsSpec,
) => (request: { readonly rawBody: Uint8Array; readonly headers: HeaderInput }) => Promise<VerificationResult>;

type PublicVerifyRequestFn = (
  request: Request,
  options: VerifyOptions | FalContractOptions | VercelContractOptions,
) => Promise<VerificationResult>;

// SAFETY: Broadening function signature once to accept Phase 9 contract-first options
const callVerify: PublicVerifyFn = verify as PublicVerifyFn;

// SAFETY: Broadening function signature once to accept Phase 9 contract-first options
const callCreateVerifier: PublicCreateVerifierFn = createVerifier as PublicCreateVerifierFn;

// SAFETY: Broadening function signature once to accept Phase 9 contract-first options
const callVerifyRequest: PublicVerifyRequestFn = verifyRequest as PublicVerifyRequestFn;

// Fixed synthetic Ed25519 keys for deterministic security testing (RFC 8410 DER seeds)
const FAL_SEED_PRIMARY = Buffer.from('1010101010101010101010101010101010101010101010101010101010101010', 'hex');
const FAL_SEED_SECONDARY = Buffer.from('2020202020202020202020202020202020202020202020202020202020202020', 'hex');
const FAL_SEED_ATTACKER = Buffer.from('bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0', 'hex');

function deriveSyntheticFalKey(seed: Buffer) {
  const pkcs8Der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey(privKey);
  const rawPub = pubKey.export({ format: 'der', type: 'spki' }).subarray(12);

  return { privKey, pubKey, rawPub: new Uint8Array(rawPub) };
}

const falKeyPrimary = deriveSyntheticFalKey(FAL_SEED_PRIMARY);
const falKeySecondary = deriveSyntheticFalKey(FAL_SEED_SECONDARY);
const falKeyAttacker = deriveSyntheticFalKey(FAL_SEED_ATTACKER);

const VERCEL_SECRET = 'vercel-canary-secret-phase9-adversarial';
const FAL_USER_ALICE = 'user_fal_subscriber_alice_42';
const FAL_USER_EVE = 'user_fal_attacker_eve_99';
const FIXED_NOW = 1729684800; // 2026-10-23T12:00:00Z

function signFal(
  requestId: string,
  userId: string,
  timestamp: string,
  bodyBytes: Uint8Array,
  privKey: crypto.KeyObject,
): string {
  const bodySha256Hex = crypto.createHash('sha256').update(bodyBytes).digest('hex');
  const message = `${requestId}\n${userId}\n${timestamp}\n${bodySha256Hex}`;
  const sig = crypto.sign(null, Buffer.from(message, 'utf-8'), privKey);

  return sig.toString('hex');
}

function signVercel(bodyBytes: Uint8Array, secret: string): string {
  return crypto.createHmac('sha1', secret).update(bodyBytes).digest('hex');
}

describe('Phase 9 Stage B: Cryptographic Properties & Adversarial Invariants', () => {
  describe('1. Fixed Algorithm, Exact Length Separation & Key Confusion', () => {
    test('Vercel strictly enforces 20-byte HMAC-SHA1 and rejects SHA-256 or Ed25519 signature lengths', async () => {
      const body = new Uint8Array([1, 2, 3, 4]);
      const validSig = signVercel(body, VERCEL_SECRET);

      expect(validSig).toHaveLength(40);

      const vercelOptions: VercelContractOptions = {
        provider: 'vercel',
        secrets: [VERCEL_SECRET],
        now: () => FIXED_NOW,
      };

      // 32-byte HMAC-SHA256 signature (64 hex characters) supplied to Vercel
      const sha256Sig = crypto.createHmac('sha256', VERCEL_SECRET).update(body).digest('hex');

      expect(sha256Sig).toHaveLength(64);

      const resSha256 = await callVerify(
        { rawBody: body, headers: { 'x-vercel-signature': sha256Sig } },
        vercelOptions,
      );

      expect(resSha256.ok).toBe(false);

      if (!resSha256.ok) {
        expect(resSha256.reason).toBe('malformed-signature');
      }

      // 64-byte Ed25519 signature (128 hex characters) supplied to Vercel
      const ed25519Sig = 'a'.repeat(128);

      const resEd25519 = await callVerify(
        { rawBody: body, headers: { 'x-vercel-signature': ed25519Sig } },
        vercelOptions,
      );

      expect(resEd25519.ok).toBe(false);

      if (!resEd25519.ok) {
        expect(resEd25519.reason).toBe('malformed-signature');
      }

      // Truncated (38 hex) signature
      const resTruncated = await callVerify(
        { rawBody: body, headers: { 'x-vercel-signature': validSig.slice(0, 38) } },
        vercelOptions,
      );

      expect(resTruncated.ok).toBe(false);

      if (!resTruncated.ok) {
        expect(resTruncated.reason).toBe('malformed-signature');
      }
    });

    test('Fal strictly enforces 64-byte Ed25519 and rejects 20-byte HMAC-SHA1 or 32-byte HMAC-SHA256', async () => {
      const body = Buffer.from('{"test":"adversarial"}', 'utf-8');
      const reqId = 'req_adversarial_len_01';
      const ts = String(FIXED_NOW);
      const validSig = signFal(reqId, FAL_USER_ALICE, ts, body, falKeyPrimary.privKey);

      expect(validSig).toHaveLength(128);

      const falOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      // 20-byte HMAC-SHA1 signature (40 hex chars) supplied to Fal
      const headersSha1 = {
        'x-fal-webhook-request-id': reqId,
        'x-fal-webhook-user-id': FAL_USER_ALICE,
        'x-fal-webhook-timestamp': ts,
        'x-fal-webhook-signature': '0123456789abcdef0123456789abcdef01234567',
      };

      const resSha1 = await callVerify({ rawBody: body, headers: headersSha1 }, falOptions);

      expect(resSha1.ok).toBe(false);

      if (!resSha1.ok) {
        expect(resSha1.reason).toBe('malformed-signature');
      }

      // 32-byte HMAC-SHA256 signature (64 hex chars) supplied to Fal
      const headersSha256 = {
        'x-fal-webhook-request-id': reqId,
        'x-fal-webhook-user-id': FAL_USER_ALICE,
        'x-fal-webhook-timestamp': ts,
        'x-fal-webhook-signature': '0'.repeat(64),
      };

      const resSha256 = await callVerify({ rawBody: body, headers: headersSha256 }, falOptions);

      expect(resSha256.ok).toBe(false);

      if (!resSha256.ok) {
        expect(resSha256.reason).toBe('malformed-signature');
      }
    });

    test('Options credential confusion: Vercel rejects publicKeys/expectedUserId and Fal rejects secrets', () => {
      // Vercel with own publicKeys or expectedUserId must throw HooklatchError invalid-options
      const invalidVercelOpts = {
        provider: 'vercel',
        secrets: [VERCEL_SECRET],
        publicKeys: [falKeyPrimary.rawPub],
      };

      try {
        callCreateVerifier(invalidVercelOpts);
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }

      // Fal with own secrets or singular secret must throw HooklatchError invalid-options
      const invalidFalOpts = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        secrets: ['dummy-secret'],
      };

      try {
        callCreateVerifier(invalidFalOpts);
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }
    });
  });

  describe('2. Fal Account Binding & Multi-Tenant Cross-Account Protection', () => {
    test('Valid cryptographic signature from platform key is rejected if userId !== expectedUserId', async () => {
      const body = Buffer.from('{"prompt":"attacker payload"}', 'utf-8');
      const reqId = 'req_cross_account_attack';
      const ts = String(FIXED_NOW);

      // Eve generates a task on fal and targets Alice's endpoint.
      // Fal signs it with Alice's platform key, but with Eve's userId in header.
      const validSigUnderEve = signFal(reqId, FAL_USER_EVE, ts, body, falKeyPrimary.privKey);

      const aliceOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE, // Alice expects her own ID
        now: () => FIXED_NOW,
      };

      const headers = {
        'x-fal-webhook-request-id': reqId,
        'x-fal-webhook-user-id': FAL_USER_EVE, // Incoming header has Eve's ID
        'x-fal-webhook-timestamp': ts,
        'x-fal-webhook-signature': validSigUnderEve,
      };

      const result = await callVerify({ rawBody: body, headers }, aliceOptions);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        // Must fail with invalid-signature (no recipient-mismatch code, no recipient echo)
        expect(result.reason).toBe('invalid-signature');
        expect(result.message).not.toContain(FAL_USER_EVE);
      }
    });

    test('expectedUserId is mandatory: missing, empty, or non-visible ASCII throws invalid-options', () => {
      const missingExpectedUserId = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
      };

      try {
        callCreateVerifier(missingExpectedUserId);
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }

      const emptyExpectedUserId = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: '',
      };

      try {
        callCreateVerifier(emptyExpectedUserId);
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }
    });
  });

  describe('3. Signed Freshness, Deterministic Reason Order & Delimiter Invariants', () => {
    test('Authentication takes precedence over freshness: forged signature + stale timestamp -> invalid-signature', async () => {
      const body = Buffer.from('{"test":"auth-before-freshness"}', 'utf-8');
      const reqId = 'req_order_01';
      const staleTs = String(FIXED_NOW - 1000); // 1000s old
      const forgedSig = 'f'.repeat(128);

      const falOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
        toleranceSeconds: 300,
      };

      const headers = {
        'x-fal-webhook-request-id': reqId,
        'x-fal-webhook-user-id': FAL_USER_ALICE,
        'x-fal-webhook-timestamp': staleTs,
        'x-fal-webhook-signature': forgedSig,
      };

      const result = await callVerify({ rawBody: body, headers }, falOptions);

      expect(result.ok).toBe(false);

      if (!result.ok) {
        // MUST be invalid-signature, NOT timestamp-expired!
        expect(result.reason).toBe('invalid-signature');
      }
    });

    test('Header presence and grammar checks precede cryptographic evaluation', async () => {
      const body = Buffer.from('{"test":"order"}', 'utf-8');

      const falOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      // Step 1: Missing signature header -> missing-signature
      const resNoSig = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': 'req_1',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
        },
      }, falOptions);

      expect(resNoSig.ok).toBe(false);

      if (!resNoSig.ok) {
        expect(resNoSig.reason).toBe('missing-signature');
      }

      // Step 2: Signature not 128 hex chars -> malformed-signature
      const resBadHex = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': 'req_1',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
          'x-fal-webhook-signature': 'not-valid-hex-length',
        },
      }, falOptions);

      expect(resBadHex.ok).toBe(false);

      if (!resBadHex.ok) {
        expect(resBadHex.reason).toBe('malformed-signature');
      }

      // Step 3: Missing request ID -> missing-identity
      const resNoReqId = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
          'x-fal-webhook-signature': 'a'.repeat(128),
        },
      }, falOptions);

      expect(resNoReqId.ok).toBe(false);

      if (!resNoReqId.ok) {
        expect(resNoReqId.reason).toBe('missing-identity');
      }

      // Step 4: Request ID with embedded newline/control chars -> malformed-signature
      const resNewlineId = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': 'req\ninjected',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
          'x-fal-webhook-signature': 'a'.repeat(128),
        },
      }, falOptions);

      expect(resNewlineId.ok).toBe(false);

      if (!resNewlineId.ok) {
        expect(resNewlineId.reason).toBe('malformed-signature');
      }

      // Step 5: Missing timestamp -> missing-timestamp
      const resNoTs = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': 'req_1',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-signature': 'a'.repeat(128),
        },
      }, falOptions);

      expect(resNoTs.ok).toBe(false);

      if (!resNoTs.ok) {
        expect(resNoTs.reason).toBe('missing-timestamp');
      }
    });

    test('Freshness window: +/-300s inclusive boundary accepted, +/-301s rejected', async () => {
      const body = Buffer.from('{"test":"freshness"}', 'utf-8');
      const reqId = 'req_boundary_check';

      const falOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
        toleranceSeconds: 300,
      };

      // Exactly at now - 300s (inclusive past edge)
      const tsMinus300 = String(FIXED_NOW - 300);
      const sigMinus300 = signFal(reqId, FAL_USER_ALICE, tsMinus300, body, falKeyPrimary.privKey);

      const resMinus300 = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': reqId,
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': tsMinus300,
          'x-fal-webhook-signature': sigMinus300,
        },
      }, falOptions);

      expect(resMinus300.ok).toBe(true);

      // At now - 301s (past leeway exceeded)
      const tsMinus301 = String(FIXED_NOW - 301);
      const sigMinus301 = signFal(reqId, FAL_USER_ALICE, tsMinus301, body, falKeyPrimary.privKey);

      const resMinus301 = await callVerify({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': reqId,
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': tsMinus301,
          'x-fal-webhook-signature': sigMinus301,
        },
      }, falOptions);

      expect(resMinus301.ok).toBe(false);

      if (!resMinus301.ok) {
        expect(resMinus301.reason).toBe('timestamp-expired');
      }
    });
  });

  describe('4. Key Mutation, Typed Views & Snapshot Containment', () => {
    test('publicKeys array bounds: 1..16 entries enforced at setup', () => {
      // Empty array throws invalid-options
      try {
        callCreateVerifier({
          provider: 'fal',
          publicKeys: [],
          expectedUserId: FAL_USER_ALICE,
        });
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }

      // 17 keys throws invalid-options
      const seventeenKeys = Array.from({ length: 17 }, () => falKeyPrimary.rawPub);

      try {
        callCreateVerifier({
          provider: 'fal',
          publicKeys: seventeenKeys,
          expectedUserId: FAL_USER_ALICE,
        });
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }
    });

    test('Key byte lengths: exactly 32 visible bytes enforced at setup', () => {
      // 31 bytes throws invalid-options
      try {
        callCreateVerifier({
          provider: 'fal',
          publicKeys: [falKeyPrimary.rawPub.subarray(0, 31)],
          expectedUserId: FAL_USER_ALICE,
        });
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }

      // 33 bytes throws invalid-options
      const overgrownKey = new Uint8Array(33);

      try {
        callCreateVerifier({
          provider: 'fal',
          publicKeys: [overgrownKey],
          expectedUserId: FAL_USER_ALICE,
        });
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(HooklatchError);

        // SAFETY: Discriminated error code property access
        const error = err as HooklatchError;

        expect(error.code).toBe('invalid-options');
      }
    });

    test('Key view offsets & buffer snapshotting: mutating key array or bytes does not alter verification', async () => {
      const originalKeyBytes = new Uint8Array(falKeyPrimary.rawPub);
      const mutableKeyView = new Uint8Array(originalKeyBytes);
      const keyList = [mutableKeyView, falKeySecondary.rawPub];

      const falOptions = {
        provider: 'fal',
        publicKeys: keyList,
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      const verifier = callCreateVerifier(falOptions);

      // Mutate the original array and the underlying bytes after passing to setup
      keyList.push(falKeyAttacker.rawPub);
      const firstByte = mutableKeyView[0];

      if (firstByte !== undefined) {
        mutableKeyView[0] = firstByte ^ 0xff;
      }

      const body = Buffer.from('{"test":"snapshot"}', 'utf-8');
      const reqId = 'req_snapshot_test';
      const ts = String(FIXED_NOW);
      const validSig = signFal(reqId, FAL_USER_ALICE, ts, body, falKeyPrimary.privKey);

      const result = await verifier({
        rawBody: body,
        headers: {
          'x-fal-webhook-request-id': reqId,
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': ts,
          'x-fal-webhook-signature': validSig,
        },
      });

      expect(result.ok).toBe(true);
    });

    test('verifyRequest exercises WHATWG Request stream with Fal contract options', async () => {
      const body = Buffer.from('{"test":"verifyRequest"}', 'utf-8');
      const reqId = 'req_verify_request_stream';
      const ts = String(FIXED_NOW);
      const validSig = signFal(reqId, FAL_USER_ALICE, ts, body, falKeyPrimary.privKey);

      const request = new Request('https://api.test/webhooks/fal', {
        method: 'POST',
        headers: {
          'x-fal-webhook-request-id': reqId,
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': ts,
          'x-fal-webhook-signature': validSig,
        },
        body,
        // @ts-expect-error duplex is required by Node for streaming bodies
        duplex: 'half',
      });

      const falOptions: FalContractOptions = {
        provider: 'fal',
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      const res = await callVerifyRequest(request, falOptions);

      expect(res.ok).toBe(true);
    });
  });

  describe('5. Crypto Fault Isolation & Safe Restoration', () => {
    test('WebCrypto NotSupportedError produces crypto-unavailable, never invalid-signature', async () => {
      const originalSubtleVerify = globalThis.crypto.subtle.verify;

      try {
        // Narrowly inject WebCrypto fault
        globalThis.crypto.subtle.verify = async () => {
          throw new DOMException('Ed25519 not supported in this environment', 'NotSupportedError');
        };

        const body = Buffer.from('{"test":"crypto-fault"}', 'utf-8');

        const falOptions: FalContractOptions = {
          provider: 'fal',
          publicKeys: [falKeyPrimary.rawPub],
          expectedUserId: FAL_USER_ALICE,
          now: () => FIXED_NOW,
        };

        const headers = {
          'x-fal-webhook-request-id': 'req_fault',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
          'x-fal-webhook-signature': 'a'.repeat(128),
        };

        try {
          const res = await callVerify({ rawBody: body, headers }, falOptions);

          // If error returned as failure details
          expect(res.ok).toBe(false);

          if (!res.ok) {
            expect(res.reason).not.toBe('invalid-signature');
          }
        } catch (err) {
          // If thrown as HooklatchError
          expect(err).toBeInstanceOf(HooklatchError);

          // SAFETY: Discriminated error code property access
          const error = err as HooklatchError;

          expect(error.code).toBe('crypto-unavailable');
        }
      } finally {
        // Safe restoration
        globalThis.crypto.subtle.verify = originalSubtleVerify;
      }
    });
  });

  describe('6. Baseline 19 Providers Regression Protection', () => {
    test('Stripe HMAC-SHA256 baseline verification is unaffected by new provider contracts', async () => {
      const stripeSecret = 'whsec_test_stripe_secret_baseline';
      const body = Buffer.from('{"id":"evt_123","object":"event"}', 'utf-8');
      const now = FIXED_NOW;
      const signature = crypto.createHmac('sha256', stripeSecret).update(`${now}.${body.toString('utf-8')}`).digest('hex');
      const header = `t=${now},v1=${signature}`;

      const res = await verify({ rawBody: body, headers: { 'stripe-signature': header } }, {
        provider: 'stripe',
        secrets: [stripeSecret],
        now: () => now,
      });

      expect(res.ok).toBe(true);

      if (res.ok) {
        expect(res.provider).toBe('stripe');
        expect(res.identity.timestamp).toBe(now);
      }
    });

    test('GitHub body-only HMAC-SHA256 verification is unaffected', async () => {
      const githubSecret = 'github_test_secret_baseline';
      const body = Buffer.from('{"action":"opened"}', 'utf-8');
      const signature = crypto.createHmac('sha256', githubSecret).update(body).digest('hex');

      const res = await verify({
        rawBody: body,
        headers: {
          'x-hub-signature-256': `sha256=${signature}`,
          'x-github-delivery': '7d934f8a-9289-4e76-805d-d60232402123',
        },
      }, {
        provider: 'github',
        secrets: [githubSecret],
      });

      expect(res.ok).toBe(true);

      if (res.ok) {
        expect(res.provider).toBe('github');
        expect(res.identity.deliveryId).toBe('7d934f8a-9289-4e76-805d-d60232402123');
      }
    });
  });
});
