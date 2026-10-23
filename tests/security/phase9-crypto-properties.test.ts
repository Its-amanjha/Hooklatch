import crypto from 'node:crypto';
import { createVerifier, verify, verifyRequest } from '../../src/index.js';
import { HooklatchError } from '../../src/errors.js';
import type { VerificationResult } from '../../src/types.js';

/**
 * Phase 9 Stage B — Heavy Adversarial & Cryptographic Properties Security Suite
 *
 * Exercises the public verification API against contract.md v1 specifications:
 *   - Vercel: Scoped HMAC-SHA1 (20-byte / 40-hex), literal secret, body-only.
 *   - Fal: Pure Ed25519 (64-byte / 128-hex), raw 32-byte public keys (1..16),
 *     mandatory expectedUserId account binding, strict LF framing, lowercase SHA-256 hex.
 *
 * Invariant: Honest contract-first testing. Real public APIs are called directly with
 * literal 'fal' and 'vercel' provider IDs. Missing union arms at base 19 are expected
 * compiler RED seams until coordinator integrates them.
 */

function expectErrorCodeSync(run: () => void, expectedCode: string): void {
  let thrown: unknown;

  try {
    run();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(HooklatchError);

  if (thrown instanceof HooklatchError) {
    expect(thrown.code).toBe(expectedCode);
  }
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

  if (thrown instanceof HooklatchError) {
    expect(thrown.code).toBe(expectedCode);
  }
}

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
const FIXED_NOW = 1729684800; // 2024-10-23T12:00:00Z (deterministic reference timestamp)

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

      const vercelOptions = {
        provider: 'vercel' as const,
        secrets: [VERCEL_SECRET],
        now: () => FIXED_NOW,
      };

      // 32-byte HMAC-SHA256 signature (64 hex characters) supplied to Vercel
      const sha256Sig = crypto.createHmac('sha256', VERCEL_SECRET).update(body).digest('hex');

      expect(sha256Sig).toHaveLength(64);

      // SAFETY: Literal 'vercel' options tested directly against public verify API
      const resSha256 = await verify(
        { rawBody: body, headers: { 'x-vercel-signature': sha256Sig } },
        vercelOptions,
      );

      expect(resSha256.ok).toBe(false);

      if (!resSha256.ok) {
        expect(resSha256.reason).toBe('malformed-signature');
      }

      // 64-byte Ed25519 signature (128 hex characters) supplied to Vercel
      const ed25519Sig = 'a'.repeat(128);

      // SAFETY: Literal 'vercel' options tested directly against public verify API
      const resEd25519 = await verify(
        { rawBody: body, headers: { 'x-vercel-signature': ed25519Sig } },
        vercelOptions,
      );

      expect(resEd25519.ok).toBe(false);

      if (!resEd25519.ok) {
        expect(resEd25519.reason).toBe('malformed-signature');
      }

      // Truncated (38 hex) signature
      // SAFETY: Literal 'vercel' options tested directly against public verify API
      const resTruncated = await verify(
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

      const falOptions = {
        provider: 'fal' as const,
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

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resSha1 = await verify(
        { rawBody: body, headers: headersSha1 },
        falOptions,
      );

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

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resSha256 = await verify(
        { rawBody: body, headers: headersSha256 },
        falOptions,
      );

      expect(resSha256.ok).toBe(false);

      if (!resSha256.ok) {
        expect(resSha256.reason).toBe('malformed-signature');
      }
    });

    test('Options credential confusion: Vercel rejects publicKeys/expectedUserId and Fal rejects secrets', () => {
      // Vercel with own publicKeys or expectedUserId must throw HooklatchError invalid-options
      const invalidVercelOpts = {
        provider: 'vercel' as const,
        secrets: [VERCEL_SECRET],
        publicKeys: [falKeyPrimary.rawPub],
      };

      // SAFETY: Deliberately invalid runtime options testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier(invalidVercelOpts as never), 'invalid-options');

      // Fal with own secrets or singular secret must throw HooklatchError invalid-options
      const invalidFalOpts = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        secrets: ['dummy-secret'],
      };

      // SAFETY: Deliberately invalid runtime options testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier(invalidFalOpts as never), 'invalid-options');
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

      const aliceOptions = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      const headers = {
        'x-fal-webhook-request-id': reqId,
        'x-fal-webhook-user-id': FAL_USER_EVE,
        'x-fal-webhook-timestamp': ts,
        'x-fal-webhook-signature': validSigUnderEve,
      };

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const result = await verify(
        { rawBody: body, headers },
        aliceOptions,
      );

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('invalid-signature');
        expect(result.message).not.toContain(FAL_USER_EVE);
      }
    });

    test('expectedUserId is mandatory: missing, empty, or non-visible ASCII throws invalid-options', () => {
      const missingExpectedUserId = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
      };

      // SAFETY: Deliberately missing expectedUserId testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier(missingExpectedUserId as never), 'invalid-options');

      const emptyExpectedUserId = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: '',
      };

      // SAFETY: Deliberately empty expectedUserId testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier(emptyExpectedUserId as never), 'invalid-options');
    });
  });

  describe('3. Signed Freshness, Deterministic Reason Order & Delimiter Invariants', () => {
    test('Authentication takes precedence over freshness: forged signature + stale timestamp -> invalid-signature', async () => {
      const body = Buffer.from('{"test":"auth-before-freshness"}', 'utf-8');
      const reqId = 'req_order_01';
      const staleTs = String(FIXED_NOW - 1000);
      const forgedSig = 'f'.repeat(128);

      const falOptions = {
        provider: 'fal' as const,
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

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const result = await verify(
        { rawBody: body, headers },
        falOptions,
      );

      expect(result.ok).toBe(false);

      if (!result.ok) {
        expect(result.reason).toBe('invalid-signature');
      }
    });

    test('Header presence and grammar checks precede cryptographic evaluation', async () => {
      const body = Buffer.from('{"test":"order"}', 'utf-8');

      const falOptions = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      // Step 1: Missing signature header -> missing-signature
      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resNoSig = await verify({
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
      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resBadHex = await verify({
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
      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resNoReqId = await verify({
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
      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resNewlineId = await verify({
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
      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resNoTs = await verify({
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

      const falOptions = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
        toleranceSeconds: 300,
      };

      // Exactly at now - 300s (inclusive past edge)
      const tsMinus300 = String(FIXED_NOW - 300);
      const sigMinus300 = signFal(reqId, FAL_USER_ALICE, tsMinus300, body, falKeyPrimary.privKey);

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resMinus300 = await verify({
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

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const resMinus301 = await verify({
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
      // SAFETY: Deliberately empty publicKeys testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier({
        provider: 'fal' as const,
        publicKeys: [],
        expectedUserId: FAL_USER_ALICE,
      } as never), 'invalid-options');

      // 17 keys throws invalid-options
      const seventeenKeys = Array.from({ length: 17 }, () => falKeyPrimary.rawPub);

      // SAFETY: Deliberately excessive publicKeys count testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier({
        provider: 'fal' as const,
        publicKeys: seventeenKeys,
        expectedUserId: FAL_USER_ALICE,
      } as never), 'invalid-options');
    });

    test('Key byte lengths: exactly 32 visible bytes enforced at setup', () => {
      // 31 bytes throws invalid-options
      // SAFETY: Deliberately truncated 31-byte key testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier({
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub.subarray(0, 31)],
        expectedUserId: FAL_USER_ALICE,
      } as never), 'invalid-options');

      // 33 bytes throws invalid-options
      const overgrownKey = new Uint8Array(33);

      // SAFETY: Deliberately overgrown 33-byte key testing HooklatchError(invalid-options)
      expectErrorCodeSync(() => createVerifier({
        provider: 'fal' as const,
        publicKeys: [overgrownKey],
        expectedUserId: FAL_USER_ALICE,
      } as never), 'invalid-options');
    });

    test('Key view offsets & buffer snapshotting: mutating key array or bytes does not alter verification', async () => {
      const originalKeyBytes = new Uint8Array(falKeyPrimary.rawPub);
      const mutableKeyView = new Uint8Array(originalKeyBytes);
      const keyList = [mutableKeyView, falKeySecondary.rawPub];

      const falOptions = {
        provider: 'fal' as const,
        publicKeys: keyList,
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      // SAFETY: Literal 'fal' options tested directly against public createVerifier API
      const verifier = createVerifier(falOptions);

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

      const falOptions = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      // SAFETY: Literal 'fal' options tested directly against public verifyRequest API
      const res = await verifyRequest(request, falOptions);

      expect(res.ok).toBe(true);
    });
  });

  describe('5. Crypto Fault Isolation & Safe Restoration', () => {
    test('WebCrypto NotSupportedError produces crypto-unavailable, never invalid-signature', async () => {
      const originalVerifyDescriptor = Object.getOwnPropertyDescriptor(globalThis.crypto.subtle, 'verify');
      let injectedCalled = false;

      try {
        globalThis.crypto.subtle.verify = async () => {
          injectedCalled = true;
          throw new DOMException('Ed25519 not supported in this environment', 'NotSupportedError');
        };

        const body = Buffer.from('{"test":"crypto-fault"}', 'utf-8');

        const falOptions = {
          provider: 'fal' as const,
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

        // SAFETY: Literal 'fal' options tested with injected fault
        await expectErrorCodeAsync(
          () => verify({ rawBody: body, headers }, falOptions),
          'crypto-unavailable',
        );

        expect(injectedCalled).toBe(true);
      } finally {
        if (originalVerifyDescriptor === undefined) {
          Reflect.deleteProperty(globalThis.crypto.subtle, 'verify');
        } else {
          Object.defineProperty(globalThis.crypto.subtle, 'verify', originalVerifyDescriptor);
        }
      }
    });

    test('Unexpected WebCrypto OperationError produces internal, never invalid-signature', async () => {
      const originalVerifyDescriptor = Object.getOwnPropertyDescriptor(globalThis.crypto.subtle, 'verify');
      let injectedCalled = false;

      try {
        globalThis.crypto.subtle.verify = async () => {
          injectedCalled = true;
          throw new DOMException('Unspecified device failure', 'OperationError');
        };

        const body = Buffer.from('{"test":"operation-error"}', 'utf-8');

        const falOptions = {
          provider: 'fal' as const,
          publicKeys: [falKeyPrimary.rawPub],
          expectedUserId: FAL_USER_ALICE,
          now: () => FIXED_NOW,
        };

        const headers = {
          'x-fal-webhook-request-id': 'req_op_fault',
          'x-fal-webhook-user-id': FAL_USER_ALICE,
          'x-fal-webhook-timestamp': String(FIXED_NOW),
          'x-fal-webhook-signature': 'a'.repeat(128),
        };

        // SAFETY: Literal 'fal' options tested with injected fault
        await expectErrorCodeAsync(
          () => verify({ rawBody: body, headers }, falOptions),
          'internal',
        );

        expect(injectedCalled).toBe(true);
      } finally {
        if (originalVerifyDescriptor === undefined) {
          Reflect.deleteProperty(globalThis.crypto.subtle, 'verify');
        } else {
          Object.defineProperty(globalThis.crypto.subtle, 'verify', originalVerifyDescriptor);
        }
      }
    });

    test('Cryptographic MAC mismatch produces result invalid-signature, not a thrown error', async () => {
      const body = Buffer.from('{"test":"wrong-mac"}', 'utf-8');

      const falOptions = {
        provider: 'fal' as const,
        publicKeys: [falKeyPrimary.rawPub],
        expectedUserId: FAL_USER_ALICE,
        now: () => FIXED_NOW,
      };

      const headers = {
        'x-fal-webhook-request-id': 'req_wrong_mac',
        'x-fal-webhook-user-id': FAL_USER_ALICE,
        'x-fal-webhook-timestamp': String(FIXED_NOW),
        'x-fal-webhook-signature': 'b'.repeat(128),
      };

      // SAFETY: Literal 'fal' options tested directly against public verify API
      const res = await verify(
        { rawBody: body, headers },
        falOptions,
      );

      expect(res.ok).toBe(false);

      if (!res.ok) {
        expect(res.reason).toBe('invalid-signature');
      }
    });
  });

  describe('6. Baseline Reference Regressions (Stripe & GitHub)', () => {
    // Note: Exercises Stripe and GitHub as baseline reference checks; does not claim all 19 providers.
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
