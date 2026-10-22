import { verify, verifyRequest, createVerifier, HooklatchError } from '../../src/index.js';
import type { VerificationResult, VerifyOptions, WebhookRequest } from '../../src/index.js';

interface StreamRequestInit extends RequestInit {
  duplex: 'half';
}

const VALID_GRAFANA_SECRET = 'grafana-order-test-valid-secret-2026';
const VALID_POLAR_CURRENT_SECRET = 'whsec_c3VwZXItc2VjcmV0LWJhc2U2NC1rZXktZm9yLXBvbGFyLTIwMjY=';
const DUMMY_BODY = new TextEncoder().encode('{"test":"setup-order"}');

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

async function expectErrorCodeAsync(run: () => Promise<VerificationResult | void>, expectedCode: string): Promise<void> {
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

describe('Phase 7 Stage B — Configuration Setup Ordering', () => {
  describe('Boundary 1: unknown-provider precedes basic secret-list and config validation', () => {
    test('unknown provider with empty secrets throws unknown-provider, not missing-secrets', () => {
      // SAFETY: Deliberately unknown provider with empty secrets to assert setup order.
      const opts: VerifyOptions = {
        provider: 'unknown-provider' as never,
        secrets: [],
      };

      expectErrorCodeSync(() => createVerifier(opts), 'unknown-provider');
    });

    test('unknown provider with invalid secrets throws unknown-provider, not invalid-secret', () => {
      // SAFETY: Deliberately unknown provider with invalid secret to assert setup order.
      const opts: VerifyOptions = {
        provider: 'unknown-provider' as never,
        secrets: [''],
      };

      expectErrorCodeSync(() => createVerifier(opts), 'unknown-provider');
    });

    test('unknown provider with invalid providerOptions throws unknown-provider, not invalid-options', () => {
      // SAFETY: Deliberately unknown provider with malformed providerOptions.
      const opts: VerifyOptions = {
        provider: 'unknown-provider' as never,
        secrets: ['some-secret'],
        providerOptions: null as never,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'unknown-provider');
    });
  });

  describe('Boundary 2: basic secret-list validation precedes new provider configuration', () => {
    test('Grafana with empty secrets throws missing-secrets, not invalid-options', () => {
      // SAFETY: Empty secrets takes precedence over missing required Grafana providerOptions.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [],
        providerOptions: {} as never,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'missing-secrets');
    });

    test('Grafana with null secrets throws missing-secrets, not invalid-options', () => {
      // SAFETY: Null secrets takes precedence over invalid providerOptions.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: null as never,
        providerOptions: null as never,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'missing-secrets');
    });

    test('Grafana with invalid empty secret string throws invalid-secret, not invalid-options', () => {
      // SAFETY: Invalid secret element takes precedence over invalid providerOptions.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [''],
        providerOptions: {} as never,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'invalid-secret');
    });

    test('Polar with empty secrets throws missing-secrets, not invalid-options', () => {
      // SAFETY: Empty secrets takes precedence over invalid Polar secretMode.
      const opts: VerifyOptions = {
        provider: 'polar',
        secrets: [],
        providerOptions: { secretMode: 'invalid' as never },
      };

      expectErrorCodeSync(() => createVerifier(opts), 'missing-secrets');
    });

    test('Polar with invalid empty secret string throws invalid-secret, not invalid-options', () => {
      // SAFETY: Invalid secret element takes precedence over invalid Polar secretMode.
      const opts: VerifyOptions = {
        provider: 'polar',
        secrets: [''],
        providerOptions: { secretMode: 'invalid' as never },
      };

      expectErrorCodeSync(() => createVerifier(opts), 'invalid-secret');
    });
  });

  describe('Boundary 3: new provider configuration precedes common bounds/clock validation', () => {
    test('Grafana missing mode throws invalid-options due to config before common bounds', () => {
      // Both providerOptions (empty) and toleranceSeconds (-1) are invalid.
      // Configuration validation runs first.
      // SAFETY: Missing mode and negative toleranceSeconds to assert evaluation order.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [VALID_GRAFANA_SECRET],
        providerOptions: {} as never,
        toleranceSeconds: -1,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'invalid-options');
    });

    test('Grafana invalid signature header throws invalid-options before maxBodyBytes', () => {
      // SAFETY: Malformed signatureHeader and invalid maxBodyBytes to assert evaluation order.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [VALID_GRAFANA_SECRET],
        providerOptions: {
          mode: 'body',
          signatureHeader: 'invalid:colon',
        },
        maxBodyBytes: -50,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'invalid-options');
    });

    test('Polar invalid secretMode throws invalid-options before clock validation', () => {
      // SAFETY: Invalid secretMode and non-function now clock to assert evaluation order.
      const opts: VerifyOptions = {
        provider: 'polar',
        secrets: [VALID_POLAR_CURRENT_SECRET],
        providerOptions: { secretMode: 'bad-mode' as never },
        now: 'not-a-clock-function' as never,
      };

      expectErrorCodeSync(() => createVerifier(opts), 'invalid-options');
    });
  });

  describe('Boundary 4: common bounds/clock validation precedes descriptor key decoding', () => {
    test('Polar current mode: invalid common bounds throws invalid-options before key decode checks base64 secret', () => {
      // 'not-valid-base64!' fails Polar current mode key decoding (which yields 'invalid-secret').
      // toleranceSeconds: -1 fails common bounds (which yields 'invalid-options').
      // Common bounds validation runs before descriptor key decoding.
      // SAFETY: Negative toleranceSeconds with invalid Base64 secret to assert order.
      const boundsFirstOpts: VerifyOptions = {
        provider: 'polar',
        secrets: ['not-valid-base64!'],
        providerOptions: { secretMode: 'current' },
        toleranceSeconds: -1,
      };

      expectErrorCodeSync(() => createVerifier(boundsFirstOpts), 'invalid-options');

      // When common bounds are valid, descriptor key decoding fails with invalid-secret.
      const keyDecodeOpts: VerifyOptions = {
        provider: 'polar',
        secrets: ['not-valid-base64!'],
        providerOptions: { secretMode: 'current' },
        toleranceSeconds: 300,
      };

      expectErrorCodeSync(() => createVerifier(keyDecodeOpts), 'invalid-secret');
    });
  });

  describe('Boundary 5: clock capture occurs before body read in verifyRequest', () => {
    test('captures clock before body reading begins', async () => {
      let clockRead = false;
      let bodyReadAfterClock = false;

      const customNow = (): number => {
        clockRead = true;

        return 1792368000;
      };

      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          if (clockRead) {
            bodyReadAfterClock = true;
          }

          controller.enqueue(DUMMY_BODY);
          controller.close();
        },
      });

      const req = new Request('http://localhost/clock-test', {
        method: 'POST',
        headers: { 'x-grafana-alerting-signature': 'dummy' },
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      const options: VerifyOptions = {
        provider: 'grafana',
        secrets: [VALID_GRAFANA_SECRET],
        now: customNow,
        providerOptions: { mode: 'body' },
      };

      await verifyRequest(req, options);
      expect(clockRead).toBe(true);
      expect(bodyReadAfterClock).toBe(true);
    });
  });

  describe('Boundary 6: no body pull on invalid setup with instrumented highWaterMark: 0 ReadableStream', () => {
    interface InstrumentedStream {
      readonly stream: ReadableStream<Uint8Array>;
      readonly wasPulledDuringVerification: () => boolean;
      readonly markVerificationStarted: () => void;
    }

    function createInstrumentedStream(): InstrumentedStream {
      let verificationStarted = false;
      let pulledDuringVerification = false;

      const stream = new ReadableStream<Uint8Array>(
        {
          start() {},
          pull(controller) {
            // Do not count constructor auto-pull as a verification read.
            if (verificationStarted) {
              pulledDuringVerification = true;
            }

            controller.enqueue(DUMMY_BODY);
            controller.close();
          },
        },
        { highWaterMark: 0 },
      );

      return {
        stream,
        wasPulledDuringVerification: () => pulledDuringVerification,
        markVerificationStarted: () => {
          verificationStarted = true;
        },
      };
    }

    test('no body pull on unknown-provider', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      // SAFETY: Deliberately unknown provider to assert setup abort before body pull.
      const opts: VerifyOptions = {
        provider: 'unknown-provider' as never,
        secrets: [VALID_GRAFANA_SECRET],
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'unknown-provider');
      expect(wasPulledDuringVerification()).toBe(false);
    });

    test('no body pull on missing-secrets', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [],
        providerOptions: { mode: 'body' },
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'missing-secrets');
      expect(wasPulledDuringVerification()).toBe(false);
    });

    test('no body pull on invalid-secret in basic secret list', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [''],
        providerOptions: { mode: 'body' },
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'invalid-secret');
      expect(wasPulledDuringVerification()).toBe(false);
    });

    test('no body pull on invalid-options from Grafana configuration', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      // SAFETY: Empty providerOptions lacks required mode.
      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [VALID_GRAFANA_SECRET],
        providerOptions: {} as never,
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'invalid-options');
      expect(wasPulledDuringVerification()).toBe(false);
    });

    test('no body pull on invalid-options from common bounds', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      const opts: VerifyOptions = {
        provider: 'grafana',
        secrets: [VALID_GRAFANA_SECRET],
        providerOptions: { mode: 'body' },
        toleranceSeconds: -1,
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'invalid-options');
      expect(wasPulledDuringVerification()).toBe(false);
    });

    test('no body pull on invalid-secret from descriptor key decoding', async () => {
      const { stream, wasPulledDuringVerification, markVerificationStarted } = createInstrumentedStream();

      const req = new Request('http://localhost/test', {
        method: 'POST',
        headers: {},
        body: stream,
        duplex: 'half',
      } satisfies StreamRequestInit);

      const opts: VerifyOptions = {
        provider: 'polar',
        secrets: ['invalid-base64-secret!'],
        providerOptions: { secretMode: 'current' },
      };

      markVerificationStarted();
      await expectErrorCodeAsync(() => verifyRequest(req, opts), 'invalid-secret');
      expect(wasPulledDuringVerification()).toBe(false);
    });
  });

  describe('Consistent setup error behavior across verify and createVerifier', () => {
    test('verify throws identical setup errors synchronously or in rejected promise', async () => {
      const dummyReq: WebhookRequest = { rawBody: DUMMY_BODY, headers: {} };

      // unknown-provider
      // SAFETY: Deliberately unknown provider to assert verify setup rejection.
      const unknownOpts: VerifyOptions = { provider: 'nope' as never, secrets: ['s'] };
      await expectErrorCodeAsync(() => verify(dummyReq, unknownOpts), 'unknown-provider');

      // missing-secrets
      const missingOpts: VerifyOptions = { provider: 'grafana', secrets: [], providerOptions: { mode: 'body' } };
      await expectErrorCodeAsync(() => verify(dummyReq, missingOpts), 'missing-secrets');

      // invalid-options
      // SAFETY: Missing mode on Grafana providerOptions.
      const invalidOpts: VerifyOptions = { provider: 'grafana', secrets: [VALID_GRAFANA_SECRET], providerOptions: {} as never };
      await expectErrorCodeAsync(() => verify(dummyReq, invalidOpts), 'invalid-options');
    });

    test('createVerifier validates setup immediately upon invocation', () => {
      // createVerifier runs setup validation before any request is received.
      // SAFETY: Deliberately unknown provider to assert immediate rejection in createVerifier.
      expectErrorCodeSync(() => createVerifier({ provider: 'nope' as never, secrets: ['s'] }), 'unknown-provider');
      expectErrorCodeSync(() => createVerifier({ provider: 'grafana', secrets: [], providerOptions: { mode: 'body' } }), 'missing-secrets');
      // SAFETY: Missing mode on Grafana providerOptions.
      expectErrorCodeSync(() => createVerifier({ provider: 'grafana', secrets: [VALID_GRAFANA_SECRET], providerOptions: {} as never }), 'invalid-options');
    });
  });
});
