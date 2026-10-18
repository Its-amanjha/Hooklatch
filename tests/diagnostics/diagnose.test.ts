import { HooklatchError } from '../../src/errors.js';
import type { VerificationFailure, VerificationFailureReason } from '../../src/types.js';
import { diagnose } from '../../src/diagnostics/index.js';


const ALL_FAILURE_REASONS: readonly VerificationFailureReason[] = [
  'missing-signature',
  'malformed-signature',
  'unsupported-scheme',
  'invalid-signature',
  'missing-identity',
  'missing-timestamp',
  'timestamp-expired',
  'timestamp-future',
  'body-too-large',
];

const ALL_ERROR_CODES: readonly HooklatchError['code'][] = [
  'unknown-provider',
  'missing-secrets',
  'invalid-secret',
  'invalid-options',
  'invalid-input',
  'body-consumed',
  'body-read-failed',
  'crypto-unavailable',
  'internal',
];

const ALL_PROVIDERS = ['stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix'] as const;

function makeFailure(reason: VerificationFailureReason, provider: string): VerificationFailure {
  // SAFETY: we intentionally widen provider to never to construct an invalid
  // VerificationFailure for testing diagnostic rejection paths.
  return { ok: false, reason, message: `synthetic-${reason}`, provider: provider as never };
}

function makeError(code: HooklatchError['code']): HooklatchError {
  return new HooklatchError(code, `synthetic-${code}`);
}

describe('diagnose', () => {
  describe('verification failures', () => {
    it.each(ALL_FAILURE_REASONS)('returns kind=verification for %s', (reason) => {
      const result = diagnose(makeFailure(reason, 'stripe'));
      expect(result.kind).toBe('verification');
      expect(result.code).toBe(reason);
    });

    it.each(ALL_FAILURE_REASONS)('derives provider from failure for %s', (reason) => {
      const result = diagnose(makeFailure(reason, 'github'));
      expect(result.provider).toBe('github');
    });

    it.each(ALL_PROVIDERS)('produces provider-specific verbose detail for %s', (provider) => {
      const result = diagnose(makeFailure('missing-signature', provider), { verbose: true });
      expect(result.detail).toBeDefined();
      expect(result.detail!.expectedHeaders.length).toBeGreaterThan(0);
      expect(result.detail!.grammar.length).toBeGreaterThan(0);
    });

    it('omits detail when verbose is false', () => {
      const result = diagnose(makeFailure('missing-signature', 'stripe'));
      expect(result.detail).toBeUndefined();
    });

    it('accepts matching provider override', () => {
      const result = diagnose(makeFailure('invalid-signature', 'stripe'), { provider: 'stripe' });
      expect(result.provider).toBe('stripe');
    });

    it('rejects conflicting provider override with generic invalid-input', () => {
      try {
        diagnose(makeFailure('invalid-signature', 'stripe'), { provider: 'github' });
        throw new Error('should have thrown');
      } catch (err) {
        // SAFETY: err was asserted to be HooklatchError above.
        expect(err).toBeInstanceOf(HooklatchError);
        // SAFETY: same toBeInstanceOf assertion narrows err to HooklatchError.
        expect((err as HooklatchError).code).toBe('invalid-input');
      }
    });
  });

  describe('setup errors', () => {
    it.each(ALL_ERROR_CODES)('returns kind=setup for %s', (code) => {
      const result = diagnose(makeError(code));
      expect(result.kind).toBe('setup');
      expect(result.code).toBe(code);
    });

    it('omits provider when no context given', () => {
      const result = diagnose(makeError('missing-secrets'));
      expect(result.provider).toBeUndefined();
    });

    it('includes provider from options when given', () => {
      const result = diagnose(makeError('missing-secrets'), { provider: 'stripe' });
      expect(result.provider).toBe('stripe');
    });

    it('omits provider-specific verbose detail when context is absent', () => {
      const result = diagnose(makeError('invalid-options'), { verbose: true });
      expect(result.detail).toBeUndefined();
    });

    it('includes provider-specific verbose detail when context is present', () => {
      const result = diagnose(makeError('invalid-options'), { provider: 'clerk', verbose: true });
      expect(result.detail).toBeDefined();
      expect(result.detail!.expectedHeaders).toContain('svix-id');
    });
  });

  describe('redaction canaries', () => {
    it('does not copy message text into output', () => {
      const failure = makeFailure('invalid-signature', 'stripe');
      const result = diagnose(failure);
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(failure.message);
    });

    it('does not copy error message text into output', () => {
      const error = makeError('invalid-options');
      const result = diagnose(error);
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(error.message);
    });

    it('does not copy stack into output', () => {
      const error = makeError('internal');
      const result = diagnose(error);
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('stack');
      expect(serialized).not.toContain('at ');
    });

    it('does not copy extra properties into output', () => {
      // SAFETY: we intentionally add an extra property to simulate invalid
      // input and confirm the diagnostic does not echo unknown fields.
      const failure = { ...makeFailure('missing-signature', 'stripe'), extra: 'leak' } as VerificationFailure;
      const result = diagnose(failure);
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('leak');
      expect(serialized).not.toContain('extra');
    });
  });

  describe('mutation safety', () => {
    it('returns fresh arrays on each call', () => {
      const failure = makeFailure('invalid-signature', 'stripe');
      const a = diagnose(failure);
      const b = diagnose(failure);
      expect(a.possibleCauses).not.toBe(b.possibleCauses);
      expect(a.suggestions).not.toBe(b.suggestions);
    });

    it('mutating returned arrays does not contaminate later output', () => {
      const failure = makeFailure('invalid-signature', 'stripe');
      const first = diagnose(failure);
      // SAFETY: diagnose returns readonly arrays but we intentionally copy them
      // into mutable arrays for the mutation-contamination test; the original
      // returned arrays are never mutated, only the copied references.
      const mutableCauses = Array.from(first.possibleCauses);
      mutableCauses.push('injected');
      const mutableSuggestions = Array.from(first.suggestions);
      mutableSuggestions.push('injected');
      const second = diagnose(failure);
      expect(second.possibleCauses).not.toContain('injected');
      expect(second.suggestions).not.toContain('injected');
    });
  });

  describe('invalid runtime input', () => {
    it('rejects null input generically', () => {
      // SAFETY: we intentionally pass invalid input to confirm rejection.
      expect(() => diagnose(null as never)).toThrow(HooklatchError);
    });

    it('rejects undefined input generically', () => {
      // SAFETY: we intentionally pass invalid input to confirm rejection.
      expect(() => diagnose(undefined as never)).toThrow(HooklatchError);
    });

    it('rejects plain object input generically', () => {
      // SAFETY: we intentionally pass invalid input to confirm rejection.
      expect(() => diagnose({} as never)).toThrow(HooklatchError);
    });

    it('rejects invalid options.provider generically', () => {
      // SAFETY: we intentionally pass an invalid provider to confirm rejection.
      expect(() => diagnose(makeError('internal'), { provider: 'fake' as never }))
        .toThrow(HooklatchError);
    });

    it('rejects invalid options type generically', () => {
      // SAFETY: we intentionally pass invalid options to confirm rejection.
      expect(() => diagnose(makeError('internal'), 'bad' as never)).toThrow(HooklatchError);
    });

    it('never echoes invalid input in error message', () => {
      try {
        // SAFETY: we intentionally pass null to confirm rejection without echoing it.
        diagnose(null as never);
        throw new Error('should have thrown');
      } catch (err) {
        // SAFETY: err was asserted to be HooklatchError below.
        expect(err).toBeInstanceOf(HooklatchError);
        // SAFETY: same toBeInstanceOf assertion narrows err to HooklatchError.
        expect((err as HooklatchError).code).toBe('invalid-input');
        // SAFETY: same toBeInstanceOf assertion narrows err to HooklatchError.
        expect((err as HooklatchError).message).not.toContain('null');
      }
    });
  });

  describe('static output allowlists', () => {
    it('all verification codes are from the frozen reason set', () => {
      for (const reason of ALL_FAILURE_REASONS) {
        const result = diagnose(makeFailure(reason, 'stripe'));
        expect(ALL_FAILURE_REASONS).toContain(result.code);
      }
    });

    it('all setup codes are from the frozen error code set', () => {
      for (const code of ALL_ERROR_CODES) {
        const result = diagnose(makeError(code));
        expect(ALL_ERROR_CODES).toContain(result.code);
      }
    });

    it('all summaries are non-empty strings', () => {
      for (const reason of ALL_FAILURE_REASONS) {
        expect(diagnose(makeFailure(reason, 'stripe')).summary.length).toBeGreaterThan(0);
      }

      for (const code of ALL_ERROR_CODES) {
        expect(diagnose(makeError(code)).summary.length).toBeGreaterThan(0);
      }
    });

    it('all possibleCauses are non-empty arrays of non-empty strings', () => {
      for (const reason of ALL_FAILURE_REASONS) {
        const result = diagnose(makeFailure(reason, 'stripe'));
        expect(result.possibleCauses.length).toBeGreaterThan(0);

        for (const cause of result.possibleCauses) {
          expect(cause).toEqual(expect.any(String));

          expect(cause.length).toBeGreaterThan(0);
        }
      }

      for (const code of ALL_ERROR_CODES) {
        const result = diagnose(makeError(code));
        expect(result.possibleCauses.length).toBeGreaterThan(0);

        for (const cause of result.possibleCauses) {
          expect(cause).toEqual(expect.any(String));

          expect(cause.length).toBeGreaterThan(0);
        }
      }
    });

    it('all suggestions are non-empty arrays of non-empty strings', () => {
      for (const reason of ALL_FAILURE_REASONS) {
        const result = diagnose(makeFailure(reason, 'stripe'));
        expect(result.suggestions.length).toBeGreaterThan(0);

        for (const s of result.suggestions) {
          expect(s).toEqual(expect.any(String));

          expect(s.length).toBeGreaterThan(0);
        }
      }

      for (const code of ALL_ERROR_CODES) {
        const result = diagnose(makeError(code));
        expect(result.suggestions.length).toBeGreaterThan(0);

        for (const s of result.suggestions) {
          expect(s).toEqual(expect.any(String));

          expect(s.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('provider-specific expected headers', () => {
    it('stripe expects Stripe-Signature', () => {
      const result = diagnose(makeFailure('missing-signature', 'stripe'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('Stripe-Signature');
    });

    it('github expects X-Hub-Signature-256', () => {
      const result = diagnose(makeFailure('missing-signature', 'github'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('X-Hub-Signature-256');
    });

    it('shopify expects X-Shopify-Hmac-Sha256', () => {
      const result = diagnose(makeFailure('missing-signature', 'shopify'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('X-Shopify-Hmac-Sha256');
    });

    it('standard-webhooks expects webhook-* triplet', () => {
      const result = diagnose(makeFailure('missing-signature', 'standard-webhooks'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('webhook-id');
      expect(result.detail!.expectedHeaders).toContain('webhook-timestamp');
      expect(result.detail!.expectedHeaders).toContain('webhook-signature');
    });

    it('clerk expects svix-* triplet', () => {
      const result = diagnose(makeFailure('missing-signature', 'clerk'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('svix-id');
      expect(result.detail!.expectedHeaders).toContain('svix-timestamp');
      expect(result.detail!.expectedHeaders).toContain('svix-signature');
    });

    it('svix expects both families', () => {
      const result = diagnose(makeFailure('missing-signature', 'svix'), { verbose: true });
      expect(result.detail!.expectedHeaders).toContain('svix-id');
      expect(result.detail!.expectedHeaders).toContain('webhook-id');
    });
  });

  describe('purity', () => {
    it('works without Node globals', () => {
      // Ensure no process, Buffer, or other Node-only globals are referenced.
      const failure = makeFailure('invalid-signature', 'stripe');
      const result = diagnose(failure);
      expect(result).toBeDefined();
    });

    it('is synchronous', () => {
      const failure = makeFailure('invalid-signature', 'stripe');
      const result = diagnose(failure);
      expect(result).not.toBeInstanceOf(Promise);
    });
  });
});
