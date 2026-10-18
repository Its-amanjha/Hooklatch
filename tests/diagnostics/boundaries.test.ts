import { diagnose } from '../../src/diagnostics/index.js';
import { HooklatchError } from '../../src/errors.js';
import type { VerificationFailure } from '../../src/types.js';

const valid: VerificationFailure = {
  ok: false, provider: 'stripe', reason: 'invalid-signature', message: 'ignored',
};

test.each([
  null, undefined, 1, 'input', true, [], new Date(),
  { reason: 'invalid-signature' },
  { ...valid, ok: true },
  { ...valid, provider: undefined },
  ...['__proto__', 'constructor', 'toString'].map((reason) => ({ ...valid, reason })),
  { ...valid, reason: { toString: (): string => 'invalid-signature', secret: 'PRIVATE_CANARY' } },
])('rejects invalid failure shape without coercing its code: %p', (input) => {
  // SAFETY: Deliberately invalid input exercises runtime rejection beyond the typed API.
  expect(() => diagnose(input as never)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
});

test.each(['__proto__', 'constructor', { toString: (): string => 'internal', secret: 'SETUP_CANARY' }])(
  'rejects an invalid setup code: %p', (code) => {
    const input = new HooklatchError('internal', 'ignored');
    Object.assign(input, { code });
    expect(() => diagnose(input)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
  },
);

test.each([[], new Date(), () => undefined, { verbose: 'true' }, { verbose: 1 }, { verbose: null }])(
  'rejects invalid options: %p', (options) => {
    // SAFETY: These deliberately malformed options must fail at the runtime boundary.
    expect(() => diagnose(valid, options as never)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
  },
);

test('does not leak accessor errors from malformed input', () => {
  const input = Object.defineProperty({}, 'reason', {
    get() { throw new Error('ACCESSOR_PRIVATE_CANARY'); },
  });

  // SAFETY: Deliberately malformed accessor input verifies generic error redaction.
  expect(() => diagnose(input as never)).toThrow(expect.objectContaining({ code: 'invalid-input' }));
});

test('returned arrays and nested detail are independent across calls', () => {
  const first = diagnose(valid, { verbose: true });
  const before = JSON.stringify(first);
  // Runtime callers can mutate arrays even though the public view is readonly.
  expect(Reflect.set(first.possibleCauses, '0', 'MUTATION_CANARY')).toBe(true);
  expect(Reflect.set(first.suggestions, '0', 'MUTATION_CANARY')).toBe(true);
  expect(first.detail).toBeDefined();

  if (first.detail) Reflect.set(first.detail.expectedHeaders, '0', 'MUTATION_CANARY');
  expect(JSON.stringify(diagnose(valid, { verbose: true }))).toBe(before);
});
