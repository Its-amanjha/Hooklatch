import {
  clerkDescriptor, getProviderDescriptor, standardWebhooksDescriptor, stripeDescriptor,
  SUPPORTED_PROVIDERS, svixDescriptor,
} from '../../src/providers/index.js';

test('resolves each supported provider descriptor and rejects unknown providers', () => {
  expect(getProviderDescriptor('stripe')).toBe(stripeDescriptor);
  expect(getProviderDescriptor('stripe').provider).toBe('stripe');
  expect(getProviderDescriptor('github').provider).toBe('github');
  expect(getProviderDescriptor('shopify').provider).toBe('shopify');
  expect(getProviderDescriptor('standard-webhooks')).toBe(standardWebhooksDescriptor);
  expect(getProviderDescriptor('clerk')).toBe(clerkDescriptor);
  expect(getProviderDescriptor('svix')).toBe(svixDescriptor);
  // SAFETY: Deliberately malformed input crosses the static API boundary to assert its runtime rejection.
  expect(() => getProviderDescriptor('unknown' as never)).toThrow('Unsupported webhook provider.');
});

test('publishes the sixteen supported provider ids in registry order', () => {
  expect(SUPPORTED_PROVIDERS).toEqual([
    'stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix',
    'razorpay', 'paddle', 'lemon-squeezy',
    'dodo-payments', 'gitlab', 'replicate', 'workos',
    'sentry', 'doppler', 'sanity',
  ]);

  for (const provider of SUPPORTED_PROVIDERS) {
    expect(getProviderDescriptor(provider).provider).toBe(provider);
  }
});
