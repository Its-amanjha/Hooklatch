import { HooklatchError } from '../errors.js';
import type { ProviderDescriptor } from '../internal/provider.js';
import type { Provider } from '../types.js';
import { clerkDescriptor } from './clerk.js';
import { githubDescriptor } from './github.js';
import { shopifyDescriptor } from './shopify.js';
import { standardWebhooksDescriptor } from './standard-webhooks.js';
import { stripeDescriptor } from './stripe.js';
import { svixDescriptor } from './svix.js';
import { razorpayDescriptor } from './razorpay.js';
import { paddleDescriptor } from './paddle.js';
import { lemonSqueezyDescriptor } from './lemon-squeezy.js';
import { dodoPaymentsDescriptor } from './dodo-payments.js';
import { gitlabDescriptor } from './gitlab.js';
import { replicateDescriptor } from './replicate.js';
import { workosDescriptor } from './workos.js';

/** Registry order is part of the internal contract; append new providers only. */
export const SUPPORTED_PROVIDERS = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
  'razorpay',
  'paddle',
  'lemon-squeezy',
  'dodo-payments',
  'gitlab',
  'replicate',
  'workos',
] as const satisfies readonly Provider[];

const DESCRIPTORS: Readonly<Record<Provider, ProviderDescriptor>> = {
  stripe: stripeDescriptor,
  github: githubDescriptor,
  shopify: shopifyDescriptor,
  'standard-webhooks': standardWebhooksDescriptor,
  clerk: clerkDescriptor,
  svix: svixDescriptor,
  razorpay: razorpayDescriptor,
  paddle: paddleDescriptor,
  'lemon-squeezy': lemonSqueezyDescriptor,
  'dodo-payments': dodoPaymentsDescriptor,
  gitlab: gitlabDescriptor,
  replicate: replicateDescriptor,
  workos: workosDescriptor,
};

/** Resolve the pure descriptor for a supported provider. */
export function getProviderDescriptor(provider: Provider): ProviderDescriptor {
  const descriptor = Object.hasOwn(DESCRIPTORS, provider) ? DESCRIPTORS[provider] : undefined;

  if (descriptor === undefined) {
    throw new HooklatchError('unknown-provider', 'Unsupported webhook provider.');
  }

  return descriptor;
}

export {
  clerkDescriptor,
  githubDescriptor,
  shopifyDescriptor,
  standardWebhooksDescriptor,
  stripeDescriptor,
  svixDescriptor,
  razorpayDescriptor,
  paddleDescriptor,
  lemonSqueezyDescriptor,
  dodoPaymentsDescriptor,
  gitlabDescriptor,
  replicateDescriptor,
  workosDescriptor,
};
