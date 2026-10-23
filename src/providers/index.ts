import { HooklatchError } from '../errors.js';
import type { AnyProviderDescriptor } from '../internal/provider.js';
import type { Provider, GrafanaOptions, PolarOptions } from '../types.js';
import { createGrafanaDescriptor } from './grafana.js';
import { createPolarDescriptor } from './polar.js';
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
import { sentryDescriptor } from './sentry.js';
import { dopplerDescriptor } from './doppler.js';
import { sanityDescriptor } from './sanity.js';
import { linearDescriptor } from './linear.js';
import { vercelDescriptor } from './vercel.js';
import { falDescriptor } from './fal.js';

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
  'sentry',
  'doppler',
  'sanity',
  'grafana',
  'polar',
  'linear',
  'vercel',
  'fal',
] as const satisfies readonly Provider[];

const DESCRIPTORS: Readonly<Record<Exclude<Provider, 'grafana' | 'polar'>, AnyProviderDescriptor>> = {
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
  sentry: sentryDescriptor,
  doppler: dopplerDescriptor,
  sanity: sanityDescriptor,
  linear: linearDescriptor,
  vercel: vercelDescriptor,
  fal: falDescriptor,
};

/** Resolve the pure descriptor for a supported provider. */
export function getProviderDescriptor(provider: Provider, providerOptions?: GrafanaOptions | PolarOptions): AnyProviderDescriptor {
  if (provider === 'grafana') {
    if (providerOptions === undefined || !('mode' in providerOptions)) {
      throw new HooklatchError('invalid-options', 'Invalid provider options.');
    }

    return createGrafanaDescriptor(providerOptions);
  }

  if (provider === 'polar') {
    if (providerOptions !== undefined && 'mode' in providerOptions) {
      throw new HooklatchError('invalid-options', 'Invalid provider options.');
    }

    return createPolarDescriptor(providerOptions);
  }

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
  sentryDescriptor,
  dopplerDescriptor,
  sanityDescriptor,
  linearDescriptor,
  vercelDescriptor,
  falDescriptor,
};
