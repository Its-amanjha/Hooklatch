import { createHmac } from 'node:crypto';
import type { EventIdentity, Provider } from '../../src/types.js';

/**
 * Deterministic, independently signed adversarial corpus for the eventual
 * nineteen public providers. Signing is implemented here from the documented
 * recipes with test-only `node:crypto`; it never calls production parse/decode
 * or signed-content helpers. Every value is synthetic and this corpus is not
 * an official provider conformance certificate.
 *
 * Providers are appended in registry order so the original sixteen-provider
 * prefix remains byte-identical; `core-properties.test.ts` pins its full-case
 * hash. Grafana and Polar cases carry explicit receiver configuration rather
 * than inferring a layout or secret mode from request data.
 */

export const SECURITY_SEED = 0x5ec0_2026;
export const CASES_PER_PROVIDER = 36;
export const BASE_TIMESTAMP = 1_700_000_000;

/** Local test union: the public Provider type grows in coordinator Stage B. */
export type SecurityProvider = Exclude<Provider, 'vercel' | 'fal'>;

export type SecurityCaseMode = 'default' | 'body' | 'timestamped' | 'current' | 'legacy';

export type GrafanaCaseOptions =
  | { readonly mode: 'body'; readonly signatureHeader?: string; readonly timestampHeader?: never }
  | {
    readonly mode: 'timestamped';
    readonly signatureHeader?: string;
    readonly timestampHeader: string;
  };

export interface PolarCaseOptions { readonly secretMode: 'current' | 'legacy' }

export type SecurityProviderOptions =
  | GrafanaCaseOptions
  | PolarCaseOptions
  | undefined;

export const SECURITY_PROVIDERS = [
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
] as const satisfies readonly SecurityProvider[];

export type SignatureEncoding = 'hex' | 'base64' | 'base64url';

export interface DeterministicCase {
  readonly seed: number;
  readonly provider: SecurityProvider;
  readonly index: number;
  readonly context: string;
  readonly body: Uint8Array;
  readonly headers: Readonly<Record<string, string>>;
  readonly activeSecret: string;
  readonly retiredSecret: string;
  readonly wrongSecret: string;
  readonly secrets: readonly string[];
  readonly rotationSecrets: readonly string[];
  readonly now: number;
  readonly timestamp: number | null;
  readonly authenticatedId: string | null;
  readonly deliveryId: string | null;
  readonly eventId: string | null;
  readonly signatureHeader: string;
  readonly signatureValue: string;
  readonly signatureToken: string;
  readonly retiredToken: string;
  readonly signatureTimestampText: string | null;
  readonly encoding: SignatureEncoding;
  readonly rotationHeader: string | null;
  readonly idHeader: string | null;
  readonly timestampHeader: string | null;
  readonly unsignedHeaders: Readonly<Record<string, string>>;
  readonly expectedIdentity: EventIdentity;
  readonly mode: SecurityCaseMode;
  readonly providerOptions: SecurityProviderOptions;
}

type Random = () => number;

/** Small explicit PRNG; the seed is the only source of variation. */
function createRandom(seed: number): Random {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);

    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function randomInt(random: Random, bound: number): number {
  return Math.floor(random() * bound);
}

function randomBytes(random: Random, length: number): Uint8Array {
  const output = new Uint8Array(length);

  for (let index = 0; index < length; index += 1) output[index] = randomInt(random, 256);

  return output;
}

const TOKEN_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

function randomToken(random: Random, length: number): string {
  let output = '';

  for (let index = 0; index < length; index += 1) {
    output += TOKEN_ALPHABET.charAt(randomInt(random, TOKEN_ALPHABET.length));
  }

  return output;
}

const encoder = new TextEncoder();

function offsetView(random: Random, payload: Uint8Array, prefix: number): Uint8Array {
  const backing = new Uint8Array(prefix + payload.byteLength + 1 + randomInt(random, 4));

  for (let index = 0; index < backing.byteLength; index += 1) {
    backing[index] = randomInt(random, 256);
  }

  backing.set(payload, prefix);

  return backing.subarray(prefix, prefix + payload.byteLength);
}

/** Eight deterministic shapes cycle through each provider's 36 cases. */
function bodyFor(index: number, random: Random): Uint8Array {
  const kind = index % 8;

  if (kind === 0) return new Uint8Array();

  if (kind === 1) return encoder.encode('plain text body, not JSON');

  if (kind === 2) {
    const suffix = randomBytes(random, 3 + randomInt(random, 12));
    const output = new Uint8Array(4 + suffix.byteLength);

    output.set([0xff, 0xfe, 0x80, 0x00]);
    output.set(suffix, 4);

    return output;
  }

  if (kind === 3) return encoder.encode(`{"nul":"\u0000","index":${index}}`);

  if (kind === 4) return offsetView(random, randomBytes(random, 1 + randomInt(random, 64)), 1 + randomInt(random, 5));

  if (kind === 5) {
    return encoder.encode(
      `{"event":"order.created","index":${index},"token":"${randomToken(random, 12)}"}`,
    );
  }

  if (kind === 6) return randomBytes(random, 200 + randomInt(random, 1000));

  return encoder.encode(`{"unicode":"héllo-秘密","nul":"\u0000","index":${index}}`);
}

type StandardWebhooksProvider = 'standard-webhooks' | 'clerk' | 'svix'
  | 'dodo-payments' | 'gitlab' | 'replicate' | 'polar';

function isStandardWebhooks(provider: SecurityProvider): provider is StandardWebhooksProvider {
  return provider === 'standard-webhooks' || provider === 'clerk' || provider === 'svix'
    || provider === 'dodo-payments' || provider === 'gitlab' || provider === 'replicate'
    || provider === 'polar';
}

interface SigningRecipe {
  readonly encoding: SignatureEncoding;
  readonly timestamped: boolean;
  readonly key: (secret: string) => Buffer;
  readonly signedContent: (
    body: Uint8Array,
    timestampText: string | null,
    idText: string | null,
  ) => Buffer;
  readonly signatureValue: (token: string, timestampText: string | null) => string;
}

/** Literal UTF-8 key material, as documented for Stripe/GitHub/Shopify. */
export function literalKeyBytes(secret: string): Buffer {
  return Buffer.from(secret, 'utf8');
}

/** Base64-decoded key material after an optional `whsec_` prefix, as documented
 * for the Standard Webhooks family. */
export function standardWebhooksKeyBytes(secret: string): Buffer {
  const encoded = secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret;

  return Buffer.from(encoded, 'base64');
}

const standardWebhooksRecipe: SigningRecipe = {
  encoding: 'base64',
  timestamped: true,
  key: standardWebhooksKeyBytes,
  signedContent: (body, timestampText, idText) => {
    if (timestampText === null || idText === null) {
      throw new Error('A Standard Webhooks case requires an id and timestamp.');
    }

    return Buffer.concat([Buffer.from(`${idText}.${timestampText}.`, 'utf8'), Buffer.from(body)]);
  },
  signatureValue: (token) => `v1,${token}`,
};

/**
 * One explicit recipe per shipped provider. The `Record<Provider, ...>` type
 * makes a missing or unmapped provider a compile error; there is no protocol
 * fallback for future IDs added to the public union.
 */
const SIGNING_RECIPES: Readonly<Record<SecurityProvider, SigningRecipe>> = {
  stripe: {
    encoding: 'hex',
    timestamped: true,
    key: literalKeyBytes,
    signedContent: (body, timestampText) => {
      if (timestampText === null) throw new Error('A Stripe case requires a timestamp.');

      return Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), Buffer.from(body)]);
    },
    signatureValue: (token, timestampText) => {
      if (timestampText === null) throw new Error('A Stripe case requires a timestamp.');

      return `t=${timestampText},v1=${token}`;
    },
  },
  github: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => `sha256=${token}`,
  },
  shopify: {
    encoding: 'base64',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => token,
  },
  'standard-webhooks': standardWebhooksRecipe,
  clerk: standardWebhooksRecipe,
  svix: standardWebhooksRecipe,
  'dodo-payments': standardWebhooksRecipe,
  gitlab: standardWebhooksRecipe,
  replicate: standardWebhooksRecipe,
  razorpay: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => token,
  },
  paddle: {
    encoding: 'hex',
    timestamped: true,
    key: literalKeyBytes,
    signedContent: (body, timestampText) => {
      if (timestampText === null) throw new Error('A Paddle case requires a timestamp.');

      return Buffer.concat([Buffer.from(`${timestampText}:`, 'utf8'), Buffer.from(body)]);
    },
    signatureValue: (token, timestampText) => {
      if (timestampText === null) throw new Error('A Paddle case requires a timestamp.');

      return `ts=${timestampText};h1=${token}`;
    },
  },
  workos: {
    encoding: 'hex',
    timestamped: true,
    key: literalKeyBytes,
    signedContent: (body, timestampText) => {
      if (timestampText === null) throw new Error('A WorkOS case requires a millisecond timestamp.');

      return Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), Buffer.from(body)]);
    },
    signatureValue: (token, timestampText) => {
      if (timestampText === null) throw new Error('A WorkOS case requires a millisecond timestamp.');

      return `t=${timestampText},v1=${token}`;
    },
  },
  linear: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => token,
  },
  sentry: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => token,
  },
  doppler: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => `sha256=${token}`,
  },
  sanity: {
    encoding: 'base64url',
    timestamped: true,
    key: literalKeyBytes,
    signedContent: (body, timestampText) => {
      if (timestampText === null) throw new Error('A Sanity case requires original milliseconds.');

      return Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), Buffer.from(body)]);
    },
    signatureValue: (token, timestampText) => {
      if (timestampText === null) throw new Error('A Sanity case requires original milliseconds.');

      return `t=${timestampText},v1=${token}`;
    },
  },
  'lemon-squeezy': {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body) => Buffer.from(body),
    signatureValue: (token) => token,
  },
  // The explicit receiver mode chooses whether the timestamp prefix is signed.
  grafana: {
    encoding: 'hex',
    timestamped: false,
    key: literalKeyBytes,
    signedContent: (body, timestampText) => timestampText === null
      ? Buffer.from(body)
      : Buffer.concat([Buffer.from(`${timestampText}:`, 'utf8'), Buffer.from(body)]),
    signatureValue: (token) => token,
  },
  // Polar always uses the canonical Standard Webhooks signed content. The
  // selected secret mode changes only how the configured secret becomes key
  // bytes, which `signToken` applies explicitly per case.
  polar: standardWebhooksRecipe,
};

function isPolarCaseOptions(options: SecurityProviderOptions): options is PolarCaseOptions {
  return options !== undefined && 'secretMode' in options;
}

/** Apply only the explicitly selected secret interpretation for Polar. */
function keyFor(
  provider: SecurityProvider,
  secret: string,
  providerOptions: SecurityProviderOptions,
): Buffer {
  if (provider !== 'polar') return SIGNING_RECIPES[provider].key(secret);

  if (!isPolarCaseOptions(providerOptions)) {
    throw new Error('A Polar case requires an explicit secret mode.');
  }

  return providerOptions.secretMode === 'legacy'
    ? literalKeyBytes(secret)
    : standardWebhooksKeyBytes(secret);
}

function signToken(
  provider: SecurityProvider,
  body: Uint8Array,
  secret: string,
  timestampText: string | null,
  idText: string | null,
  providerOptions: SecurityProviderOptions,
): string {
  const recipe = SIGNING_RECIPES[provider];

  return createHmac('sha256', keyFor(provider, secret, providerOptions))
    .update(recipe.signedContent(body, timestampText, idText))
    .digest(recipe.encoding);
}

export function hmacToken(
  key: Buffer,
  content: Uint8Array,
  encoding: SignatureEncoding,
): string {
  return createHmac('sha256', key).update(content).digest(encoding);
}

/** Exported so property tests can sign shifted timestamps or ids independently. */
export function signatureTokenFor(
  case_: DeterministicCase,
  secret: string,
  timestampText: string | null,
  idText: string | null,
  providerOptions: SecurityProviderOptions = case_.providerOptions,
): string {
  return signToken(
    case_.provider,
    case_.body,
    secret,
    timestampText,
    idText,
    providerOptions,
  );
}

export function headerValueFor(
  case_: DeterministicCase,
  token: string,
  timestampText: string | null,
): string {
  return SIGNING_RECIPES[case_.provider].signatureValue(token, timestampText);
}

/** Flip one digest bit and re-encode to a still-valid canonical token. */
export function flipDigestBit(token: string, encoding: SignatureEncoding): string {
  const bytes = Buffer.from(token, encoding);
  const first = bytes[0];

  if (first === undefined) throw new Error('Cannot flip a bit in an empty digest.');

  bytes[0] = first ^ 0x01;

  return bytes.toString(encoding);
}

/** One-byte body mutation; empty bodies get a nonempty replacement. */
export function flipBodyByte(body: Uint8Array, index: number): Uint8Array {
  if (body.byteLength === 0) return new Uint8Array([0x01]);

  const copy = new Uint8Array(body);
  const at = index % copy.byteLength;
  const value = copy[at];

  if (value === undefined) throw new Error('Cannot flip an absent body byte.');

  copy[at] = value ^ 0x01;

  return copy;
}

function buildCase(provider: SecurityProvider, index: number, seed: number): DeterministicCase {
  const random = createRandom(seed);
  const body = bodyFor(index, random);
  let activeSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  let retiredSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  let wrongSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  const polarMode = provider === 'polar' ? (index % 2 === 0 ? 'current' : 'legacy') : null;

  if (polarMode === 'legacy') {
    const unicodeSuffix = index % 8 === 7 ? '-héllo-秘密' : '';

    activeSecret = `whsec_legacy_${randomToken(random, 20)}${unicodeSuffix}`;
    retiredSecret = `whsec_legacy_${randomToken(random, 20)}${unicodeSuffix}`;
    wrongSecret = `whsec_legacy_${randomToken(random, 20)}${unicodeSuffix}`;
  }

  const seconds = BASE_TIMESTAMP + ((index * 37 + randomInt(random, 17)) % 1000);
  const millisecondProtocol = provider === 'workos' || provider === 'sanity';
  const timestamp = millisecondProtocol ? seconds + 0.125 : seconds;
  const timestampText = String(millisecondProtocol ? timestamp * 1000 : timestamp);
  const recipe = SIGNING_RECIPES[provider];
  const grafanaTimestamped = provider === 'grafana' && index % 2 === 1;
  const grafanaCustomSignature = provider === 'grafana' && (index % 4 === 2 || index % 4 === 3);
  const timestamped = provider === 'grafana' ? grafanaTimestamped : recipe.timestamped;
  const signedTimestamp = timestamped ? timestampText : null;
  const id = `msg_${provider.replaceAll('-', '')}_${index}_${randomToken(random, 10)}`;
  const signedId = isStandardWebhooks(provider) ? id : null;
  const deliveryId = index % 3 === 0 ? null : `dlv_${index}_${randomToken(random, 8)}`;
  const shopifyEventId = index % 4 === 0 ? null : `evt_${index}_${randomToken(random, 8)}`;
  let razorpayEventHeader: string | null = null;
  let razorpayEventId: string | null = null;

  if (provider === 'razorpay') {
    const eventIdMode = index % 4;

    if (eventIdMode === 1) {
      razorpayEventHeader = '';
    } else if (eventIdMode === 2) {
      razorpayEventHeader = '   ';
    } else if (eventIdMode === 3) {
      razorpayEventHeader = `evt_${index}_${randomToken(random, 8)}`;
      razorpayEventId = razorpayEventHeader;
    }
  }

  const configuredGrafanaSignatureHeader = grafanaCustomSignature
    ? 'X-Grafana-Signature'
    : 'X-Grafana-Alerting-Signature';

  const configuredGrafanaTimestampHeader = grafanaTimestamped
    ? (index % 4 === 3 ? 'X-Grafana-Timestamp' : 'X-Grafana-Ts')
    : null;

  let mode: SecurityCaseMode = 'default';
  let providerOptions: SecurityProviderOptions;

  if (provider === 'grafana') {
    mode = grafanaTimestamped ? 'timestamped' : 'body';

    if (grafanaTimestamped) {
      if (configuredGrafanaTimestampHeader === null) {
        throw new Error('A timestamped Grafana case requires a timestamp header.');
      }

      const timestampedOptions = {
        mode: 'timestamped' as const,
        timestampHeader: configuredGrafanaTimestampHeader,
      };

      providerOptions = grafanaCustomSignature
        ? { ...timestampedOptions, signatureHeader: configuredGrafanaSignatureHeader }
        : timestampedOptions;
    } else {
      providerOptions = grafanaCustomSignature
        ? { mode: 'body', signatureHeader: configuredGrafanaSignatureHeader }
        : { mode: 'body' };
    }
  } else if (provider === 'polar') {
    if (polarMode === null) throw new Error('A Polar case requires a secret mode.');

    mode = polarMode;
    providerOptions = { secretMode: polarMode };
  }

  const signatureToken = signToken(
    provider,
    body,
    activeSecret,
    signedTimestamp,
    signedId,
    providerOptions,
  );

  const retiredToken = signToken(
    provider,
    body,
    retiredSecret,
    signedTimestamp,
    signedId,
    providerOptions,
  );

  const signatureValue = recipe.signatureValue(signatureToken, signedTimestamp);
  const headers: Record<string, string> = {};
  const unsignedHeaders: Record<string, string> = {};
  let signatureHeader = '';
  let idHeader: string | null = null;
  let timestampHeader: string | null = null;

  switch (provider) {
    case 'stripe':
      signatureHeader = 'Stripe-Signature';
      headers[signatureHeader] = signatureValue;
      break;
    case 'github':
      signatureHeader = 'X-Hub-Signature-256';
      headers[signatureHeader] = signatureValue;
      headers['X-GitHub-Event'] = 'push';
      unsignedHeaders['X-GitHub-Event'] = 'push';

      if (deliveryId !== null) {
        headers['X-GitHub-Delivery'] = deliveryId;
        unsignedHeaders['X-GitHub-Delivery'] = deliveryId;
      }

      break;
    case 'shopify':
      signatureHeader = 'X-Shopify-Hmac-Sha256';
      headers[signatureHeader] = signatureValue;

      if (deliveryId !== null) {
        headers['X-Shopify-Webhook-Id'] = deliveryId;
        unsignedHeaders['X-Shopify-Webhook-Id'] = deliveryId;
      }

      if (shopifyEventId !== null) {
        headers['X-Shopify-Event-Id'] = shopifyEventId;
        unsignedHeaders['X-Shopify-Event-Id'] = shopifyEventId;
      }

      break;
    case 'standard-webhooks':
    case 'clerk':
    case 'svix':
    case 'dodo-payments':
    case 'gitlab':
    case 'replicate':
    case 'polar': {
      const canonical = provider === 'svix' && index % 2 === 1;

      if (canonical) {
        idHeader = 'Webhook-Id';
        timestampHeader = 'Webhook-Timestamp';
        signatureHeader = 'Webhook-Signature';
      } else if (provider === 'clerk' || provider === 'svix') {
        idHeader = 'Svix-Id';
        timestampHeader = 'Svix-Timestamp';
        signatureHeader = 'Svix-Signature';
      } else {
        idHeader = 'Webhook-Id';
        timestampHeader = 'Webhook-Timestamp';
        signatureHeader = 'Webhook-Signature';
      }

      headers[idHeader] = id;
      headers[timestampHeader] = timestampText;
      headers[signatureHeader] = signatureValue;

      if (provider === 'polar') {
        unsignedHeaders['Svix-Id'] = id;
        unsignedHeaders['Svix-Timestamp'] = timestampText;
        unsignedHeaders['Svix-Signature'] = signatureValue;
      }

      break;
    }

    case 'razorpay':
      signatureHeader = 'X-Razorpay-Signature';
      headers[signatureHeader] = signatureValue;

      if (razorpayEventHeader !== null) {
        headers['X-Razorpay-Event-Id'] = razorpayEventHeader;
        unsignedHeaders['X-Razorpay-Event-Id'] = razorpayEventHeader;
      }

      break;
    case 'linear':
      signatureHeader = 'Linear-Signature';
      headers[signatureHeader] = signatureValue;
      unsignedHeaders['Linear-Timestamp'] = String(BASE_TIMESTAMP * 1000);
      unsignedHeaders['Linear-Delivery'] = 'hooklatch-synthetic-linear-delivery';
      unsignedHeaders['Linear-Event'] = 'Issue';
      break;
    case 'sentry':
      signatureHeader = 'Sentry-Hook-Signature';
      headers[signatureHeader] = signatureValue;
      unsignedHeaders['Sentry-Hook-Timestamp'] = '1600000000';
      unsignedHeaders['Sentry-Hook-Resource'] = 'issue';
      unsignedHeaders['Request-Id'] = id;
      Object.assign(headers, unsignedHeaders);
      break;
    case 'doppler':
      signatureHeader = 'X-Doppler-Signature';
      headers[signatureHeader] = signatureValue;
      unsignedHeaders['X-Doppler-Delivery-Id'] = id;
      unsignedHeaders['Authorization'] = 'Bearer synthetic-untrusted-token';
      Object.assign(headers, unsignedHeaders);
      break;
    case 'sanity':
      signatureHeader = 'Sanity-Webhook-Signature';
      headers[signatureHeader] = signatureValue;
      break;
    case 'workos':
      signatureHeader = 'WorkOS-Signature';
      headers[signatureHeader] = signatureValue;
      break;
    case 'paddle':
      signatureHeader = 'Paddle-Signature';
      headers[signatureHeader] = signatureValue;
      break;
    case 'lemon-squeezy':
      signatureHeader = 'X-Signature';
      headers[signatureHeader] = signatureValue;
      headers['X-Event-Name'] = 'order_created';
      unsignedHeaders['X-Event-Name'] = 'order_created';
      break;
    case 'grafana': {
      signatureHeader = configuredGrafanaSignatureHeader;
      headers[signatureHeader] = signatureValue;

      if (grafanaTimestamped) {
        if (configuredGrafanaTimestampHeader === null) {
          throw new Error('A timestamped Grafana case requires a timestamp header.');
        }

        timestampHeader = configuredGrafanaTimestampHeader;
        headers[timestampHeader] = timestampText;
        unsignedHeaders['X-Grafana-Alt-Timestamp'] = String(seconds + 86_400);
      } else {
        timestampHeader = null;
        unsignedHeaders['X-Grafana-Timestamp'] = '1600000000';
      }

      if (grafanaCustomSignature) {
        unsignedHeaders['X-Grafana-Alerting-Signature'] = signatureValue;
      } else {
        unsignedHeaders['X-Grafana-Other-Signature'] = signatureValue;
      }

      break;
    }
  }

  let rotationHeader: string | null = null;

  if (provider === 'stripe' || provider === 'workos') {
    rotationHeader = `t=${timestampText},v1=${retiredToken},v1=${signatureToken}`;
  } else if (isStandardWebhooks(provider)) {
    rotationHeader = `v1,${retiredToken} v1,${signatureToken}`;
  } else if (provider === 'paddle') {
    rotationHeader = `ts=${timestampText};h1=${retiredToken};h1=${signatureToken}`;
  }

  let recordEventId: string | null = null;

  if (provider === 'shopify') {
    recordEventId = shopifyEventId;
  } else if (provider === 'razorpay') {
    recordEventId = razorpayEventId;
  }

  let expectedIdentity: EventIdentity;

  if (provider === 'stripe' || provider === 'paddle' || provider === 'workos' || provider === 'sanity') {
    expectedIdentity = {
      deliveryId: null, eventId: null, timestamp, authenticatedFields: ['timestamp'],
    };
  } else if (provider === 'github') {
    expectedIdentity = {
      deliveryId, eventId: null, timestamp: null, authenticatedFields: [],
    };
  } else if (provider === 'shopify') {
    expectedIdentity = {
      deliveryId, eventId: shopifyEventId, timestamp: null, authenticatedFields: [],
    };
  } else if (provider === 'grafana') {
    expectedIdentity = grafanaTimestamped
      ? {
        deliveryId: null, eventId: null, timestamp, authenticatedFields: ['timestamp'],
      }
      : {
        deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [],
      };
  } else if (isStandardWebhooks(provider)) {
    expectedIdentity = {
      deliveryId: null, eventId: id, timestamp, authenticatedFields: ['eventId', 'timestamp'],
    };
  } else if (provider === 'razorpay') {
    expectedIdentity = {
      deliveryId: null, eventId: razorpayEventId, timestamp: null, authenticatedFields: [],
    };
  } else {
    // Body-only providers without mapped identity document no authenticated ids.
    expectedIdentity = {
      deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [],
    };
  }

  return {
    seed,
    provider,
    index,
    context: `seed=0x${seed.toString(16)} provider=${provider} case=${index}`,
    body,
    headers,
    activeSecret,
    retiredSecret,
    wrongSecret,
    secrets: [activeSecret],
    rotationSecrets: [activeSecret, retiredSecret],
    now: timestamp,
    timestamp: timestamped ? timestamp : null,
    authenticatedId: signedId,
    deliveryId: provider === 'github' || provider === 'shopify' ? deliveryId : null,
    eventId: recordEventId,
    signatureHeader,
    signatureValue,
    signatureToken,
    retiredToken,
    signatureTimestampText: signedTimestamp,
    encoding: recipe.encoding,
    rotationHeader,
    idHeader,
    timestampHeader,
    unsignedHeaders,
    expectedIdentity,
    mode,
    providerOptions,
  };
}

export function buildCases(seed: number = SECURITY_SEED): readonly DeterministicCase[] {
  const cases: DeterministicCase[] = [];
  let providerIndex = 0;

  for (const provider of SECURITY_PROVIDERS) {
    for (let index = 0; index < CASES_PER_PROVIDER; index += 1) {
      cases.push(buildCase(provider, index, seed + providerIndex * 0x9e3779b1 + index * 0x85ebca6b));
    }

    providerIndex += 1;
  }

  return cases;
}

export const ALL_CASES = buildCases();

export function casesFor(provider: SecurityProvider): readonly DeterministicCase[] {
  return ALL_CASES.filter((entry) => entry.provider === provider);
}

export function corpusFingerprint(cases: readonly DeterministicCase[]): string {
  return cases.map((entry) =>
    `${entry.context}:${Buffer.from(entry.body).toString('hex')}:${entry.signatureToken}`,
  ).join('|');
}
