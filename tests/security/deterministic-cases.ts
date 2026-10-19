import { createHmac } from 'node:crypto';
import type { EventIdentity, Provider } from '../../src/types.js';

/**
 * Deterministic, independently signed adversarial corpus for the six registered
 * public providers. Signing is implemented here from the documented recipes
 * with test-only `node:crypto`; it never calls production parse/decode or
 * signed-content helpers. Every value is synthetic and this corpus is not an
 * official provider conformance certificate.
 */

export const SECURITY_SEED = 0x5ec0_2026;
export const CASES_PER_PROVIDER = 36;
export const BASE_TIMESTAMP = 1_700_000_000;

export const SECURITY_PROVIDERS = [
  'stripe',
  'github',
  'shopify',
  'standard-webhooks',
  'clerk',
  'svix',
] as const satisfies readonly Provider[];

export type SignatureEncoding = 'hex' | 'base64';

export interface DeterministicCase {
  readonly seed: number;
  readonly provider: Provider;
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

function isStandardWebhooks(provider: Provider): boolean {
  return provider === 'standard-webhooks' || provider === 'clerk' || provider === 'svix';
}

function encodingFor(provider: Provider): SignatureEncoding {
  return isStandardWebhooks(provider) || provider === 'shopify' ? 'base64' : 'hex';
}

function isTimestamped(provider: Provider): boolean {
  return provider === 'stripe' || isStandardWebhooks(provider);
}

function keyBytesFor(provider: Provider, secret: string): Buffer {
  return isStandardWebhooks(provider)
    ? standardWebhooksKeyBytes(secret)
    : literalKeyBytes(secret);
}

function signedContentFor(
  provider: Provider,
  body: Uint8Array,
  timestampText: string | null,
  idText: string | null,
): Buffer {
  if (provider === 'stripe') {
    if (timestampText === null) throw new Error('A Stripe case requires a timestamp.');

    return Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), Buffer.from(body)]);
  }

  if (isStandardWebhooks(provider)) {
    if (timestampText === null || idText === null) {
      throw new Error('A Standard Webhooks case requires an id and timestamp.');
    }

    return Buffer.concat([Buffer.from(`${idText}.${timestampText}.`, 'utf8'), Buffer.from(body)]);
  }

  return Buffer.from(body);
}

function signToken(
  provider: Provider,
  encoding: SignatureEncoding,
  body: Uint8Array,
  secret: string,
  timestampText: string | null,
  idText: string | null,
): string {
  return createHmac('sha256', keyBytesFor(provider, secret))
    .update(signedContentFor(provider, body, timestampText, idText))
    .digest(encoding);
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

export function hmacToken(
  key: Buffer,
  content: Uint8Array,
  encoding: SignatureEncoding,
): string {
  return createHmac('sha256', key).update(content).digest(encoding);
}

function formatSignatureValue(
  provider: Provider,
  token: string,
  timestampText: string | null,
): string {
  if (provider === 'stripe') {
    if (timestampText === null) throw new Error('A Stripe case requires a timestamp.');

    return `t=${timestampText},v1=${token}`;
  }

  if (provider === 'github') return `sha256=${token}`;

  if (provider === 'shopify') return token;

  return `v1,${token}`;
}

/** Exported so property tests can sign shifted timestamps or ids independently. */
export function signatureTokenFor(
  case_: DeterministicCase,
  secret: string,
  timestampText: string | null,
  idText: string | null,
): string {
  return signToken(case_.provider, case_.encoding, case_.body, secret, timestampText, idText);
}

export function headerValueFor(
  case_: DeterministicCase,
  token: string,
  timestampText: string | null,
): string {
  return formatSignatureValue(case_.provider, token, timestampText);
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

function buildCase(provider: Provider, index: number, seed: number): DeterministicCase {
  const random = createRandom(seed);
  const body = bodyFor(index, random);
  const activeSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  const retiredSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  const wrongSecret = `whsec_${Buffer.from(randomBytes(random, 24 + randomInt(random, 25))).toString('base64')}`;
  const timestamp = BASE_TIMESTAMP + ((index * 37 + randomInt(random, 17)) % 1000);
  const timestampText = String(timestamp);
  const timestamped = isTimestamped(provider);
  const signedTimestamp = timestamped ? timestampText : null;
  const id = `msg_${provider.replaceAll('-', '')}_${index}_${randomToken(random, 10)}`;
  const signedId = isStandardWebhooks(provider) ? id : null;
  const deliveryId = index % 3 === 0 ? null : `dlv_${index}_${randomToken(random, 8)}`;
  const shopifyEventId = index % 4 === 0 ? null : `evt_${index}_${randomToken(random, 8)}`;
  const encoding = encodingFor(provider);
  const signatureToken = signToken(provider, encoding, body, activeSecret, signedTimestamp, signedId);
  const retiredToken = signToken(provider, encoding, body, retiredSecret, signedTimestamp, signedId);
  const signatureValue = formatSignatureValue(provider, signatureToken, signedTimestamp);
  const headers: Record<string, string> = {};
  const unsignedHeaders: Record<string, string> = {};
  let signatureHeader = '';
  let idHeader: string | null = null;
  let timestampHeader: string | null = null;

  if (provider === 'stripe') {
    signatureHeader = 'Stripe-Signature';
    headers[signatureHeader] = signatureValue;
  } else if (provider === 'github') {
    signatureHeader = 'X-Hub-Signature-256';
    headers[signatureHeader] = signatureValue;
    headers['X-GitHub-Event'] = 'push';
    unsignedHeaders['X-GitHub-Event'] = 'push';

    if (deliveryId !== null) {
      headers['X-GitHub-Delivery'] = deliveryId;
      unsignedHeaders['X-GitHub-Delivery'] = deliveryId;
    }
  } else if (provider === 'shopify') {
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
  } else {
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
  }

  const rotationHeader = provider === 'stripe'
    ? `t=${timestampText},v1=${retiredToken},v1=${signatureToken}`
    : isStandardWebhooks(provider)
      ? `v1,${retiredToken} v1,${signatureToken}`
      : null;

  let expectedIdentity: EventIdentity;

  if (provider === 'stripe') {
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
  } else {
    expectedIdentity = {
      deliveryId: null, eventId: id, timestamp, authenticatedFields: ['eventId', 'timestamp'],
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
    eventId: provider === 'shopify' ? shopifyEventId : null,
    signatureHeader,
    signatureValue,
    signatureToken,
    retiredToken,
    signatureTimestampText: signedTimestamp,
    encoding,
    rotationHeader,
    idHeader,
    timestampHeader,
    unsignedHeaders,
    expectedIdentity,
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

export function casesFor(provider: Provider): readonly DeterministicCase[] {
  return ALL_CASES.filter((entry) => entry.provider === provider);
}

export function corpusFingerprint(cases: readonly DeterministicCase[]): string {
  return cases.map((entry) =>
    `${entry.context}:${Buffer.from(entry.body).toString('hex')}:${entry.signatureToken}`,
  ).join('|');
}
