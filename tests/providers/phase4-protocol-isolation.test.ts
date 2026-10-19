import { verifyHmac } from '../../src/internal/crypto.js';
import type {
  NormalizedHeaders,
  ParsedSignature,
  ParseResult,
} from '../../src/internal/provider.js';
import { dodoPaymentsDescriptor } from '../../src/providers/dodo-payments.js';
import { gitlabDescriptor } from '../../src/providers/gitlab.js';
import { replicateDescriptor } from '../../src/providers/replicate.js';
import { standardWebhooksDescriptor } from '../../src/providers/standard-webhooks.js';
import { workosDescriptor } from '../../src/providers/workos.js';
import type {
  EventIdentity,
  FailureDetails,
  VerificationFailureReason,
} from '../../src/types.js';
import { headerMap, hmacBase64, hmacHex, ternErrorCode } from './helpers.js';

/**
 * Deterministic adversarial and isolation qualification for the four phase-4
 * descriptors. Every digest is built here with test-only `node:crypto` and
 * Node `Buffer.concat`; production parse/decode/signing helpers are never used
 * to produce expected values. All material is synthetic, no provider was
 * contacted, and these descriptors remain unregistered in the public registry.
 * Diagnostic identifiers embed the fixed seed so failures are reproducible.
 */

const SEED = 0x9e4d_0d0d;
const ID = 'msg_phase4_isolation';
const TIMESTAMP = '1792368000';
const WORKOS_T = '1792368000500';
const BODY = Buffer.from('{"synthetic":true,"id":"isolation"}', 'utf8');
const KEY = Buffer.alloc(32, 0x4b);
const OTHER_KEY = Buffer.alloc(32, 0x4c);
const SECRET = KEY.toString('base64');
const OTHER_SECRET = OTHER_KEY.toString('base64');
const WORKOS_SECRET = 'workos isolation literal secret';

// A literal WorkOS secret whose UTF-8 bytes are also reachable by canonical
// Base64 decoding, so both protocols can be exercised with the same HMAC key.
const SHARED_LITERAL = '0123456789abcdef0123456789abcdef';
const SHARED_KEY = Buffer.from(SHARED_LITERAL, 'utf8');
const SHARED_CANONICAL_SECRET = SHARED_KEY.toString('base64');

interface CanonicalDescriptor {
  readonly provider: 'dodo-payments' | 'gitlab' | 'replicate' | 'standard-webhooks';
  decodeSecret(secret: string): Uint8Array;
  parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult;
}

const CANONICAL = [
  { name: 'dodo-payments', descriptor: dodoPaymentsDescriptor },
  { name: 'gitlab', descriptor: gitlabDescriptor },
  { name: 'replicate', descriptor: replicateDescriptor },
] as const;

/** Small explicit PRNG; the fixed seed is the only source of variation. */
function createRandom(seed: number): () => number {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);

    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function randomInt(random: () => number, bound: number): number {
  return Math.floor(random() * bound);
}

function randomBytes(random: () => number, length: number): Uint8Array {
  const output = new Uint8Array(length);

  for (let index = 0; index < length; index += 1) output[index] = randomInt(random, 256);

  return output;
}

/** Five stable body examples plus one seeded offset view and one seeded long body. */
function seededBodies(random: () => number): readonly Uint8Array[] {
  const offsetBacking = randomBytes(random, 1 + randomInt(random, 96) + 8);

  return [
    new Uint8Array(),
    Buffer.from('plain text, not JSON', 'utf8'),
    new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
    Buffer.from('{"unicode":"héllo-秘密","nul":"\\u0000"}', 'utf8'),
    offsetBacking.subarray(4, offsetBacking.byteLength - 4),
    randomBytes(random, 200 + randomInt(random, 201)),
  ];
}

function fingerprint(bodies: readonly Uint8Array[]): string {
  return bodies.map((body) => Buffer.from(body).toString('hex')).join('|');
}

function canonicalContent(id: string, timestamp: string, body: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), Buffer.from(body)]);
}

function canonicalSignature(key: Buffer, body: Uint8Array): string {
  return `v1,${hmacBase64(key, canonicalContent(ID, TIMESTAMP, body))}`;
}

function canonicalRecord(
  signature: string,
  id: string = ID,
  timestamp: string = TIMESTAMP,
) {
  return {
    'webhook-id': id,
    'webhook-timestamp': timestamp,
    'webhook-signature': signature,
  };
}

function workosContent(timestamp: string, body: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), Buffer.from(body)]);
}

function workosSignature(timestamp: string, body: Uint8Array): string {
  return hmacHex(WORKOS_SECRET, workosContent(timestamp, body));
}

function workosRecord(timestamp: string, signature: string) {
  return { 'workos-signature': `t=${timestamp},v1=${signature}` };
}

function flipByte(body: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(body);

  if (copy.byteLength === 0) return new Uint8Array([0x01]);

  const at = index % copy.byteLength;
  const current = copy[at];

  if (current === undefined) throw new Error('Cannot flip an absent body byte.');

  copy[at] = current ^ 0x01;

  return copy;
}

function parseOk(result: ParseResult, diagnostic: string): ParsedSignature {
  if (!result.ok) throw new Error(`${diagnostic}: expected success, got ${result.reason}: ${result.message}`);

  return result;
}

function parseFailure(result: ParseResult, diagnostic: string): FailureDetails {
  if (result.ok) throw new Error(`${diagnostic}: expected failure, but the header parsed successfully.`);

  return result;
}

const CANONICAL_IDENTITY: EventIdentity = {
  deliveryId: null,
  eventId: ID,
  timestamp: Number(TIMESTAMP),
  authenticatedFields: ['eventId', 'timestamp'],
};

test('generates identical seeded body shapes and distinct shapes for another seed', () => {
  const first = seededBodies(createRandom(SEED));
  const second = seededBodies(createRandom(SEED));
  const other = seededBodies(createRandom(SEED + 1));

  expect(fingerprint(first)).toBe(fingerprint(second));
  expect(fingerprint(other)).not.toBe(fingerprint(first));
  expect(first.some((body) => body.byteLength === 0)).toBe(true);
  expect(first.some((body) => body.byteLength >= 200)).toBe(true);
});

test('canonical aliases verify identical bytes when the same secret is configured', async () => {
  const signature = canonicalSignature(KEY, BODY);
  const expected = canonicalContent(ID, TIMESTAMP, BODY);

  const descriptors: readonly CanonicalDescriptor[] = [
    ...CANONICAL.map((entry) => entry.descriptor),
    standardWebhooksDescriptor,
  ];

  for (const descriptor of descriptors) {
    const diagnostic = `provider=${descriptor.provider} canonical-alias`;
    const parsed = parseOk(descriptor.parse(headerMap(canonicalRecord(signature)), BODY), diagnostic);

    expect(Buffer.from(parsed.signedContent).equals(expected)).toBe(true);
    expect(parsed.identity).toEqual(CANONICAL_IDENTITY);
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }

  // The provider labels differ; no vendor identity is authenticated by the bytes.
  expect(CANONICAL.map((entry) => entry.descriptor.provider))
    .toEqual(['dodo-payments', 'gitlab', 'replicate']);
  expect(standardWebhooksDescriptor.provider).toBe('standard-webhooks');

  // Vendor-specific headers are metadata: they cannot alter authenticated fields.
  for (const { name, descriptor } of CANONICAL) {
    const diagnostic = `provider=${name} vendor-header-isolation`;

    const vendorHeaders = {
      ...canonicalRecord(signature),
      'x-gitlab-token': 'ignored legacy token',
      'x-dodo-payments-signature': 'ignored',
      'x-replicate-event': 'prediction.completed',
    };

    const parsed = parseOk(descriptor.parse(headerMap(vendorHeaders), BODY), diagnostic);

    expect(parsed.identity).toEqual(CANONICAL_IDENTITY);
    expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }
});

test('distinct configured secrets isolate the canonical aliases', async () => {
  const signature = canonicalSignature(KEY, BODY);

  for (const { name, descriptor } of CANONICAL) {
    const diagnostic = `provider=${name} distinct-secret`;

    const parsed = parseOk(
      descriptor.parse(headerMap(canonicalRecord(signature)), BODY),
      diagnostic,
    );

    expect(await verifyHmac([descriptor.decodeSecret(OTHER_SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(false);
  }

  // The documented limitation is intentional: the same secret accepts the same
  // bytes under another alias, so endpoint-specific secrets are required.
  const replay = parseOk(
    dodoPaymentsDescriptor.parse(headerMap(canonicalRecord(signature)), BODY),
    'cross-alias replay',
  );

  expect(await verifyHmac([gitlabDescriptor.decodeSecret(SECRET)], replay.signatures, replay.signedContent))
    .toBe(true);
});

test('seeded mutation generator rejects altered bodies for all four descriptors', async () => {
  const bodies = seededBodies(createRandom(SEED));

  for (const body of bodies) {
    const bodyId = Buffer.from(body).toString('hex').slice(0, 24);
    const canonical = canonicalSignature(KEY, body);
    const workos = workosSignature(WORKOS_T, body);

    for (const { name, descriptor } of CANONICAL) {
      const diagnostic = `seed=0x${SEED.toString(16)} provider=${name} body=${bodyId}`;

      const parsed = parseOk(
        descriptor.parse(headerMap(canonicalRecord(canonical)), body),
        `${diagnostic} baseline`,
      );

      expect(await verifyHmac([descriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
        .toBe(true);

      const mutated = flipByte(body, 0);

      expect(Buffer.from(mutated).equals(Buffer.from(body))).toBe(false);

      const mutatedParsed = parseOk(
        descriptor.parse(headerMap(canonicalRecord(canonical)), mutated),
        `${diagnostic} mutated-body`,
      );

      expect(await verifyHmac(
        [descriptor.decodeSecret(SECRET)],
        mutatedParsed.signatures,
        mutatedParsed.signedContent,
      )).toBe(false);
    }

    const workosDiagnostic = `seed=0x${SEED.toString(16)} provider=workos body=${bodyId}`;

    const workosParsed = parseOk(
      workosDescriptor.parse(headerMap(workosRecord(WORKOS_T, workos)), body),
      `${workosDiagnostic} baseline`,
    );

    expect(await verifyHmac(
      [workosDescriptor.decodeSecret(WORKOS_SECRET)],
      workosParsed.signatures,
      workosParsed.signedContent,
    )).toBe(true);

    const mutatedWorkos = parseOk(
      workosDescriptor.parse(headerMap(workosRecord(WORKOS_T, workos)), flipByte(body, 1)),
      `${workosDiagnostic} mutated-body`,
    );

    expect(await verifyHmac(
      [workosDescriptor.decodeSecret(WORKOS_SECRET)],
      mutatedWorkos.signatures,
      mutatedWorkos.signedContent,
    )).toBe(false);
  }
});

test('WorkOS and canonical signatures are not interchangeable under a shared key', async () => {
  const canonicalValue = `v1,${hmacBase64(SHARED_KEY, canonicalContent(ID, TIMESTAMP, BODY))}`;
  const workosValue = hmacHex(SHARED_LITERAL, workosContent(WORKOS_T, BODY));

  const canonicalParsed = parseOk(
    dodoPaymentsDescriptor.parse(headerMap(canonicalRecord(canonicalValue)), BODY),
    'shared-key canonical baseline',
  );

  const workosParsed = parseOk(
    workosDescriptor.parse(headerMap(workosRecord(WORKOS_T, workosValue)), BODY),
    'shared-key workos baseline',
  );

  expect(await verifyHmac(
    [dodoPaymentsDescriptor.decodeSecret(SHARED_CANONICAL_SECRET)],
    canonicalParsed.signatures,
    canonicalParsed.signedContent,
  )).toBe(true);
  expect(await verifyHmac(
    [workosDescriptor.decodeSecret(SHARED_LITERAL)],
    workosParsed.signatures,
    workosParsed.signedContent,
  )).toBe(true);

  // Both digests are 32 bytes; rejection comes from the different signed bytes.
  expect(canonicalParsed.signatures[0]?.byteLength).toBe(32);
  expect(workosParsed.signatures[0]?.byteLength).toBe(32);

  const workosDigest = Buffer.from(workosValue, 'hex');

  const workosAsCanonical = parseOk(
    dodoPaymentsDescriptor.parse(
      headerMap(canonicalRecord(`v1,${workosDigest.toString('base64')}`)),
      BODY,
    ),
    'workos digest as canonical',
  );

  expect(await verifyHmac(
    [dodoPaymentsDescriptor.decodeSecret(SHARED_CANONICAL_SECRET)],
    workosAsCanonical.signatures,
    workosAsCanonical.signedContent,
  )).toBe(false);

  const canonicalDigest = Buffer.from(canonicalValue.slice(3), 'base64');

  const canonicalAsWorkos = parseOk(
    workosDescriptor.parse(headerMap(workosRecord(TIMESTAMP, canonicalDigest.toString('hex'))), BODY),
    'canonical digest as workos',
  );

  expect(await verifyHmac(
    [workosDescriptor.decodeSecret(SHARED_LITERAL)],
    canonicalAsWorkos.signatures,
    canonicalAsWorkos.signedContent,
  )).toBe(false);
});

test('canonical and WorkOS header families never parse each other', () => {
  const workosOnly = workosRecord(WORKOS_T, workosSignature(WORKOS_T, BODY));
  const canonicalOnly = canonicalRecord(canonicalSignature(KEY, BODY));

  for (const { name, descriptor } of CANONICAL) {
    expect(parseFailure(
      descriptor.parse(headerMap(workosOnly), BODY),
      `provider=${name} workos-only`,
    ).reason).toBe('missing-signature');
  }

  expect(parseFailure(workosDescriptor.parse(headerMap(canonicalOnly), BODY), 'workos canonical-only').reason)
    .toBe('missing-signature');
  expect(Buffer.from(workosDescriptor.decodeSecret(WORKOS_SECRET)).equals(Buffer.from(WORKOS_SECRET, 'utf8')))
    .toBe(true);
});

test('GitLab legacy X-Gitlab-Token cannot repair canonical defects or change authenticity', async () => {
  const signature = canonicalSignature(KEY, BODY);
  const legacyToken = 'gl_phase4_legacy_token';

  expect(parseFailure(
    gitlabDescriptor.parse(headerMap({ 'x-gitlab-token': legacyToken }), BODY),
    'legacy-token-only',
  ).reason).toBe('missing-signature');

  const base = parseOk(
    gitlabDescriptor.parse(headerMap(canonicalRecord(signature)), BODY),
    'canonical baseline',
  );

  for (const token of [legacyToken, 'gl_phase4_other_token', '']) {
    const parsed = parseOk(
      gitlabDescriptor.parse(
        headerMap({ ...canonicalRecord(signature), 'x-gitlab-token': token }),
        BODY,
      ),
      'legacy token beside valid canonical bytes',
    );

    expect(Buffer.from(parsed.signedContent).equals(Buffer.from(base.signedContent))).toBe(true);
    expect(parsed.identity).toEqual(CANONICAL_IDENTITY);
    expect(await verifyHmac([gitlabDescriptor.decodeSecret(SECRET)], parsed.signatures, parsed.signedContent))
      .toBe(true);
  }

  const defects: readonly (readonly [
    Record<string, string | readonly string[]>,
    VerificationFailureReason,
  ])[] = [
    [{ 'webhook-timestamp': TIMESTAMP, 'webhook-signature': signature }, 'missing-identity'],
    [{ 'webhook-id': ID, 'webhook-signature': signature }, 'missing-timestamp'],
    [canonicalRecord(`v1,@@@ ${signature}`), 'malformed-signature'],
    [canonicalRecord(`v1a,${signature.slice(3)}`), 'unsupported-scheme'],
    [{ ...canonicalRecord(signature), 'webhook-timestamp': [TIMESTAMP, TIMESTAMP] }, 'malformed-signature'],
    [{ ...canonicalRecord(signature), 'webhook-signature': [signature, signature] }, 'malformed-signature'],
  ];

  for (const [headers, reason] of defects) {
    const diagnostic = `gitlab-defect=${reason}`;

    expect(parseFailure(gitlabDescriptor.parse(headerMap(headers), BODY), diagnostic).reason).toBe(reason);
    expect(parseFailure(
      gitlabDescriptor.parse(headerMap({ ...headers, 'x-gitlab-token': legacyToken }), BODY),
      `${diagnostic} with-legacy-token`,
    ).reason).toBe(reason);
  }

  // A forged legacy-token value that happens to look like a digest is still ignored.
  const forgedLegacy = hmacHex(SHARED_LITERAL, BODY);

  expect(parseFailure(
    gitlabDescriptor.parse(headerMap({ 'x-gitlab-token': forgedLegacy }), BODY),
    'forged-legacy-digest',
  ).reason).toBe('missing-signature');
});

test('literal and Base64 key policies stay isolated', async () => {
  const literalOnly = 'workos literal secret with spaces';

  const canonicalParsed = parseOk(
    dodoPaymentsDescriptor.parse(
      headerMap(canonicalRecord(`v1,${hmacBase64(SHARED_KEY, canonicalContent(ID, TIMESTAMP, BODY))}`)),
      BODY,
    ),
    'canonical key-policy baseline',
  );

  const workosParsed = parseOk(
    workosDescriptor.parse(
      headerMap(workosRecord(WORKOS_T, hmacHex(WORKOS_SECRET, workosContent(WORKOS_T, BODY)))),
      BODY,
    ),
    'workos key-policy baseline',
  );

  expect(ternErrorCode(() => dodoPaymentsDescriptor.decodeSecret(literalOnly))).toBe('invalid-secret');
  expect(ternErrorCode(() => gitlabDescriptor.decodeSecret(literalOnly))).toBe('invalid-secret');
  expect(ternErrorCode(() => replicateDescriptor.decodeSecret(literalOnly))).toBe('invalid-secret');
  expect(Buffer.from(workosDescriptor.decodeSecret(literalOnly)).equals(Buffer.from(literalOnly, 'utf8')))
    .toBe(true);

  // A literal protocol key cannot be substituted for the Base64 key family and vice versa.
  expect(await verifyHmac(
    [Buffer.from(SHARED_CANONICAL_SECRET, 'utf8')],
    canonicalParsed.signatures,
    canonicalParsed.signedContent,
  )).toBe(false);
  expect(await verifyHmac(
    [Buffer.from(WORKOS_SECRET, 'base64')],
    workosParsed.signatures,
    workosParsed.signedContent,
  )).toBe(false);
});
