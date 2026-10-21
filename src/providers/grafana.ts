import { HooklatchError } from '../errors.js';
import { concatBytes, utf8 } from '../internal/bytes.js';
import type { NormalizedHeaders, ParseResult, ProviderDescriptor } from '../internal/provider.js';
import { decodeHexSignature, decodeLiteralSecret, failure, isCanonicalTimestamp } from './shared.js';

/**
 * Receiver configuration for the Grafana alerting webhook HMAC.
 *
 * `mode` selects the signed layout. `body` signs the exact raw body.
 * `timestamped` signs `${timestamp}:` followed by the exact raw body, where
 * the timestamp is read from the configured timestamp header. The mode is
 * always explicit: nothing is inferred from the request, and a missing
 * timestamp never downgrades to the body-only layout.
 */
export type GrafanaDescriptorOptions =
  | { readonly mode: 'body'; readonly signatureHeader?: string; readonly timestampHeader?: never }
  | { readonly mode: 'timestamped'; readonly signatureHeader?: string; readonly timestampHeader: string };

type GrafanaDescriptor = { readonly provider: 'grafana' }
  & Pick<ProviderDescriptor, 'decodeSecret' | 'parse'>;

type GrafanaMode = 'body' | 'timestamped';

/** Immutable receiver configuration captured when the factory runs. */
interface GrafanaConfiguration {
  /** Lower-cased signature header name used for lookup. */
  readonly signatureHeader: string;
  /** Lower-cased timestamp header name, or null in body-only mode. */
  readonly timestampHeader: string | null;
}

/** Grafana's own default signature header name. */
const DEFAULT_SIGNATURE_HEADER = 'x-grafana-alerting-signature';

/** RFC 9110 field-name token characters. */
const FIELD_NAME_TOKEN = /^[!#$%&'*+.^_`|~\dA-Za-z-]+$/;

/**
 * Authentication and framing header names that a configured Grafana header
 * must not replace. This is Hooklatch configuration policy, not a Grafana
 * rule: Grafana itself does not restrict the configured header names.
 */
const RESERVED_HEADER_NAMES: ReadonlySet<string> = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'trailer',
  'te',
  'proxy-authorization',
  'proxy-authenticate',
  'authorization',
  'cookie',
  'set-cookie',
]);

const ALLOWED_OPTION_KEYS: ReadonlySet<string> = new Set([
  'mode',
  'signatureHeader',
  'timestampHeader',
]);

const INVALID_OPTIONS_MESSAGE = 'Invalid Grafana provider options.';

function invalidOptions(): never {
  throw new HooklatchError('invalid-options', INVALID_OPTIONS_MESSAGE);
}

function isOptionsObject(options: GrafanaDescriptorOptions): options is GrafanaDescriptorOptions {
  return typeof options === 'object' && options !== null && !Array.isArray(options);
}

function isHeaderNameText(value: string | undefined): value is string {
  return typeof value === 'string';
}

function isConfiguredHeaderName(value: string): boolean {
  return FIELD_NAME_TOKEN.test(value) && !RESERVED_HEADER_NAMES.has(value.toLowerCase());
}

/** Only the three documented option keys are accepted; nothing is inherited. */
function hasUnexpectedOptionKey(options: GrafanaDescriptorOptions): boolean {
  for (const key of Object.keys(options)) {
    if (!ALLOWED_OPTION_KEYS.has(key)) return true;
  }

  for (const key of Object.getOwnPropertySymbols(options)) {
    if (Object.prototype.propertyIsEnumerable.call(options, key)) return true;
  }

  return false;
}

function readSignatureHeader(options: GrafanaDescriptorOptions): string {
  if (!Object.hasOwn(options, 'signatureHeader')) return DEFAULT_SIGNATURE_HEADER;

  const value = options.signatureHeader;

  if (!isHeaderNameText(value) || !isConfiguredHeaderName(value)) invalidOptions();

  return value.toLowerCase();
}

function readTimestampHeader(
  options: GrafanaDescriptorOptions,
  mode: GrafanaMode,
  signatureHeader: string,
): string | null {
  const configured = Object.hasOwn(options, 'timestampHeader');

  if (mode === 'body') {
    // Body-only mode has no timestamp header, not even an explicit undefined.
    if (configured) invalidOptions();

    return null;
  }

  if (!configured) invalidOptions();

  const value = options.timestampHeader;

  if (!isHeaderNameText(value) || !isConfiguredHeaderName(value)) invalidOptions();

  const normalized = value.toLowerCase();

  // A collision would make the two headers unreadable, so it is rejected.
  if (normalized === signatureHeader) invalidOptions();

  return normalized;
}

function buildConfiguration(options: GrafanaDescriptorOptions): GrafanaConfiguration {
  if (!isOptionsObject(options)) invalidOptions();

  if (hasUnexpectedOptionKey(options)) invalidOptions();

  if (!Object.hasOwn(options, 'mode')) invalidOptions();

  const mode = options.mode;

  if (mode !== 'body' && mode !== 'timestamped') invalidOptions();

  const signatureHeader = readSignatureHeader(options);
  const timestampHeader = readTimestampHeader(options, mode, signatureHeader);

  return { signatureHeader, timestampHeader };
}

/**
 * Validate and snapshot the configuration. Any getter or proxy trap observed
 * while reading the options is contained here and reported as one generic
 * invalid-options error that never echoes the underlying exception.
 */
function snapshotConfiguration(options: GrafanaDescriptorOptions): GrafanaConfiguration {
  try {
    return buildConfiguration(options);
  } catch {
    throw new HooklatchError('invalid-options', INVALID_OPTIONS_MESSAGE);
  }
}

/**
 * Parse the configured Grafana headers into the bytes Grafana signs.
 *
 * The signature header is always read first: its structure decides the
 * failure before any timestamp is inspected. Freshness and the HMAC check
 * belong to core, so this only reports the signature and the signed bytes.
 */
function parseGrafana(
  configuration: GrafanaConfiguration,
  headers: NormalizedHeaders,
  rawBody: Uint8Array,
): ParseResult {
  const signatureRaw = headers.get(configuration.signatureHeader);

  if (signatureRaw === undefined || signatureRaw.trim() === '') {
    return failure('missing-signature', 'No Grafana signature header was provided.');
  }

  const signature = decodeHexSignature(signatureRaw);

  if (signature === null) {
    return failure('malformed-signature', 'The Grafana signature header is malformed.');
  }

  const timestampHeader = configuration.timestampHeader;

  if (timestampHeader === null) {
    return {
      ok: true,
      signatures: [signature],
      signedContent: rawBody,
      identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] },
    };
  }

  const timestampRaw = headers.get(timestampHeader);

  if (timestampRaw === undefined || timestampRaw.trim() === '') {
    return failure('missing-timestamp', 'No Grafana timestamp header was provided.');
  }

  if (!isCanonicalTimestamp(timestampRaw)) {
    return failure('malformed-signature', 'The Grafana timestamp is malformed.');
  }

  return {
    ok: true,
    signatures: [signature],
    signedContent: concatBytes(utf8(`${timestampRaw}:`), rawBody),
    identity: {
      deliveryId: null,
      eventId: null,
      timestamp: Number(timestampRaw),
      authenticatedFields: ['timestamp'],
    },
  };
}

/**
 * Create a Grafana descriptor for the given receiver configuration.
 *
 * The configuration is trusted application input, never derived from a
 * request. Header names select which header is read; they are lookup
 * configuration and are not part of the signed bytes, so the same secret,
 * body and timestamp produce the same MAC under any configured header name.
 *
 * The returned descriptor is not registered with the public provider
 * registry; the coordinator owns that integration.
 */
export function createGrafanaDescriptor(options: GrafanaDescriptorOptions): GrafanaDescriptor {
  const configuration = snapshotConfiguration(options);

  return {
    provider: 'grafana',

    decodeSecret(secret: string): Uint8Array {
      return decodeLiteralSecret(secret, 'Grafana');
    },

    parse(headers: NormalizedHeaders, rawBody: Uint8Array): ParseResult {
      return parseGrafana(configuration, headers, rawBody);
    },
  };
}
