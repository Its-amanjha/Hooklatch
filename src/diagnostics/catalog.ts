import type { HooklatchErrorCode, Provider, VerificationFailureReason } from '../types.js';
import type { DiagnosticCode } from './types.js';

/** Static guidance for verification failure reasons. */
interface Guidance {
  readonly summary: string;
  readonly possibleCauses: readonly string[];
  readonly suggestions: readonly string[];
}

const VERIFICATION_GUIDANCE: Readonly<Record<VerificationFailureReason, Guidance>> = {
  'missing-signature': {
    summary: 'The provider signature header was not present in the request.',
    possibleCauses: [
      'A proxy, load balancer, or middleware stripped the signature header.',
      'The request was not actually sent by the provider.',
      'The request was modified in transit.',
    ],
    suggestions: [
      'Check that no intermediary removes the signature header.',
      'Verify the request originates from the provider documented IP ranges.',
      'Compare expected header names with your middleware configuration.',
    ],
  },
  'malformed-signature': {
    summary: 'Required signing headers were malformed or conflicted.',
    possibleCauses: [
      'The header value was truncated or altered by an intermediary.',
      'The provider changed its header format.',
      'The request was not actually sent by the provider.',
    ],
    suggestions: [
      'Compare the raw header value against the provider documentation.',
      'Check for header-combining proxies that may merge or split values.',
      'Use synthetic requests to compare header grammar without recording sensitive values.',
    ],
  },
  'unsupported-scheme': {
    summary: 'Only unsupported or legacy signature schemes were present.',
    possibleCauses: [
      'The provider sent a legacy signature format (e.g. SHA-1).',
      'The signature scheme version is not supported by this release.',
      'The request was not actually sent by the provider.',
    ],
    suggestions: [
      'Check the provider documentation for supported signature schemes.',
      'Ensure the provider is configured to send the current scheme version.',
      'Update the SDK when a new scheme is required.',
    ],
  },
  'invalid-signature': {
    summary: 'The signature was well-formed but did not authenticate.',
    possibleCauses: [
      'The configured secret does not match the provider endpoint secret.',
      'A secret rotation is in progress and the old secret is still active at the provider.',
      'The body was modified in transit, compressed, or re-serialized.',
      'The wrong provider was selected for this request.',
      'The request was not actually sent by the provider.',
    ],
    suggestions: [
      'Verify the configured secret matches the provider endpoint secret.',
      'Check whether a secret rotation is in progress and include all active secrets.',
      'Ensure the raw body is captured before any JSON parsing or re-serialization.',
      'Confirm the correct provider is selected for this endpoint.',
    ],
  },
  'missing-identity': {
    summary: 'A required identity metadata header was absent.',
    possibleCauses: [
      'The request was not actually sent by the provider.',
      'An intermediary stripped the header.',
      'The provider changed its header format.',
    ],
    suggestions: [
      'Compare the incoming headers with the provider documentation.',
      'Check that no proxy or middleware removes the header.',
      'Verify the request originates from the provider.',
    ],
  },
  'missing-timestamp': {
    summary: 'A required signed timestamp header was absent.',
    possibleCauses: [
      'The request was not actually sent by the provider.',
      'An intermediary stripped the header.',
      'The provider changed its header format.',
    ],
    suggestions: [
      'Compare the incoming headers with the provider documentation.',
      'Check that no proxy or middleware removes the header.',
      'Verify the request originates from the provider.',
    ],
  },
  'timestamp-expired': {
    summary: 'The signed timestamp is older than the configured tolerance.',
    possibleCauses: [
      'The request is a replay of an older delivery.',
      'Clock skew exists between the provider and this host.',
      'The body was delayed by a queue or retry mechanism.',
    ],
    suggestions: [
      'Check clock synchronization between provider and host.',
      'Review provider delivery timing before changing the configured tolerance.',
      'Investigate whether the request is a replay attack.',
    ],
  },
  'timestamp-future': {
    summary: 'The signed timestamp is newer than the configured tolerance.',
    possibleCauses: [
      'Clock skew exists between the provider and this host.',
      'The provider clock is ahead of this host.',
    ],
    suggestions: [
      'Check clock synchronization between provider and host.',
      'Review provider clock behavior before changing the configured tolerance.',
    ],
  },
  'body-too-large': {
    summary: 'The request body exceeded the configured size limit.',
    possibleCauses: [
      'The legitimate payload exceeds the configured maxBodyBytes.',
      'The body was inflated by compression middleware.',
      'A malicious or malformed request sent an oversized body.',
    ],
    suggestions: [
      'Increase maxBodyBytes if the provider legitimately sends larger payloads.',
      'Check for compression middleware that may inflate the body.',
      'Reject the request if the size is unexpected for this provider.',
    ],
  },
};

/** Static guidance for setup/runtime error codes. */
const SETUP_GUIDANCE: Readonly<Record<HooklatchErrorCode, Guidance>> = {
  'unknown-provider': {
    summary: 'The specified provider is not supported.',
    possibleCauses: [
      'The provider name contains a typo.',
      'The provider has not been added to the SDK yet.',
    ],
    suggestions: [
      'Check the provider name against the supported list.',
      'Update the SDK to a version that supports the provider.',
    ],
  },
  'missing-secrets': {
    summary: 'No signing secrets were configured.',
    possibleCauses: [
      'The secrets option was omitted.',
      'The secrets array was empty.',
    ],
    suggestions: [
      'Provide at least one active signing secret.',
      'Load secrets from environment variables or a secrets manager.',
    ],
  },
  'invalid-secret': {
    summary: 'A configured secret failed validation.',
    possibleCauses: [
      'The secret is empty or contains only whitespace.',
      'The secret format does not match the provider requirements.',
      'The secret was copied incorrectly from the provider dashboard.',
    ],
    suggestions: [
      'Verify the secret matches the provider documentation format.',
      'Check for trailing whitespace or newline characters.',
      'Regenerate the secret at the provider if necessary.',
    ],
  },
  'invalid-options': {
    summary: 'The verification options were malformed.',
    possibleCauses: [
      'toleranceSeconds is negative or non-finite.',
      'maxBodyBytes is not a positive safe integer.',
      'The now function is not callable.',
    ],
    suggestions: [
      'Check toleranceSeconds is a non-negative finite number.',
      'Check maxBodyBytes is a positive safe integer.',
      'Check that now is a function returning epoch seconds.',
    ],
  },
  'invalid-input': {
    summary: 'The request or header input was malformed.',
    possibleCauses: [
      'The header input was not a Headers, tuple list, or record.',
      'A header value contained illegal characters.',
      'The input object was null or undefined.',
    ],
    suggestions: [
      'Ensure headers are provided as a Headers, tuple list, or plain record.',
      'Check for null or undefined header values.',
      'Validate header input before calling verify.',
    ],
  },
  'body-consumed': {
    summary: 'The Request body was already read before verification.',
    possibleCauses: [
      'A middleware or handler read the body before calling verifyRequest.',
      'The same Request object was processed twice.',
    ],
    suggestions: [
      'Call verifyRequest before any other body reads.',
      'Use createVerifier with captured raw bytes for multi-stage processing.',
      'Clone the Request if multiple consumers need the body.',
    ],
  },
  'body-read-failed': {
    summary: 'The request body stream could not be read.',
    possibleCauses: [
      'The client disconnected mid-body.',
      'A platform streaming error occurred.',
      'The body was locked by another consumer.',
    ],
    suggestions: [
      'Check client connection stability.',
      'Retry the request if the failure is transient.',
      'Inspect platform logs for streaming errors.',
    ],
  },
  'crypto-unavailable': {
    summary: 'Web Crypto is not available in this environment.',
    possibleCauses: [
      'The runtime does not provide globalThis.crypto.subtle.',
      'The environment is not Node 22+ or a compatible Workers runtime.',
    ],
    suggestions: [
      'Ensure the runtime is Node 22+ or a Workers-compatible environment.',
      'Check that crypto.subtle is available at global scope.',
      'Update the runtime if it is below the minimum supported version.',
    ],
  },
  'internal': {
    summary: 'An unexpected internal error occurred.',
    possibleCauses: [
      'An unhandled exception in the verification pipeline.',
      'A platform-specific failure in cryptographic operations.',
    ],
    suggestions: [
      'Report this issue with the SDK version and runtime details.',
      'Retry the request if the failure may be transient.',
      'Check for known issues in the SDK release notes.',
    ],
  },
};

/** Provider-specific verbose detail: expected headers and grammar. */
interface ProviderDetail {
  readonly expectedHeaders: readonly string[];
  readonly grammar: string;
}

const PROVIDER_DETAIL: Readonly<Record<Provider, ProviderDetail>> = {
  vercel: {
    expectedHeaders: ['x-vercel-signature'],
    grammar: 'Exactly 40 hexadecimal digits encoding HMAC-SHA1 over exact raw body bytes; no timestamp or identity extraction.',
  },
  fal: {
    expectedHeaders: ['x-fal-webhook-signature', 'x-fal-webhook-request-id', 'x-fal-webhook-user-id', 'x-fal-webhook-timestamp'],
    grammar: 'Exactly 128 hexadecimal signature digits; visible ASCII request and user IDs excluding commas; canonical nonnegative integer seconds. Ed25519 authenticates request ID, user ID, timestamp and the lowercase SHA256 raw-body digest. Static trusted raw public keys and exact expected user ID are required.',
  },
  stripe: {
    expectedHeaders: ['Stripe-Signature'],
    grammar: 'Comma-separated key=value pairs: t=<unix-seconds>,v1=<hex-signature>[,v1=<hex-signature>]',
  },
  github: {
    expectedHeaders: ['X-Hub-Signature-256'],
    grammar: 'sha256=<64 hexadecimal digits; letter case is ignored>',
  },
  shopify: {
    expectedHeaders: ['X-Shopify-Hmac-Sha256'],
    grammar: 'Canonical Base64-encoded HMAC-SHA256 signature',
  },
  'standard-webhooks': {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Space-delimited list of v1,<base64-signature> tokens',
  },
  clerk: {
    expectedHeaders: ['svix-id', 'svix-timestamp', 'svix-signature'],
    grammar: 'Space-delimited list of v1,<base64-signature> tokens',
  },
  svix: {
    expectedHeaders: ['svix-id', 'svix-timestamp', 'svix-signature', 'webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Space-delimited list of v1,<base64-signature> tokens (branded or canonical family)',
  },
  razorpay: {
    expectedHeaders: ['X-Razorpay-Signature'],
    grammar: 'A single 64-digit hexadecimal HMAC-SHA256 signature over the raw body',
  },
  paddle: {
    expectedHeaders: ['Paddle-Signature'],
    grammar: 'Semicolon-separated ts=<unix-seconds>;h1=<64 hexadecimal digits>, with repeated h1 allowed',
  },
  'lemon-squeezy': {
    expectedHeaders: ['X-Signature'],
    grammar: 'A single 64-digit hexadecimal HMAC-SHA256 signature over the raw body',
  },
  'dodo-payments': {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Space-delimited list of v1,<base64-signature> tokens over id.timestamp.body',
  },
  gitlab: {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Signing-token mode: space-delimited v1,<base64-signature> tokens; no X-Gitlab-Token fallback',
  },
  replicate: {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Space-delimited list of v1,<base64-signature> tokens over id.timestamp.body',
  },
  workos: {
    expectedHeaders: ['WorkOS-Signature'],
    grammar: 'Comma-separated t=<unix-milliseconds>,v1=<64 hexadecimal digits>; one t, repeated valid v1 allowed',
  },
  sentry: {
    expectedHeaders: ['Sentry-Hook-Signature'],
    grammar: 'Sentry App mode: a single bare 64-digit hexadecimal HMAC-SHA256 signature over the raw body',
  },
  doppler: {
    expectedHeaders: ['X-Doppler-Signature'],
    grammar: 'Signed mode: sha256=<64 hexadecimal digits> over the raw body; no Basic/Bearer fallback',
  },
  linear: {
    expectedHeaders: ['Linear-Signature'],
    grammar: 'A single bare 64-digit hexadecimal HMAC-SHA256 signature over exact raw body bytes. Signature authentication only: body claims are not extracted and unsigned header timestamps do not establish freshness.',
  },
  sanity: {
    expectedHeaders: ['sanity-webhook-signature'],
    grammar: 'Exactly t=<unix-milliseconds>,v1=<43 canonical unpadded Base64url characters>; one of each field, no whitespace',
  },
  grafana: {
    expectedHeaders: [],
    grammar: 'Configured signature header: 64 hexadecimal digits. Body mode signs raw bytes; timestamped mode also requires the configured timestamp header with canonical Unix seconds and signs timestamp:body.',
  },
  polar: {
    expectedHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
    grammar: 'Space-delimited v1,<base64-signature> tokens over id.timestamp.body; current or legacy secretMode is trusted application configuration, never detected from a request.',
  },
};

export function getVerificationGuidance(reason: VerificationFailureReason): Guidance {
  return VERIFICATION_GUIDANCE[reason];
}

export function getSetupGuidance(code: HooklatchErrorCode): Guidance {
  return SETUP_GUIDANCE[code];
}

export function getProviderDetail(provider: Provider): ProviderDetail | undefined {
  return PROVIDER_DETAIL[provider];
}

export function isVerificationCode(code: DiagnosticCode): code is VerificationFailureReason {
  return typeof code === 'string' && Object.hasOwn(VERIFICATION_GUIDANCE, code);
}

export function isSetupCode(code: DiagnosticCode): code is HooklatchErrorCode {
  return typeof code === 'string' && Object.hasOwn(SETUP_GUIDANCE, code);
}
