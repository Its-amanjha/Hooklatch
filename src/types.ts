/** Contract version 1. Verification never parses or validates payload schemas. */
export type Provider = 'stripe' | 'github' | 'shopify' | 'standard-webhooks'
  | 'clerk' | 'svix' | 'razorpay' | 'paddle' | 'lemon-squeezy'
  | 'dodo-payments' | 'gitlab' | 'replicate' | 'workos' | 'sentry' | 'doppler' | 'sanity'
  | 'grafana' | 'polar' | 'linear';

export type HeaderInput = Headers
  | Readonly<Record<string, string | readonly string[] | undefined>>
  | readonly (readonly [string, string])[];

export interface WebhookRequest { readonly rawBody: Uint8Array; readonly headers: HeaderInput }

export type GrafanaOptions =
  | { readonly mode: 'body'; readonly signatureHeader?: string; readonly timestampHeader?: never }
  | { readonly mode: 'timestamped'; readonly signatureHeader?: string; readonly timestampHeader: string };

export interface PolarOptions { readonly secretMode?: 'current' | 'legacy' }

interface CommonVerifyOptions {
  readonly secrets: readonly string[];
  readonly toleranceSeconds?: number;
  readonly now?: () => number;
  readonly maxBodyBytes?: number;
}

export type VerifyOptions = CommonVerifyOptions & (
  | { readonly provider: Exclude<Provider, 'grafana' | 'polar'>; readonly providerOptions?: never }
  | { readonly provider: 'grafana'; readonly providerOptions: GrafanaOptions }
  | { readonly provider: 'polar'; readonly providerOptions?: PolarOptions }
);

export type IdentityField = 'deliveryId' | 'eventId' | 'timestamp';

export interface EventIdentity {
  readonly deliveryId: string | null;
  readonly eventId: string | null;
  readonly timestamp: number | null;
  readonly authenticatedFields: readonly IdentityField[];
}

export type VerificationFailureReason = 'missing-signature' | 'malformed-signature'
  | 'unsupported-scheme' | 'invalid-signature' | 'missing-identity'
  | 'missing-timestamp' | 'timestamp-expired' | 'timestamp-future' | 'body-too-large';

export interface FailureDetails {
  readonly ok: false;
  readonly reason: VerificationFailureReason;
  readonly message: string;
}

export interface VerificationSuccess {
  readonly ok: true;
  readonly provider: Provider;
  readonly rawBody: Uint8Array;
  readonly identity: EventIdentity;
}

export interface VerificationFailure extends FailureDetails { readonly provider: Provider }

export type VerificationResult = VerificationSuccess | VerificationFailure;

export type HooklatchErrorCode = 'unknown-provider' | 'missing-secrets' | 'invalid-secret'
  | 'invalid-options' | 'invalid-input' | 'body-consumed' | 'body-read-failed'
  | 'crypto-unavailable' | 'internal';
