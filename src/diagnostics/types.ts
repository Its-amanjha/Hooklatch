import type { HooklatchErrorCode, Provider, VerificationFailureReason } from '../types.js';

/** Stable diagnostic codes; guidance text is intended for people. */
export type DiagnosticCode = VerificationFailureReason | HooklatchErrorCode;

export interface DiagnosticOptions {
  readonly provider?: Provider;
  readonly verbose?: boolean;
}

/** Only allowlisted guidance and validated provider names enter this output. */
export interface Diagnostic {
  readonly code: DiagnosticCode;
  readonly kind: 'verification' | 'setup';
  readonly provider?: Provider;
  readonly summary: string;
  readonly possibleCauses: readonly string[];
  readonly suggestions: readonly string[];
  readonly detail?: {
    readonly expectedHeaders: readonly string[];
    readonly grammar: string;
  };
}
