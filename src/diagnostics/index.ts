import { HooklatchError } from '../errors.js';
import type { Provider, VerificationFailure } from '../types.js';
import type { Diagnostic, DiagnosticCode, DiagnosticOptions } from './types.js';
import {
  getProviderDetail,
  getSetupGuidance,
  getVerificationGuidance,
  isVerificationCode,
} from './catalog.js';

function validateProvider(provider: Provider | undefined): Provider | undefined {
  if (provider === undefined) return undefined;

  const valid: readonly Provider[] = ['stripe', 'github', 'shopify', 'standard-webhooks', 'clerk', 'svix'];

  if (valid.includes(provider)) {
    return provider;
  }

  throw new HooklatchError('invalid-input', 'Invalid provider name.');
}

function normalizeOptions(options: DiagnosticOptions): DiagnosticOptions {
  if (options === null || !(options instanceof Object)) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic options.');
  }

  const provider = validateProvider(options.provider);

  return provider !== undefined
    ? { provider, verbose: options.verbose === true }
    : { verbose: options.verbose === true };
}

function buildDiagnostic(
  code: DiagnosticCode,
  kind: 'verification' | 'setup',
  guidance: { readonly summary: string; readonly possibleCauses: readonly string[]; readonly suggestions: readonly string[] },
  provider: Provider | undefined,
  detail: { readonly expectedHeaders: readonly string[]; readonly grammar: string } | undefined,
): Diagnostic {
  const result: Diagnostic = {
    code,
    kind,
    summary: guidance.summary,
    possibleCauses: [...guidance.possibleCauses],
    suggestions: [...guidance.suggestions],
  };

  if (provider !== undefined) {
    Object.assign(result, { provider });
  }

  if (detail !== undefined) {
    Object.assign(result, { detail: { expectedHeaders: [...detail.expectedHeaders], grammar: detail.grammar } });
  }

  return result;
}

export function diagnose(
  input: VerificationFailure | HooklatchError,
  options?: DiagnosticOptions,
): Diagnostic {
  if (input instanceof HooklatchError) {
    const normalized = options !== undefined ? normalizeOptions(options) : undefined;
    const provider = normalized?.provider;
    const verbose = normalized?.verbose;
    const guidance = getSetupGuidance(input.code);

    if (guidance === undefined) {
      throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
    }

    const detail = provider !== undefined && verbose === true ? getProviderDetail(provider) : undefined;

    return buildDiagnostic(input.code, 'setup', guidance, provider, detail);
  }

  if (input == null) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }

  // SAFETY: input was rejected when null or non-object above; HooklatchError is
  // handled by the instanceof branch above. The remaining object must conform
  // to VerificationFailure at the type boundary.
  const failure = input as VerificationFailure;
  const code = failure.reason;

  if (!isVerificationCode(code)) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }

  const normalized = options !== undefined ? normalizeOptions(options) : undefined;
  const failureProvider = validateProvider(failure.provider);

  if (failureProvider === undefined && failure.provider !== undefined) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }

  if (normalized?.provider !== undefined && normalized.provider !== failureProvider) {
    throw new HooklatchError('invalid-input', 'Provider mismatch.');
  }

  const provider = failureProvider ?? normalized?.provider;
  const verbose = normalized?.verbose;
  const guidance = getVerificationGuidance(code);
  const detail = provider !== undefined && verbose === true ? getProviderDetail(provider) : undefined;

  return buildDiagnostic(code, 'verification', guidance, provider, detail);
}

export type { Diagnostic, DiagnosticOptions, DiagnosticCode } from './types.js';
