import { HooklatchError } from '../errors.js';
import { SUPPORTED_PROVIDERS } from '../providers/index.js';
import type { Provider, VerificationFailure } from '../types.js';
import type { Diagnostic, DiagnosticCode, DiagnosticOptions } from './types.js';
import {
  getProviderDetail,
  getSetupGuidance,
  getVerificationGuidance,
  isVerificationCode,
  isSetupCode,
} from './catalog.js';

type DiagnosticRecord = VerificationFailure | DiagnosticOptions;

function isRecord(value: DiagnosticRecord): value is DiagnosticRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);

  return prototype === null || prototype === Object.prototype;
}

function isProvider(value: Provider): value is Provider {
  return typeof value === 'string' && SUPPORTED_PROVIDERS.some((provider) => provider === value);
}

function isBoolean(value: unknown): value is boolean { return typeof value === 'boolean'; }

function validateProvider(provider: Provider | undefined): Provider | undefined {
  if (provider === undefined) return undefined;

  if (isProvider(provider)) {
    return provider;
  }

  throw new HooklatchError('invalid-input', 'Invalid provider name.');
}

function normalizeOptions(options: DiagnosticOptions): DiagnosticOptions {
  if (!isRecord(options) || (options.verbose !== undefined && !isBoolean(options.verbose))) {
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

function diagnoseValidated(
  input: VerificationFailure | HooklatchError,
  options?: DiagnosticOptions,
): Diagnostic {
  if (input instanceof HooklatchError) {
    const code = input.code;

    if (!isSetupCode(code)) throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
    const normalized = options !== undefined ? normalizeOptions(options) : undefined;
    const provider = normalized?.provider;
    const verbose = normalized?.verbose;
    const guidance = getSetupGuidance(code);

    if (guidance === undefined) {
      throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
    }

    const detail = provider !== undefined && verbose === true ? getProviderDetail(provider) : undefined;

    return buildDiagnostic(code, 'setup', guidance, provider, detail);
  }

  if (!isRecord(input)) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }

  const { ok, reason: code, provider: failureProvider } = input;

  if (ok !== false || !isVerificationCode(code) || !isProvider(failureProvider)) {
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }

  const normalized = options !== undefined ? normalizeOptions(options) : undefined;

  if (normalized?.provider !== undefined && normalized.provider !== failureProvider) {
    throw new HooklatchError('invalid-input', 'Provider mismatch.');
  }

  const provider = failureProvider ?? normalized?.provider;
  const verbose = normalized?.verbose;
  const guidance = getVerificationGuidance(code);
  const detail = provider !== undefined && verbose === true ? getProviderDetail(provider) : undefined;

  return buildDiagnostic(code, 'verification', guidance, provider, detail);
}

export function diagnose(input: VerificationFailure | HooklatchError, options?: DiagnosticOptions): Diagnostic {
  try {
    return diagnoseValidated(input, options);
  } catch {
    // Untrusted accessors/proxies may throw; their messages must not escape.
    throw new HooklatchError('invalid-input', 'Invalid diagnostic input.');
  }
}

export type { Diagnostic, DiagnosticOptions, DiagnosticCode } from './types.js';
