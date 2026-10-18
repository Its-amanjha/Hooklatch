import type { HooklatchErrorCode } from './types.js';

/** Operational error. Messages deliberately exclude request and credential data. */
export class HooklatchError extends Error {
  readonly code: HooklatchErrorCode;
  constructor(code: HooklatchErrorCode, message: string) {
    super(message);
    this.name = 'HooklatchError';
    this.code = code;
  }
}
