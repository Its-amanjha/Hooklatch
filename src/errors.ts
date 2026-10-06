import type { TernErrorCode } from './types.js';

/** Operational error. Messages deliberately exclude request and credential data. */
export class TernError extends Error {
  readonly code: TernErrorCode;
  constructor(code: TernErrorCode, message: string) {
    super(message);
    this.name = 'TernError';
    this.code = code;
  }
}
