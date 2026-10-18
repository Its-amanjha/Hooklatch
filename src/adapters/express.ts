import type { NextFunction, Request, Response, RequestHandler } from 'express';
import { HttpError, readNodeStream } from './shared.js';
import { HooklatchError } from '../errors.js';
import { createVerifier } from '../index.js';
import { normalizeOptions } from '../internal/options.js';
import { normalizeHeaders } from '../internal/headers.js';
import type { VerificationSuccess, VerifyOptions } from '../types.js';

declare module 'express-serve-static-core' {
  interface Request {
    webhook?: VerificationSuccess;
  }
}

export function createWebhookMiddleware(options: VerifyOptions): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const normalized = normalizeOptions(options);
      const verifier = createVerifier(normalized);
      const headers = [...normalizeHeaders(req.headers)];
      const maxBytes = normalized.maxBodyBytes;
      const encodingHeader = req.headers['content-encoding'];
      const encoding = Array.isArray(encodingHeader) ? encodingHeader.join(',') : encodingHeader;

      if (encoding && encoding.toLowerCase() !== 'identity') {
        res.status(400).send('Bad Request');

        return;
      }

      const body: unknown = req.body;
      let rawBody: Uint8Array;

      if (body instanceof Uint8Array) {
        if (body.byteLength > maxBytes) {
          res.status(413).send('Payload Too Large');

          return;
        }

        rawBody = new Uint8Array(body);
      } else if (body !== undefined && body !== null) {
        res.status(500).send('Internal Server Error');

        return;
      } else {
        if (req.readableEnded || req.readableDidRead || req.destroyed || req.readable === false) {
          res.status(500).send('Internal Server Error');

          return;
        }

        rawBody = await readNodeStream(req, maxBytes);
      }

      const result = await verifier({ rawBody, headers });

      if (!result.ok) {
        const status = result.reason === 'body-too-large' ? 413 : 400;
        res.status(status).send(status === 413 ? 'Payload Too Large' : 'Bad Request');

        return;
      }

      req.webhook = result;
    } catch (err) {
      if (err instanceof HttpError) {
        res.status(err.status).send(err.message);

        return;
      }

      if (err instanceof HooklatchError) {
        res.status(500).send('Internal Server Error');

        return;
      }

      next(err);

      return;
    }

    next();
  };
}
