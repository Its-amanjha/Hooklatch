import { HooklatchError } from '../errors.js';
import { verifyRequest } from '../index.js';
import type { VerificationSuccess, VerifyOptions } from '../types.js';

export interface NextWebhookHandlerOptions extends VerifyOptions {
  readonly handler: (request: Request, success: VerificationSuccess) => Response | Promise<Response>;
}

export function createWebhookHandler(options: NextWebhookHandlerOptions): (request: Request) => Promise<Response> {
  const { handler, ...verifyOptions } = options;

  return async (request: Request): Promise<Response> => {
    const encoding = request.headers.get('content-encoding');

    if (encoding && encoding.toLowerCase() !== 'identity') {
      return new Response('Bad Request', { status: 400 });
    }

    let verification!: VerificationSuccess;

    try {
      const result = await verifyRequest(request, verifyOptions);

      if (!result.ok) {
        if (result.reason === 'body-too-large') {
          return new Response('Payload Too Large', { status: 413 });
        }

        return new Response('Bad Request', { status: 400 });
      }

      verification = result;
    } catch (err) {
      if (err instanceof HooklatchError) {
        return new Response('Internal Server Error', { status: 500 });
      }

      throw err;
    }

    return await handler(request, verification);
  };
}
