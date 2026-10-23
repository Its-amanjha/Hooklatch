import { HooklatchError } from '../errors.js';
import { verifyRequest } from '../index.js';
import type { VerificationSuccess, VerifyOptions } from '../types.js';

export type NextWebhookHandlerOptions = VerifyOptions & {
  readonly handler: (request: Request, success: VerificationSuccess) => Response | Promise<Response>;
};

export function createWebhookHandler(options: NextWebhookHandlerOptions): (request: Request) => Promise<Response> {
  try {
    // Observe credential descriptors before object-rest can invoke an accessor
    // that replaces itself. Existing HMAC top-level getter snapshots stay intact.
    const credentials = ['publicKeys', 'expectedUserId', 'secrets', 'secret'].map((name) => ({
      name, property: Object.getOwnPropertyDescriptor(options, name),
    }));

    const { handler, ...verifyOptions } = options;

    for (const { name, property } of credentials) {
      const preserve = verifyOptions.provider === 'fal'
        || (verifyOptions.provider === 'vercel' && (name === 'publicKeys' || name === 'expectedUserId'));

      if (preserve && property !== undefined) Object.defineProperty(verifyOptions, name, property);
    }

    // Object rest omits non-enumerable fields; own configuration presence is meaningful.
    if (Object.hasOwn(options, 'providerOptions') && !Object.hasOwn(verifyOptions, 'providerOptions')) {
      Object.defineProperty(verifyOptions, 'providerOptions', {
        value: options.providerOptions, enumerable: true, configurable: true, writable: true,
      });
    }

    return requestHandler(verifyOptions, handler);
  } catch {
    // Contain caller-owned accessors without exposing their thrown values.
    return async () => new Response('Internal Server Error', { status: 500 });
  }
}

function requestHandler(
  verifyOptions: VerifyOptions, handler: NextWebhookHandlerOptions['handler'],
): (request: Request) => Promise<Response> {

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
