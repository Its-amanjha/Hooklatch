import { verifyRequest } from '../index.js';
import type { VerificationSuccess, VerifyOptions } from '../types.js';

export interface ExecutionContextLike {
  waitUntil?(promise: Promise<unknown>): void;
  passThroughOnException?(): void;
}

export interface WorkerWebhookHandlerOptions<Env = unknown> {
  readonly options: (env: Env) => VerifyOptions;
  readonly handler: (
    request: Request,
    env: Env,
    ctx: ExecutionContextLike,
    success: VerificationSuccess,
  ) => Response | Promise<Response>;
}

export function createWebhookHandler<Env = unknown>(
  options: WorkerWebhookHandlerOptions<Env>,
): (request: Request, env: Env, ctx: ExecutionContextLike) => Promise<Response> {
  return async (request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> => {
    const encoding = request.headers.get('content-encoding');
    if (encoding && encoding.toLowerCase() !== 'identity') {
      return new Response('Bad Request', { status: 400 });
    }

    let verification!: VerificationSuccess;
    try {
      const verifyOptions = options.options(env);
      const result = await verifyRequest(request, verifyOptions);
      if (!result.ok) {
        if (result.reason === 'body-too-large') {
          return new Response('Payload Too Large', { status: 413 });
        }
        return new Response('Bad Request', { status: 400 });
      }
      verification = result;
    } catch {
      // This boundary contains setup/verification only, never the user handler.
      return new Response('Internal Server Error', { status: 500 });
    }
    return await options.handler(request, env, ctx, verification);
  };
}
