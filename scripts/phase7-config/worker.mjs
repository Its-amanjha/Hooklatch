/**
 * Neutral Web-standard worker for workerd qualification of Grafana and Polar.
 *
 * Strictly zero Node builtins, no process, and no Buffer imports.
 * Communicates via standard Web Fetch Request / Response.
 */

function isCallable(val) {
  return Object.prototype.toString.call(val) === '[object Function]' ||
    Object.prototype.toString.call(val) === '[object AsyncFunction]';
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/runtime') {
      return Response.json({
        userAgent: globalThis.navigator?.userAgent ?? 'unavailable',
        hasProcess: typeof process !== 'undefined',
        hasBuffer: typeof Buffer !== 'undefined',
      });
    }

    if (url.pathname === '/health') {
      return Response.json({ status: 'healthy', environment: 'workerd' });
    }

    if (url.pathname.startsWith('/case/')) {
      const caseHeader = request.headers.get('x-test-case');

      if (!caseHeader) {
        return Response.json({ error: 'Missing x-test-case header' }, { status: 400 });
      }

      let spec;

      try {
        spec = JSON.parse(caseHeader);
      } catch (err) {
        return Response.json({ error: `Malformed x-test-case: ${err.message}` }, { status: 400 });
      }

      try {
        const sdk = await import('../../src/index.js').catch(() => null);

        if (!sdk || !isCallable(sdk.verify)) {
          return Response.json({
            ok: false,
            status: 'blocked',
            message: 'SDK verify is unavailable or does not support 18 providers yet.',
          }, { status: 501 });
        }

        const rawBody = new Uint8Array(await request.arrayBuffer());

        const verifyOptions = {
          provider: spec.provider,
          secrets: spec.options.secrets,
          providerOptions: spec.options.providerOptions,
          toleranceSeconds: spec.options.toleranceSeconds,
          now: () => spec.options.now,
        };

        const result = await sdk.verify({ rawBody, headers: request.headers }, verifyOptions);

        return Response.json({
          ok: result.ok,
          provider: result.provider,
          reason: result.reason,
          identity: result.identity,
          bytes: result.rawBody ? Array.from(result.rawBody) : undefined,
        });
      } catch (err) {
        return Response.json({
          ok: false,
          error: err.name,
          message: err.message,
        }, { status: 500 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
