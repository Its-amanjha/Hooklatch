/**
 * Neutral Web-standard worker for workerd qualification of Grafana and Polar.
 *
 * Strictly zero Node builtins, no process, and no Buffer imports.
 * Communicates via standard Web Fetch Request / Response.
 */

function isString(val) {
  return Object.prototype.toString.call(val) === '[object String]';
}

function isCallable(val) {
  return Object.prototype.toString.call(val) === '[object Function]' ||
    Object.prototype.toString.call(val) === '[object AsyncFunction]';
}

function buildVerifyOptions(specOptions) {
  const options = {
    provider: specOptions.provider,
    secrets: specOptions.secrets,
  };

  if (specOptions.toleranceSeconds !== undefined) {
    options.toleranceSeconds = specOptions.toleranceSeconds;
  }

  if (specOptions.now !== undefined) {
    options.now = () => specOptions.now;
  }

  if (specOptions.providerOptions !== undefined) {
    const providerOpts = {};

    for (const [key, value] of Object.entries(specOptions.providerOptions)) {
      if (value !== undefined) {
        providerOpts[key] = value;
      }
    }

    options.providerOptions = providerOpts;
  }

  return options;
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

    const isVerifyRequest = url.pathname.startsWith('/verify-request');

    const isVerify = url.pathname.startsWith('/verify');

    const isCreateVerifier = url.pathname.startsWith('/create-verifier');

    if (isVerifyRequest || isVerify || isCreateVerifier) {
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

        const verifyOptions = buildVerifyOptions(spec.options);

        let result;

        if (isVerifyRequest) {
          // Tests setup-before-body-pull: pass request directly without reading body first
          result = await sdk.verifyRequest(request, verifyOptions);
        } else if (isCreateVerifier) {
          const rawBody = new Uint8Array(await request.arrayBuffer());

          const verifier = sdk.createVerifier(verifyOptions);

          result = await verifier({ rawBody, headers: request.headers });
        } else {
          const rawBody = new Uint8Array(await request.arrayBuffer());

          result = await sdk.verify({ rawBody, headers: request.headers }, verifyOptions);
        }

        return Response.json({
          ok: result.ok,
          provider: result.provider,
          reason: result.reason,
          identity: result.identity,
          bytes: result.rawBody ? Array.from(result.rawBody) : undefined,
        });
      } catch (err) {
        const isHooklatch = err.name === 'HooklatchError' ||
          Boolean(err.code && isString(err.code));

        return Response.json({
          ok: false,
          isHooklatchError: isHooklatch,
          errorCode: err.code ?? err.name,
          message: err.message,
        }, { status: 200 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
