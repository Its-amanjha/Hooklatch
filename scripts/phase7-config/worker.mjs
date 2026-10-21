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
    const rawNow = specOptions.now;

    options.now = isCallable(rawNow) ? rawNow : () => rawNow;
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

    let sdkModule;

    try {
      sdkModule = await import('../../dist/index.js');
    } catch {
      return Response.json({
        ok: false,
        errorCategory: 'module-load-failure',
        errorCode: 'dist-import-failed',
      }, { status: 500 });
    }

    if (url.pathname === '/sdk-info') {
      return Response.json({
        loaded: isCallable(sdkModule.verify),
        providers: sdkModule.SUPPORTED_PROVIDERS ?? [],
      });
    }

    const isVerifyRequest = url.pathname.startsWith('/verify-request');

    const isVerify = url.pathname.startsWith('/verify');

    const isCreateVerifier = url.pathname.startsWith('/create-verifier');

    if (isVerifyRequest || isVerify || isCreateVerifier) {
      const caseHeader = request.headers.get('x-test-case');

      if (!caseHeader) {
        return Response.json({
          ok: false,
          errorCategory: 'request-error',
          errorCode: 'missing-case-header',
        }, { status: 400 });
      }

      let spec;

      try {
        spec = JSON.parse(caseHeader);
      } catch {
        return Response.json({
          ok: false,
          errorCategory: 'request-error',
          errorCode: 'malformed-case-header',
        }, { status: 400 });
      }

      try {
        if (!isCallable(sdkModule.verify)) {
          return Response.json({
            ok: false,
            errorCategory: 'system',
            errorCode: 'sdk-verify-not-callable',
          }, { status: 501 });
        }

        const verifyOptions = buildVerifyOptions(spec.options);

        let result;

        if (isVerifyRequest) {
          // Tests setup-before-body-pull directly through public API without pre-reading body
          result = await sdkModule.verifyRequest(request, verifyOptions);
        } else if (isCreateVerifier) {
          const rawBody = new Uint8Array(await request.arrayBuffer());

          const verifier = sdkModule.createVerifier(verifyOptions);

          result = await verifier({ rawBody, headers: request.headers });
        } else {
          const rawBody = new Uint8Array(await request.arrayBuffer());

          result = await sdkModule.verify({ rawBody, headers: request.headers }, verifyOptions);
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
          errorCode: isHooklatch ? err.code : 'internal-error',
          errorCategory: isHooklatch ? 'verification' : 'system',
        }, { status: 200 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
