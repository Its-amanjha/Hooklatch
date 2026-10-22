/** Web-only executor shared by Node and workerd qualification. */
function isCallable(value) {
  return Object.prototype.toString.call(value) === '[object Function]'
    || Object.prototype.toString.call(value) === '[object AsyncFunction]';
}

function buildOptions(wire) {
  const options = { ...wire, secrets: [...wire.secrets] };

  if (Object.hasOwn(wire, 'providerOptions')) options.providerOptions = { ...wire.providerOptions };

  if (Object.hasOwn(wire, 'now')) {
    const now = wire.now;
    options.now = () => now;
  }

  return options;
}

function packResult(result) {
  return {
    ok: result.ok, provider: result.provider, reason: result.reason,
    identity: result.identity,
    bytes: result.rawBody instanceof Uint8Array ? Array.from(result.rawBody) : undefined,
  };
}

function packError(sdk, error) {
  if (error instanceof sdk.HooklatchError) return { isHooklatchError: true, errorCode: error.code };

  return { isInfrastructureFailure: true, errorCategory: 'sdk-exception' };
}

/** Observe a real awaited rejection, with stream auto-pull disabled. */
async function setupBeforeRead(sdk, options) {
  let pulls = 0;

  const stream = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array([0, 255, 1]));
      controller.close();
    },
  }, { highWaterMark: 0 });

  const request = new Request('https://qualification.test/setup', {
    method: 'POST', body: stream, duplex: 'half',
  });

  let outcome;

  try {
    outcome = packResult(await sdk.verifyRequest(request, options));
  } catch (error) {
    outcome = packError(sdk, error);
  }

  await Promise.resolve();
  outcome.bodyPulls = pulls;
  outcome.bodyUsed = request.bodyUsed;
  await stream.cancel();

  return outcome;
}

/** Each invocation owns options and byte views; catalogue fixtures never mutate. */
export async function executeSdkCase(sdk, spec, api) {
  const options = buildOptions(spec.options);

  if (spec.scenario === 'setup-before-read') return setupBeforeRead(sdk, options);
  const rawBody = new Uint8Array(spec.bytes);
  const original = new Uint8Array(rawBody);
  const headers = new Headers(spec.headers);

  const mutate = () => {
    if (spec.scenario === 'config-snapshot') {
      if (options.provider === 'grafana') {
        options.providerOptions.mode = 'invalid-after-setup';
        options.providerOptions.signatureHeader = 'x-after-setup';
        options.providerOptions.timestampHeader = 'x-after-setup-time';
      } else options.providerOptions.secretMode = 'invalid-after-setup';
    }

    if (spec.scenario === 'secret-snapshot') options.secrets[0] = 'mutated-synthetic-key';
  };

  try {
    let pending;

    if (api === 'createVerifier') {
      const verifier = sdk.createVerifier(options);
      mutate();
      pending = verifier({ rawBody, headers });
    } else if (api === 'verifyRequest') {
      const stream = new ReadableStream({
        pull(controller) {
          controller.enqueue(rawBody);
          controller.close();
        },
      }, { highWaterMark: 0 });

      const request = new Request('https://qualification.test/webhook', {
        method: 'POST', headers, body: stream, duplex: 'half',
      });

      pending = sdk.verifyRequest(request, options);
      mutate();
    } else if (api === 'verify') {
      pending = sdk.verify({ rawBody, headers }, options);
      mutate();
    } else return { isInfrastructureFailure: true, errorCategory: 'unknown-api' };

    // Direct APIs snapshot before crypto awaits. Request bodies are asynchronous:
    // their returned bytes must be independent of the source after the read.
    if (spec.scenario === 'byte-snapshot' && api !== 'verifyRequest') rawBody.fill(0);
    const result = await pending;

    if (spec.scenario === 'byte-snapshot' && api === 'verifyRequest') rawBody.fill(0);
    const packed = packResult(result);

    if (spec.scenario === 'byte-snapshot') {
      packed.snapshotSourceChanged = rawBody.some((byte, index) => byte !== original[index]);
    }

    return packed;
  } catch (error) {
    return packError(sdk, error);
  }
}

export default {
  async fetch(request) {
    if (new URL(request.url).pathname === '/runtime') {
      return Response.json({
        userAgent: globalThis.navigator?.userAgent ?? 'unavailable',
        hasProcess: Object.hasOwn(globalThis, 'process'),
        hasBuffer: Object.hasOwn(globalThis, 'Buffer'),
      });
    }

    try {
      const spec = await request.json();
      const sdk = await import('../../dist/index.js');

      if (!isCallable(sdk.verify) || !isCallable(sdk.verifyRequest)
        || !isCallable(sdk.createVerifier) || !isCallable(sdk.HooklatchError)) {
        return Response.json({ errorCategory: 'sdk-exports' }, { status: 500 });
      }

      return Response.json(await executeSdkCase(sdk, spec, spec.api));
    } catch {
      return Response.json({ errorCategory: 'worker-execution' }, { status: 500 });
    }
  },
};
