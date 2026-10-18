import { readBody } from '../../src/internal/body.js';

test('reads a byte snapshot and enforces actual streamed size without Content-Length', async () => {
  const stream = new ReadableStream<Uint8Array>({ start(controller) {
    controller.enqueue(new Uint8Array([1, 2]));
    controller.enqueue(new Uint8Array([3, 4]));
    controller.close();
  } });

  const init = { method: 'POST', body: stream, duplex: 'half' } satisfies RequestInit & { duplex: 'half' };
  const request = new Request('https://example.test', init);
  expect(await readBody(request, 3)).toBeNull();
});

test('accepts an exact-limit body and detects already-consumed requests', async () => {
  const request = new Request('https://example.test', { method: 'POST', body: 'hi' });
  expect(await readBody(request, 2)).toEqual(new Uint8Array([104, 105]));
  await expect(readBody(request, 2)).rejects.toMatchObject({ code: 'body-consumed' });
});

test('never echoes stream failure contents', async () => {
  const init = { method: 'POST', body: new ReadableStream({
    start(controller) { controller.error(new Error('sensitive request data')); },
  }), duplex: 'half' } satisfies RequestInit & { duplex: 'half' };

  const request = new Request('https://example.test', init);

  await expect(readBody(request, 2)).rejects.toMatchObject({ code: 'body-read-failed', message: 'Unable to read request body.' });
});

test('accepts many tiny chunks within the byte limit without spreading an argument list', async () => {
  let remaining = 150000;

  const stream = new ReadableStream<Uint8Array>({ pull(controller) {
    if (remaining-- > 0) controller.enqueue(new Uint8Array([7]));
    else controller.close();
  } });

  const init = { method: 'POST', body: stream, duplex: 'half' } satisfies RequestInit & { duplex: 'half' };
  const request = new Request('https://example.test', init);
  const bytes = await readBody(request, 150000);
  expect(bytes?.byteLength).toBe(150000);
  expect(bytes?.[149999]).toBe(7);
});
