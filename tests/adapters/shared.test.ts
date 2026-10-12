import { HttpError, readNodeStream } from '../../src/adapters/shared.js';

test('readNodeStream returns bytes under limit', async () => {
  const stream = (async function* () {
    yield new Uint8Array([1, 2]);
    yield new Uint8Array([3]);
  })();
  expect(await readNodeStream(stream, 10)).toEqual(new Uint8Array([1, 2, 3]));
});

test('readNodeStream throws 413 on overflow', async () => {
  const stream = (async function* () {
    yield new Uint8Array([1, 2, 3, 4]);
  })();
  await expect(readNodeStream(stream, 2)).rejects.toMatchObject({ status: 413 });
});

test('HttpError carries status and message', () => {
  const err = new HttpError(418, 'teapot');
  expect(err.status).toBe(418);
  expect(err.message).toBe('teapot');
});
