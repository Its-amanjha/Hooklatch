import { concatBytes, decodeBase64, decodeHex, utf8 } from '../../src/internal/bytes.js';

test('canonical hex accepts either case and rejects partial or invalid bytes', () => {
  expect(decodeHex('00aAFF')).toEqual(new Uint8Array([0, 170, 255]));
  for (const value of ['0', '0g', ' aa', 'aa\n']) expect(decodeHex(value)).toBeNull();
});

test('base64 accepts canonical padded/unpadded data and rejects noncanonical bits', () => {
  expect(decodeBase64('Zg==')).toEqual(utf8('f'));
  expect(decodeBase64('Zg')).toEqual(utf8('f'));
  expect(decodeBase64('Zm8=')).toEqual(utf8('fo'));
  expect(decodeBase64('Zm8')).toEqual(utf8('fo'));
  for (const value of ['Zh==', 'Zg=', 'Z', 'Zg===', 'Z g==', 'Zm9=', 'Zg--']) {
    expect(decodeBase64(value)).toBeNull();
  }
});

test('byte concatenation retains binary bytes rather than decoding them', () => {
  expect(concatBytes(utf8('x.'), new Uint8Array([255, 0, 128])))
    .toEqual(new Uint8Array([120, 46, 255, 0, 128]));
});
