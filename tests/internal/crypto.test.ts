import { verifyHmac } from '../../src/internal/crypto.js';
import { decodeHex, utf8 } from '../../src/internal/bytes.js';

test('verifies the published GitHub HMAC vector and rejects a tampered message', async () => {
  const signature = decodeHex('757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17')!;
  const key = utf8("It's a Secret to Everybody");
  expect(await verifyHmac([key], [signature], utf8('Hello, World!'))).toBe(true);
  expect(await verifyHmac([key], [signature], utf8('Hello, World?'))).toBe(false);
});

test('rotation accepts any active key/signature pair', async () => {
  const signature = decodeHex('757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17')!;
  expect(await verifyHmac([utf8('wrong'), utf8("It's a Secret to Everybody")],
    [new Uint8Array(32), signature], utf8('Hello, World!'))).toBe(true);
});
