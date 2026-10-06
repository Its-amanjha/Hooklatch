export function utf8(value: string): Uint8Array { return new TextEncoder().encode(value); }

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

export function decodeHex(value: string): Uint8Array | null {
  if (value.length % 2 !== 0 || !/^[\da-f]*$/i.test(value)) return null;
  const output = new Uint8Array(value.length / 2);
  for (let i = 0; i < output.length; i += 1) output[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return output;
}

export function decodeBase64(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  const unpadded = value.replace(/=+$/, '');
  if (unpadded.length % 4 === 1) return null;
  const padded = unpadded + '='.repeat((4 - unpadded.length % 4) % 4);
  if (value.includes('=') && value !== padded) return null;
  try {
    const binary = atob(padded);
    if (btoa(binary) !== padded) return null;
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch { return null; }
}
