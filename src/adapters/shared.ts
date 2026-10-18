/** Shared helpers for framework adapters. Node/Web runtime agnostic except where noted. */

export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
  }
}

function isText(value: Uint8Array | ArrayBuffer | string): value is string {
  return typeof value === 'string';
}

export function toUint8Array(value: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);

  if (value instanceof ArrayBuffer) return new Uint8Array(value);

  if (isText(value)) return new TextEncoder().encode(value);
  throw new HttpError(500, 'Internal Server Error');
}

export async function readNodeStream(stream: AsyncIterable<unknown>, maxBytes: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;

  try {
    for await (const chunk of stream) {
      const bytes = chunk instanceof Uint8Array
        ? chunk
        : chunk instanceof ArrayBuffer
          ? new Uint8Array(chunk)
          : null;

      if (!bytes) throw new HttpError(500, 'Internal Server Error');
      size += bytes.byteLength;

      if (size > maxBytes) throw new HttpError(413, 'Payload Too Large');
      chunks.push(new Uint8Array(bytes));
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(500, 'Internal Server Error');
  }

  const output = new Uint8Array(size);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return output;
}
