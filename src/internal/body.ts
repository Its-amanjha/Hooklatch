import { HooklatchError } from '../errors.js';

/** null means size limit exceeded. Reads actual chunks, not trusted length claims. */
export async function readBody(request: Request, maxBodyBytes: number): Promise<Uint8Array | null> {
  if (request.bodyUsed || request.body?.locked) throw new HooklatchError('body-consumed', 'Request body has already been consumed.');

  if (!request.body) return new Uint8Array();
  let reader: ReadableStreamDefaultReader<Uint8Array>;

  try { reader = request.body.getReader(); }
  catch { throw new HooklatchError('body-read-failed', 'Unable to read request body.'); }

  // Bound bookkeeping as well as byte storage: a chunk array can grow very
  // large even for a tiny body, and spreading it exceeds JS argument limits.
  let output = new Uint8Array(Math.min(maxBodyBytes, 8192));
  let size = 0;

  try {
    while (true) {
      const chunk = await reader.read();

      if (chunk.done) break;

      if (!(chunk.value instanceof Uint8Array)) throw new Error('Invalid byte stream');
      size += chunk.value.byteLength;

      if (size > maxBodyBytes) {
        // Cancellation must not hold the response hostage to a stalled producer.
        void reader.cancel().catch(() => undefined);

        return null;
      }

      if (size > output.byteLength) {
        const grown = new Uint8Array(Math.min(maxBodyBytes, Math.max(size, output.byteLength * 2)));
        grown.set(output);
        output = grown;
      }

      output.set(chunk.value, size - chunk.value.byteLength);
    }

    return output.slice(0, size);
  } catch { throw new HooklatchError('body-read-failed', 'Unable to read request body.'); }
  finally { reader.releaseLock(); }
}
