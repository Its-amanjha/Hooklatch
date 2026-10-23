/**
 * Phase 9 Stage B anchor suite for the Vercel and fal fixture corpora.
 *
 * These anchors never import provider modules, the Provider union, the
 * verification entry points, or even the shared test helpers: both providers
 * are unregistered at this base (19 providers) and the suite validates fixture
 * data only, in a fully self-contained way. Every byte-bearing expectation is
 * recomputed here from the recorded request material with node:crypto.
 *
 * Frozen receiver contract (notes/phase-9-stage-b/contract.md v1):
 *   vercel: HMAC-SHA1 over exact body bytes with a literal UTF-8 secret,
 *           20-byte digest, 40-hex x-vercel-signature accepted in either case,
 *           no signed timestamp, all-null identity, no freshness gate.
 *   fal:    Ed25519 over utf8(requestId LF userId LF timestamp LF
 *           lowerHex(sha256(rawBody))) with no trailing newline, 64-byte
 *           128-hex signature in either case, raw 32-byte caller-trusted keys
 *           (canonical unpadded base64url in fixture encoding only), required
 *           exact-string expectedUserId, and the auth -> account -> freshness
 *           reason order where missing/malformed grammar precedes every crypto
 *           step. Wrong recipient and stale-or-future times report the existing
 *           generic reasons; a wrong MAC always wins over both.
 *
 * The suite is dual-view: the record view keeps stored bytes verbatim while
 * the WHATWG Headers view trims outer HTTP whitespace per stored value
 * (collectSP-and-HTAB, plus CR/LF, per the fetch field-value normalization).
 * Material view differences must be declared via webHeadersExpected; the model
 * rejects undeclared divergence. Rows whose header values cannot materialize
 * inside a real WHATWG Headers instance are pinned to an exact record-only
 * list rather than silently skipped, and malformed JSON is demonstrated to be
 * a parse failure rather than a counted invariant.
 *
 * Deliberately invalid inputs built inside the mutation controls (the fifteen
 * guard controls and the mutation asserts) exist only to prove the guards and
 * the recomputation catch them; they are documented inline and are never cast
 * back into fixture state.
 */
import { Buffer } from 'node:buffer';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Strict failure helper. Guard and anchor failures throw with this prefix, so
// a green run implies every named check below actually ran.
// ---------------------------------------------------------------------------
function fail(message: string): never {
  throw new Error(`fixture-anchor failure: ${message}`);
}

function assertIsTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

// ---------------------------------------------------------------------------
// Minimal type guards. Runtime typeof stays inside guard functions per house
// rules; checklist logic elsewhere is plain throws.
// ---------------------------------------------------------------------------
function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number';
}

function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

const HEADER_TOKEN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

function isHeaderName(value: string): boolean {
  return HEADER_TOKEN.test(value);
}

function isHex(value: string, byteLength: number): boolean {
  return value.length === byteLength * 2 && /^[0-9a-f]*$/.test(value);
}

/** The frozen identifier grammar: 1..1024 visible ASCII, comma excluded. */
function visibleAsciiId(value: string): boolean {
  if (value.length < 1 || value.length > 1024) return false;

  for (const char of value) {

    const code = char.codePointAt(0);



    if (code === undefined || code < 0x21 || code > 0x7e || code === 0x2c) return false;

  }

  return true;

}

// ---------------------------------------------------------------------------


// Hand-rolled byte encodings, independent of Buffer's decoder behavior.








// ---------------------------------------------------------------------------

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

interface DecodedStretch {




























  readonly bytes: Buffer;

  readonly leftoverBits: number;




  readonly leftoverValue: number;


}


function decodeCascadeChecked(encoded: string, alphabet: string): DecodedStretch | null {
  let bits = 0;

  let bitCount = 0;

  const out: number[] = [];

  for (const char of encoded) {


    const symbol = alphabet.indexOf(char);


    if (symbol < 0) return null;


    bits = bits * 64 + symbol;

    bitCount += 6;


    if (bitCount >= 8) {

      bitCount -= 8;

      const scale = 2 ** bitCount;

      out.push(Math.floor(bits / scale) & 0xff);

      bits %= scale;



    }

  }


  return { bytes: Buffer.from(out), leftoverBits: bitCount, leftoverValue: bits };


}


function decodeCascade(encoded: string, alphabet: string): DecodedStretch {

  const report = decodeCascadeChecked(encoded, alphabet);

  if (report === null) fail('decoder rejects a symbol outside its alphabet');

  return report;


}

/** Canonical standard Base64: terminal padding exists unless the payload is exact full blocks. */


function decodeBase64(encoded: string): Buffer {


  if (encoded.length === 0) return Buffer.alloc(0);


  if (encoded.length % 4 !== 0) fail('body decoder rejects incomplete base64 blocks');







  const pads = encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0;

  const core = encoded.slice(0, encoded.length - pads);

  if (core.includes('=')) fail('body decoder rejects inner padding');


  const remainder = core.length % 4;




  if (remainder === 1) fail('body decoder rejects a one-symbol trailing block');



  const report = decodeCascade(core, BASE64_ALPHABET);


  const expectedPads = report.leftoverBits === 4 ? 2 : report.leftoverBits === 2 ? 1 : 0;




  if (report.leftoverBits !== 0 && report.leftoverBits !== 2 && report.leftoverBits !== 4) fail('body decoder rejects a noncanonical trailing block');






  if (pads !== expectedPads) fail('body decoder rejects a noncanonical padding split');




  if (report.leftoverValue !== 0) fail('body decoder rejects nonzero unused trailing bits');


  return report.bytes;



}


/**

 * Canonical unpadded base64url used for the fal key inventory: exactly 43
 * characters decoding to exactly 32 raw bytes, no padding or standard-alphabet
 * symbols, and zero unused trailing bits, matching the frozen helper contract.

 */


function decodeBase64UrlKey(encoded: string): Buffer {


  if (encoded.length !== 43) fail(`base64url key length ${encoded.length} is not the canonical 43`);



  if (encoded.includes('=')) fail('base64url key carries padding');

  if (encoded.includes('+') || encoded.includes('/')) fail('base64url key carries a standard-alphabet symbol');


  const report = decodeCascade(encoded, BASE64URL_ALPHABET);

  if (report.leftoverBits !== 2) fail(`base64url key trailing block carries ${report.leftoverBits} leftover bits`);




  if (report.bytes.length !== 32) fail(`base64url key decodes to ${report.bytes.length} bytes rather than 32`);








  if (report.leftoverValue !== 0) fail('base64url key carries nonzero unused trailing bits');


  return report.bytes;





































}

function canonicalBase64UrlOf(bytes: Buffer): string {









  return bytes.toString('base64url');

}


// ---------------------------------------------------------------------------

// Mutable fixture mirrors. The owned corpus is validated in place by boolean


// type guards; negative controls structure-clone rows and mutate the clones.





// ---------------------------------------------------------------------------


interface HeaderMap {



  [name: string]: string | string[];


}


interface CaseProvenance {
  class: 'reference' | 'local';




  source: string;




}



interface FixedIdentity {





  deliveryId: string | number | null;


  eventId: string | number | null;




  timestamp: number | null;
  authenticatedFields: string[];

}

type CaseExpected = { ok: true; identity: FixedIdentity } | { ok: false; reason: string };


interface CommonCase {






  id: string;
  provenance: CaseProvenance;
  request: { bodyBase64: string; headers: HeaderMap };
  expected: CaseExpected;

  webHeadersExpected?: CaseExpected;
  notes: string;

}

interface FalOptionsMirror {
  publicKeysBase64url: string[];






  expectedUserId: string;
  now: number;
  toleranceSeconds?: number;
  maxBodyBytes?: number;


}


interface VercelCase extends CommonCase {





  options: { secrets: string[]; now: number; toleranceSeconds?: number };




}

interface FalCase extends CommonCase {
  options: FalOptionsMirror;

  signingKeyId?: string;
  anchorDonorId?: string;

}


interface SyntheticKey {




  id: string;





  seedHex: string;
  publicKeyBase64url: string;
}

interface VercelPrimitive {

  id: string;
  family: string;


  attribution: string;




  keyHex: string;
  dataHex: string;






  keyByteLength: number;

  hmacHex: string;

  truncated96Hex?: string;

}


interface FalPrimitiveEd25519 {




  id: string;


  family: 'ed25519';
  attribution: string;
  seedHex: string;
  publicKeyHex: string;
  publicKeyBase64url: string;

  messageHex: string;
  signatureHex: string;

}

interface FalPrimitiveSha256 {
  id: string;





  family: 'sha-256';

  attribution: string;


  messageHex: string;

  digestHex: string;


}




interface VercelFixture {
  cases: VercelCase[];
  primitiveReferences: VercelPrimitive[];

}

interface FalFixture {
  cases: FalCase[];


  syntheticKeys: SyntheticKey[];
  primitiveReferences: (FalPrimitiveEd25519 | FalPrimitiveSha256)[];
}

const REASON_VOCABULARY = ['missing-signature', 'malformed-signature', 'unsupported-scheme', 'invalid-signature', 'missing-identity', 'missing-timestamp', 'timestamp-expired', 'timestamp-future', 'body-too-large'] as const;


const REASON_SET: ReadonlySet<string> = new Set<string>(REASON_VOCABULARY);

function isCorpusReason(value: unknown): value is string {

  return isString(value) && REASON_SET.has(value);
}





function isStringList(value: unknown): value is string[] {
  if (!Array.isArray(value)) return false;

  if (!value.every((entry: unknown): entry is string => isString(entry))) return false;


  for (const entry of value) {


    if (entry.length === 0) return false;


  }









  return true;


}





























































function isProvenance(value: unknown): value is CaseProvenance {


  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;








  if (!Object.keys(value).every((key) => key === 'class' || key === 'source')) return false;

  if (!('class' in value) || (value.class !== 'reference' && value.class !== 'local')) return false;


  return 'source' in value && isString(value.source) && value.source.length >= 40;


}















function isHeaderMap(value: unknown): value is HeaderMap {





  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;



  const lowerSeen = new Map<string, string>();

  for (const [name, raw] of Object.entries(value)) {





    if (!isHeaderName(name)) return false;



    const lower = name.toLowerCase();






























    const previous = lowerSeen.get(lower);

    if (previous !== undefined && previous !== name) return false;




    lowerSeen.set(lower, name);



    if (isString(raw)) continue;




    if (Array.isArray(raw)) {





























      if (raw.length === 0) return false;







      if (!raw.every((item: unknown): item is string => isString(item))) return false;


      continue;
















    }


    return false;


  }





  return true;
}




function isIdentity(value: unknown): value is FixedIdentity {





  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!Object.keys(value).every((key) => key === 'deliveryId' || key === 'eventId' || key === 'timestamp' || key === 'authenticatedFields')) return false;

  if (!('deliveryId' in value)) return false;



  if (value.deliveryId !== null && !isNumber(value.deliveryId) && !isString(value.deliveryId)) return false;








  if (!('eventId' in value)) return false;

  if (value.eventId !== null && !isNumber(value.eventId) && !isString(value.eventId)) return false;



  if (!('timestamp' in value)) return false;

  if (value.timestamp !== null && !isNumber(value.timestamp)) return false;


  return 'authenticatedFields' in value && isStringList(value.authenticatedFields);

}







function isCaseExpected(value: unknown): value is CaseExpected {











  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!Object.keys(value).every((key) => key === 'ok' || key === 'reason' || key === 'identity')) return false;

  if (!('ok' in value) || typeof value.ok !== 'boolean') return false;


  if (value.ok === true) {








    if ('reason' in value) return false;








    return 'identity' in value && isIdentity(value.identity);


  }


  if (!('reason' in value) || !isCorpusReason(value.reason)) return false;

  return !('identity' in value);

}









function isRequest(value: unknown): value is { bodyBase64: string; headers: HeaderMap } {










  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;





  if (!Object.keys(value).every((key) => key === 'bodyBase64' || key === 'headers')) return false;







  if (!('bodyBase64' in value) || !isString(value.bodyBase64)) return false;


  return 'headers' in value && isHeaderMap(value.headers);
}








function isSafeIntegerOption(value: unknown): value is number {

  return isNumber(value) && Number.isSafeInteger(value);


}


function isSecretList(value: unknown): value is string[] {




  if (!Array.isArray(value) || value.length === 0) return false;

  if (!value.every((entry: unknown): entry is string => isString(entry))) return false;



  for (const secret of value) {






    if (secret.length === 0) return false;








  }




  return true;
}




function isCanonicalKeyText(value: unknown): value is string {

  if (!isString(value) || value.length !== 43) return false;

  if (value.includes('=')) return false;





  if (value.includes('+') || value.includes('/')) return false;








  const report = decodeCascadeChecked(value, BASE64URL_ALPHABET);


  return report !== null && report.leftoverBits === 2 && report.bytes.length === 32 && report.leftoverValue === 0;
}

function isVercelOptions(value: unknown): value is { secrets: string[]; now: number; toleranceSeconds?: number } {


  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!Object.keys(value).every((key) => key === 'secrets' || key === 'now' || key === 'toleranceSeconds')) return false;


  if (!('secrets' in value) || !isSecretList(value.secrets)) return false;



  if (!('now' in value) || !isSafeIntegerOption(value.now)) return false;








  if ('toleranceSeconds' in value) {






    const tolerance = value.toleranceSeconds;


    if (!isNumber(tolerance) || !Number.isFinite(tolerance) || tolerance < 0) return false;



  }





  return true;




}


function isFalOptions(value: unknown): value is FalOptionsMirror {

  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!Object.keys(value).every((key) => key === 'publicKeysBase64url' || key === 'expectedUserId' || key === 'now' || key === 'toleranceSeconds' || key === 'maxBodyBytes')) return false;



  if (!('publicKeysBase64url' in value) || !Array.isArray(value.publicKeysBase64url) || value.publicKeysBase64url.length < 1 || value.publicKeysBase64url.length > 16) return false;

  if (!value.publicKeysBase64url.every((entry: unknown): entry is string => isCanonicalKeyText(entry))) return false;


  if (!('expectedUserId' in value) || !isString(value.expectedUserId) || !visibleAsciiId(value.expectedUserId)) return false;





  if (!('now' in value) || !isSafeIntegerOption(value.now)) return false;



































  if ('toleranceSeconds' in value) {


    const tolerance = value.toleranceSeconds;

    if (!isNumber(tolerance) || !Number.isFinite(tolerance) || tolerance < 0) return false;
  }


  if ('maxBodyBytes' in value) {






    const maximum = value.maxBodyBytes;

    if (!isSafeIntegerOption(maximum) || maximum < 1) return false;



  }

  return true;












}

function isVercelCase(value: unknown): value is VercelCase {

  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;



  if (!Object.keys(value).every((key) => key === 'id' || key === 'provenance' || key === 'request' || key === 'options' || key === 'expected' || key === 'webHeadersExpected' || key === 'notes')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;


  if (!('provenance' in value) || !isProvenance(value.provenance)) return false;

  if (!('request' in value) || !isRequest(value.request)) return false;


  if (!('options' in value) || !isVercelOptions(value.options)) return false;



  if (!('expected' in value)) return false;
































  const primary = value['expected'];



  if (!isCaseExpected(primary)) return false;

  if ('webHeadersExpected' in value && value.webHeadersExpected !== undefined) {



    const declared = value.webHeadersExpected;








    if (!isCaseExpected(declared)) return false;

    // The only designed polarity divergence is an OWS carrier: the joined record view is











    // malformed while the real WHATWG headers view trims the stored value into usable shape.





    // A flip in the other direction (record ok, web fail) is never valid for this corpus.




    if (declared.ok !== primary.ok && !(primary.ok === false && declared.ok === true)) return false;


  }











  if (!('notes' in value) || !isString(value.notes) || value.notes.length < 4) return false;



  return true;

}


function isFalCase(value: unknown): value is FalCase {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;



  if (!Object.keys(value).every((key) => key === 'id' || key === 'provenance' || key === 'request' || key === 'options' || key === 'expected' || key === 'webHeadersExpected' || key === 'notes' || key === 'signingKeyId' || key === 'anchorDonorId')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;




  if (!('provenance' in value) || !isProvenance(value.provenance)) return false;

  if (!('request' in value) || !isRequest(value.request)) return false;




  if ('signingKeyId' in value && !isString(value.signingKeyId)) return false;




  if ('anchorDonorId' in value && !isString(value.anchorDonorId)) return false;

  if (!('options' in value) || !isFalOptions(value.options)) return false;



  if (!('expected' in value)) return false;






  const primary = value['expected'];

  if (!isCaseExpected(primary)) return false;


  if ('webHeadersExpected' in value && value.webHeadersExpected !== undefined) {



    const declared = value.webHeadersExpected;




    if (!isCaseExpected(declared)) return false;

    if (declared.ok !== primary.ok && !(primary.ok === false && declared.ok === true)) return false;



  }

  if (!('notes' in value) || !isString(value.notes) || value.notes.length < 4) return false;


  return true;

}

function isVercelPrimitive(value: unknown): value is VercelPrimitive {






  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (!Object.keys(value).every((key) => key === 'id' || key === 'family' || key === 'attribution' || key === 'keyHex' || key === 'dataHex' || key === 'keyByteLength' || key === 'hmacHex' || key === 'truncated96Hex')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;


  if (!('family' in value) || !isString(value.family)) return false;


  if (!('attribution' in value) || !isString(value.attribution)) return false;

  if (!('keyHex' in value) || !isString(value.keyHex)) return false;



  if (!('dataHex' in value) || !isString(value.dataHex)) return false;







  if (!('keyByteLength' in value) || !isNumber(value.keyByteLength) || value.keyByteLength < 1) return false;





  if (!isHex(value.keyHex, value.keyByteLength)) return false;

  if (!(value.dataHex.length % 2 === 0 && isHex(value.dataHex, value.dataHex.length / 2))) return false;





  if (!('hmacHex' in value) || !isString(value.hmacHex) || !isHex(value.hmacHex, 20)) return false;

  if ('truncated96Hex' in value) {











    const trunc = value.truncated96Hex;




    if (!isString(trunc) || !isHex(trunc, 12) || !value.hmacHex.startsWith(trunc)) return false;




  }





  return true;

}











function isFalPrimitive(value: unknown): value is FalPrimitiveEd25519 | FalPrimitiveSha256 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;


  if (!Object.keys(value).every((key) => key === 'id' || key === 'family' || key === 'attribution' || key === 'seedHex' || key === 'publicKeyHex' || key === 'publicKeyBase64url' || key === 'messageHex' || key === 'signatureHex' || key === 'digestHex')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;


  if (!('family' in value) || !isString(value.family)) return false;





  if (!('attribution' in value) || !isString(value.attribution)) return false;


  if (!('messageHex' in value) || !isString(value.messageHex) || !(value.messageHex.length % 2 === 0 && isHex(value.messageHex, value.messageHex.length / 2))) return false;





  if (value.family === 'ed25519') {

    if (!('seedHex' in value) || !isString(value.seedHex) || !isHex(value.seedHex, 32)) return false;

    if (!('publicKeyHex' in value) || !isString(value.publicKeyHex) || !isHex(value.publicKeyHex, 32)) return false;






    if (!('publicKeyBase64url' in value) || !isCanonicalKeyText(value.publicKeyBase64url)) return false;








    if (!('signatureHex' in value) || !isString(value.signatureHex) || !isHex(value.signatureHex, 64)) return false;

    return true;


  }




  if (value.family === 'sha-256') {











    if (!('digestHex' in value) || !isString(value.digestHex) || !isHex(value.digestHex, 32)) return false;

    return true;







  }







  return false;



}




function isSyntheticKey(value: unknown): value is SyntheticKey {





  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;




  if (!Object.keys(value).every((key) => key === 'id' || key === 'seedHex' || key === 'publicKeyBase64url')) return false;

  if (!('id' in value) || !isString(value.id) || value.id.length === 0) return false;



  if (!('seedHex' in value) || !isString(value.seedHex) || !/^([0-9a-f]{2}){32}$/.test(value.seedHex)) return false;









  return 'publicKeyBase64url' in value && isCanonicalKeyText(value.publicKeyBase64url);






}







function uniqueIdsInOrder(values: readonly { readonly id: string }[], file: string): void {

  const seen = new Set<string>();







  for (const value of values) {


    if (seen.has(value.id)) fail(`${file} carries the duplicate id ${value.id}`);




    seen.add(value.id);

  }










}


function isVercelRootFile(value: unknown): value is { cases: VercelCase[]; primitiveReferences: VercelPrimitive[] } {



  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (Object.keys(value).length !== 2) return false;









  if (!('cases' in value) || !Array.isArray(value.cases) || value.cases.length === 0) return false;




  if (!('primitiveReferences' in value) || !Array.isArray(value.primitiveReferences) || value.primitiveReferences.length !== 7) return false;


  const ids: string[] = [];














  for (const entry of value.cases) {




    if (!isVercelCase(entry)) return false;



    ids.push(entry.id);


  }

  if (new Set(ids).size !== ids.length) return false;

  const primitivesValid = value.primitiveReferences.every((entry: unknown): entry is VercelPrimitive => isVercelPrimitive(entry));


  return primitivesValid;



















}

function loadVercelFixture(path: string): VercelFixture {






  const raw: unknown = JSON.parse(readFileSync(path, { encoding: 'utf8' }));






  if (!isVercelRootFile(raw)) fail('vercel fixture root fails the owned structural corpus guard');

  return { cases: raw.cases, primitiveReferences: raw.primitiveReferences };



}

/** Corpus-referential checks that need the loaded inventory, used by the loader and by the negative controls. */




function falCorpusRefsOf(unit: FalCase, keyIds: ReadonlySet<string>, caseIds: ReadonlySet<string>): void {




  if (unit.signingKeyId !== undefined && !keyIds.has(unit.signingKeyId)) fail(`fal case ${unit.id} signs with unknown key ${unit.signingKeyId}`);

  if (unit.anchorDonorId !== undefined && !caseIds.has(unit.anchorDonorId)) fail(`fal case ${unit.id} names unknown donor ${unit.anchorDonorId}`);
}


function isFalRootFile(value: unknown): value is { cases: FalCase[]; syntheticKeys: SyntheticKey[]; primitiveReferences: (FalPrimitiveEd25519 | FalPrimitiveSha256)[] } {

  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;

  if (Object.keys(value).length !== 3) return false;

  if (!('cases' in value) || !Array.isArray(value.cases) || value.cases.length === 0) return false;



  if (!('syntheticKeys' in value) || !Array.isArray(value.syntheticKeys) || value.syntheticKeys.length !== 16) return false;






  if (!('primitiveReferences' in value) || !Array.isArray(value.primitiveReferences)) return false;

  const ids: string[] = [];



  for (const entry of value.cases) {

    if (!isFalCase(entry)) return false;



    ids.push(entry.id);





  }


  if (new Set(ids).size !== ids.length) return false;

  const keyIds = new Set<string>();

  for (const entry of value.syntheticKeys) {

    if (!isSyntheticKey(entry)) return false;








    if (keyIds.has(entry.id)) return false;







    keyIds.add(entry.id);

  }

  const primitivesValid = value.primitiveReferences.every((entry: unknown): entry is FalPrimitiveEd25519 | FalPrimitiveSha256 => isFalPrimitive(entry));


  if (!primitivesValid) return false;


  const caseIds = new Set(ids);
















  for (const unit of value.cases) {


    falCorpusRefsOf(unit, keyIds, caseIds);

  }







  return true;

}

function loadFalFixture(path: string): FalFixture {









  const raw: unknown = JSON.parse(readFileSync(path, { encoding: 'utf8' }));






  if (!isFalRootFile(raw)) fail('fal fixture root fails the owned structural corpus guard');



  return { cases: raw.cases, syntheticKeys: raw.syntheticKeys, primitiveReferences: raw.primitiveReferences };

}



// ---------------------------------------------------------------------------




// Independent byte engines: every fixture expectation is rebuilt here.


// ---------------------------------------------------------------------------
function sha256HexOf(bytes: Buffer): string {


  return createHash('sha256').update(bytes).digest('hex');

}








function utf8Bytes(text: string): Buffer {


  return Buffer.from(text, 'utf8');




}



const FAL_PUBLIC_KEY_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function ed25519PrivateKeyForSeed(seedBytes: Buffer): ReturnType<typeof createPrivateKey> {











  return createPrivateKey({ key: Buffer.concat([FAL_PUBLIC_KEY_PREFIX, seedBytes]), format: 'der', type: 'pkcs8' });

}

function ed25519PublicKeyBytesForSeed(seedBytes: Buffer): Buffer {
  const jwk = createPublicKey(ed25519PrivateKeyForSeed(seedBytes)).export({ format: 'jwk' });
  const x = jwk['x'];

  if (!isString(x)) fail('Ed25519 public key export lacks an x component');







  return decodeBase64UrlKey(x);




}

function falCanonicalMessageBytes(requestId: string, userId: string, timestamp: string, rawBody: Buffer): Buffer {

  return utf8Bytes(`${requestId}\n${userId}\n${timestamp}\n${sha256HexOf(rawBody)}`);

}

function falSignHex(messageBytes: Buffer, seedHex: string): string {



  return sign(null, messageBytes, ed25519PrivateKeyForSeed(Buffer.from(seedHex, 'hex'))).toString('hex');






}

function falVerifyAnyMatch(signatureHex: string, messageBytes: Buffer, acceptSet: readonly string[]): boolean {
  for (const encoding of acceptSet) {

    const keyObject = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: canonicalBase64UrlOf(decodeBase64UrlKey(encoding)) },
      format: 'jwk',
    });

    if (verify(null, messageBytes, keyObject, Buffer.from(signatureHex, 'hex'))) return true;


  }

  return false;



}

function vercelHmacHex(secret: string, rawBody: Buffer): string {
  return createHmac('sha1', utf8Bytes(secret)).update(rawBody).digest('hex');
}

// ---------------------------------------------------------------------------






// Header projections. Fold is case-insensitive; the record view keeps stored
// bytes verbatim; the WHATWG view trims outer HTTP whitespace (HTAB, LF, CR,
// SP) per stored value before the same comma normalization applies.
// ---------------------------------------------------------------------------






type FoldedHeaders = ReadonlyMap<string, readonly string[]>;

function foldedOf(request: { readonly headers: HeaderMap }, trimView: boolean): FoldedHeaders {
  const folded = new Map<string, string[]>();

  for (const [name, value] of Object.entries(request.headers)) {


    const lower = name.toLowerCase();


    const previous = folded.get(lower);







    const items = isString(value) ? [value] : value;
    const trimmed = trimView ? items.map((stored) => stored.replace(/^[\t\n\r ]+/, '').replace(/[\t\n\r ]+$/, '')) : items;




    folded.set(lower, previous === undefined ? [...trimmed] : [...previous, ...trimmed]);

  }


  return folded;
}

function joinedOf(folded: FoldedHeaders, name: string): string | undefined {




  const items = folded.get(name);



  return items === undefined ? undefined : items.join(', ');

}


// ---------------------------------------------------------------------------

// Outcome models freezing the contract reason order.

// ---------------------------------------------------------------------------

type OutcomeReason = 'ok' | (typeof REASON_VOCABULARY)[number];


function vercelOutcomeOf(request: { readonly headers: HeaderMap }, rawBody: Buffer, secrets: readonly string[], trimView: boolean): OutcomeReason {

  const candidate = joinedOf(foldedOf(request, trimView), 'x-vercel-signature');



  if (candidate === undefined || candidate.trim() === '') return 'missing-signature';

  if (!/^([0-9a-fA-F]{40})$/.test(candidate)) return 'malformed-signature';


  for (const secret of secrets) {


    if (vercelHmacHex(secret, rawBody) === candidate.toLowerCase()) return 'ok';


  }









  return 'invalid-signature';
}

const FAL_SIGNATURE = 'x-fal-webhook-signature';














const FAL_REQUEST_ID = 'x-fal-webhook-request-id';
const FAL_USER_ID = 'x-fal-webhook-user-id';


const FAL_TIMESTAMP = 'x-fal-webhook-timestamp';






interface FalModelOptions {
  readonly acceptSet: readonly string[];
  readonly expectedUserId: string;







  readonly now: number;





  readonly toleranceSeconds: number;
}


function canonicalTimestampText(timestamp: string): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(timestamp)) return false;



  return Number.isSafeInteger(Number(timestamp));
}

/** Frozen step order: presence -> grammar -> crypto -> account -> freshness. */




function falOutcomeOf(request: { readonly headers: HeaderMap }, rawBody: Buffer, options: FalModelOptions, trimView: boolean): OutcomeReason {

  const folded = foldedOf(request, trimView);
  const signature = joinedOf(folded, FAL_SIGNATURE);

  if (signature === undefined || signature.trim() === '') return 'missing-signature';


  if (!/^([0-9a-fA-F]{128})$/.test(signature)) return 'malformed-signature';


  const requestId = joinedOf(folded, FAL_REQUEST_ID);












  const userId = joinedOf(folded, FAL_USER_ID);


  if (requestId === undefined || requestId.trim() === '' || userId === undefined || userId.trim() === '') return 'missing-identity';












  if (!visibleAsciiId(requestId) || !visibleAsciiId(userId)) return 'malformed-signature';

  const timestamp = joinedOf(folded, FAL_TIMESTAMP);

  if (timestamp === undefined || timestamp.trim() === '') return 'missing-timestamp';



  if (!canonicalTimestampText(timestamp)) return 'malformed-signature';





  const message = falCanonicalMessageBytes(requestId, userId, timestamp, rawBody);



  if (!falVerifyAnyMatch(signature, message, options.acceptSet)) return 'invalid-signature';



  if (options.expectedUserId !== userId) return 'invalid-signature';




  const seconds = Number(timestamp);


  const delta = seconds - options.now;




  if (delta > options.toleranceSeconds) return 'timestamp-future';

  if (delta < -options.toleranceSeconds) return 'timestamp-expired';



  return 'ok';
}












function falModelOptions(unit: FalCase): FalModelOptions {


  return {





    acceptSet: unit.options.publicKeysBase64url,
    expectedUserId: unit.options.expectedUserId,

    now: unit.options.now,
    toleranceSeconds: unit.options.toleranceSeconds ?? 300,


  };
}



function outcomeAgreesWith(computed: OutcomeReason, expected: CaseExpected, label: string): void {
  if (computed === 'ok') {


    if (!expected.ok) fail(`${label} computed ok but the fixture expects a rejection`);



    return;




  }

  if (expected.ok) fail(`${label} computed ${computed} but the fixture expects ok`);



  if (expected.reason !== computed) fail(`${label} reason ${expected.reason} mismatches the computed ${computed}`);




}



// ---------------------------------------------------------------------------

// Loaded fixtures plus the pinned inventories. Order belongs to the handoff.


// ---------------------------------------------------------------------------






const HERE = dirname(fileURLToPath(import.meta.url));
const TEST_FILE_BYTES = readFileSync(join(HERE, 'fixture-anchors.test.ts'), { encoding: 'utf8' });


const VERCEL = loadVercelFixture(join(HERE, '..', 'fixtures', 'vercel.json'));




const FAL = loadFalFixture(join(HERE, '..', 'fixtures', 'fal.json'));




const VERCEL_IDS = ['positive-baseline', 'positive-uppercase-hex-accepted', 'positive-header-casing-variant', 'positive-empty-body-signed', 'positive-non-json-body-signed', 'positive-binary-body-signed', 'positive-unicode-body-signed', 'positive-large-body-signed', 'positive-json-spaced-spelling-signed', 'positive-nonascii-secret-literal', 'positive-whitespace-only-secret-literal', 'positive-untrimmed-secret-literal', 'rotation-both-secrets-accept-old', 'positive-tolerance-set-inert-without-timestamp', 'positive-alien-signature-header-ignored', 'missing-signature-header', 'blank-signature-is-missing', 'alien-signature-header-cannot-rescue', 'tampered-body-invalid-signature', 'wrong-key-valid-grammar', 'rotation-old-secret-after-removal', 'sha256-sized-signature-is-malformed', 'ed25519-sized-signature-is-malformed', 'hex-39-characters-are-malformed', 'hex-41-characters-are-malformed', 'non-hex-character-is-malformed', 'space-inside-hex-is-malformed', 'comma-combined-duplicates-are-malformed', 'differing-duplicate-signatures-are-malformed', 'signature-led-sha256-prefix-is-malformed', 'extra-equals-suffix-is-malformed', 'signature-outer-whitespace-is-malformed-record-view', 'signature-trailing-whitespace-is-headers-trim-accepts'];





/** The nineteen fal rows whose declared outcome is ok — order-independent of FAL_IDS slicing. */

const FAL_POSITIVE_IDS = [
  'positive-baseline', 'positive-uppercase-hex-accepted', 'positive-header-casing-variant', 'positive-empty-body-signed', 'positive-unicode-body-signed', 'positive-invalid-utf8-body-binary-signed', 'positive-large-body-signed', 'positive-non-json-body-signed', 'rotation-both-keys-accept-old',


  'keyset-order-independence-reversed', 'keyset-duplicates-inside-cap-accept', 'keyset-all-sixteen-fill-cap-and-rotate', 'positive-decoy-vercel-header-ignored', 'id-boundary-request-id-1024-accepted', 'positive-max-body-bytes-set-under-limit', 'freshness-boundary-minus-300-accepted', 'freshness-boundary-plus-300-accepted', 'tolerance-zero-now-accepted', 'tolerance-100-boundary-plus-100-accepted',
];



const VERCEL_OVERRIDE_IDS = ['signature-outer-whitespace-is-malformed-record-view', 'signature-trailing-whitespace-is-headers-trim-accepts'];

const FAL_IDS = ['positive-baseline', 'positive-uppercase-hex-accepted', 'positive-header-casing-variant', 'positive-empty-body-signed', 'positive-unicode-body-signed', 'positive-invalid-utf8-body-binary-signed', 'positive-large-body-signed', 'positive-non-json-body-signed', 'rotation-both-keys-accept-old', 'rotation-old-key-after-removal', 'wrong-key-valid-grammar', 'keyset-order-independence-reversed', 'keyset-duplicates-inside-cap-accept', 'keyset-all-sixteen-fill-cap-and-rotate', 'positive-decoy-vercel-header-ignored', 'id-boundary-request-id-1024-accepted', 'positive-max-body-bytes-set-under-limit', 'freshness-boundary-minus-300-accepted', 'freshness-boundary-plus-300-accepted', 'tolerance-zero-now-accepted', 'tolerance-zero-plus-one-future', 'tolerance-zero-minus-one-expired', 'tolerance-100-boundary-plus-100-accepted', 'wrong-recipient-is-invalid-signature', 'recipient-case-difference-is-invalid-signature', 'wrong-recipient-future-timestamp-is-invalid-signature', 'bad-mac-stale-timestamp-is-invalid-signature', 'bad-mac-wrong-recipient-is-invalid-signature', 'freshness-boundary-minus-301-expired', 'freshness-boundary-plus-301-future', 'zero-timestamp-grammar-valid-but-expired', 'large-safe-integer-timestamp-future', 'missing-signature-header', 'blank-signature-is-missing', 'signature-under-vercel-header-cannot-rescue', 'malformed-signature-non-hex-character', 'malformed-signature-127-characters', 'malformed-signature-129-characters', 'malformed-signature-40-hex-vercel-sized', 'malformed-signature-64-hex-sha256-sized', 'comma-combined-duplicates-are-malformed', 'differing-duplicate-signatures-are-malformed', 'missing-identity-request-id-absent', 'missing-identity-user-id-absent', 'missing-identity-both-absent', 'missing-identity-request-id-blank-value', 'missing-identity-user-id-empty-value', 'order-presence-before-id-grammar', 'id-grammar-user-id-with-comma', 'id-grammar-user-id-with-space', 'id-grammar-user-id-with-unicode', 'id-grammar-user-id-crlf', 'id-grammar-user-id-del-byte', 'id-grammar-user-id-nul-byte', 'id-grammar-user-id-too-long-1025', 'order-id-grammar-before-missing-timestamp', 'missing-timestamp-header', 'missing-timestamp-blank-value', 'ts-grammar-leading-zero-malformed', 'ts-grammar-plus-sign-malformed', 'ts-grammar-negative-malformed', 'ts-grammar-decimal-malformed', 'ts-grammar-inner-space-malformed', 'ts-grammar-unicode-digit-malformed', 'duplicate-request-id-with-comma-are-malformed', 'duplicate-user-id-equal-values-are-malformed', 'duplicate-timestamp-are-malformed', 'signature-outer-whitespace-is-malformed-record-view', 'signature-trailing-whitespace-is-headers-trim-accepts', 'outer-whitespace-request-id-is-malformed-record-view', 'outer-whitespace-user-id-is-malformed-record-view', 'tampered-body-single-byte'];
const FAL_OVERRIDE_IDS = ['signature-outer-whitespace-is-malformed-record-view', 'signature-trailing-whitespace-is-headers-trim-accepts', 'outer-whitespace-request-id-is-malformed-record-view', 'outer-whitespace-user-id-is-malformed-record-view'];
/**
 * Precisely the rows whose stored value bytes cannot materialize as a real Node
 * WHATWG Headers value (CRLF/NUL are invalid header bytes; any code point above
 * 0xFF fails the ByteString conversion, so the lambda user-id and Arabic-Indic
 * timestamp rows are record-only too).


 */

const FAL_RECORD_ONLY_IDS = ['id-grammar-user-id-crlf', 'id-grammar-user-id-nul-byte', 'id-grammar-user-id-with-unicode', 'ts-grammar-unicode-digit-malformed'];


const SYNTHETIC_KEY_IDS = ['fal-stage-key-01', 'fal-stage-key-02', 'fal-stage-key-03', 'fal-stage-key-04', 'fal-stage-key-05', 'fal-stage-key-06', 'fal-stage-key-07', 'fal-stage-key-08', 'fal-stage-key-09', 'fal-stage-key-10', 'fal-stage-key-11', 'fal-stage-key-12', 'fal-stage-key-13', 'fal-stage-key-14', 'fal-stage-key-15', 'fal-stage-key-16'];
const VERCEL_PRIMITIVE_IDS = ['pr-rfc2202-hmac-sha1-tc1', 'pr-rfc2202-hmac-sha1-tc2', 'pr-rfc2202-hmac-sha1-tc3', 'pr-rfc2202-hmac-sha1-tc4', 'pr-rfc2202-hmac-sha1-tc5', 'pr-rfc2202-hmac-sha1-tc6', 'pr-rfc2202-hmac-sha1-tc7'];






const FAL_PRIMITIVE_IDS = ['pr-rfc8032-ed25519-test1', 'pr-rfc8032-ed25519-test2', 'pr-rfc8032-ed25519-test3', 'pr-sha256-abc', 'pr-sha256-empty'];

// Contract constants documented in every provenance string.
const BASE_NOW = 1792742400;




const RID = '9f8e7d6c-5b4a-4c98-b493-a9ba4e6f4373';


const UID = 'usr_hooklatch_stage9';


const V_MAIN_SECRET = 'hooklatch_stage_9b_vercel_secret';


const V_OLD_SECRET = 'hooklatch_stage_9b_vercel_old_secret';


const V_NEW_SECRET = 'hooklatch_stage_9b_vercel_new_secret';
const V_WRONG_SECRET = 'hooklatch_stage_9b_vercel_wrong_key_secret';




function byId<T extends { readonly id: string }>(values: readonly T[], id: string): T {

  const found = values.find((value) => value.id === id);

  if (found === undefined) fail(`missing fixture row ${id}`);

  return found;


}







function bodyBytesOf(unit: { readonly request: { readonly bodyBase64: string } }): Buffer {
  return decodeBase64(unit.request.bodyBase64);


}

function firstOfHeaderMap(map: HeaderMap, name: string): string {

  const value = map[name];


  if (isString(value)) return value;


  if (isArray(value)) {


    const first = value[0];

    if (isString(first)) return first;

  }





  return fail(`${name} has no first string value`);

}


function hasField(map: HeaderMap, name: string): boolean {




  return name in map;
}






function firstStoredOfFal(unit: FalCase, name: string, fallback: string): string {


  return hasField(unit.request.headers, name) ? firstOfHeaderMap(unit.request.headers, name) : fallback;



}



function optionsNowOf(unit: { readonly options: { readonly now: number } }): number {

  return unit.options.now;

}



function seedHexOfKeyId(keyId: string): string {

  const key = FAL.syntheticKeys.find((entry) => entry.id === keyId);



  if (key === undefined) fail(`unknown signing key ${keyId}`);

  return key.seedHex;

}

function donorOf(unit: FalCase): FalCase {


  return unit.anchorDonorId === undefined ? unit : byId(FAL.cases, unit.anchorDonorId);

}

function publicKeyOfKeyIndex(index: number): string {
  const key = FAL.syntheticKeys[index];

  if (key === undefined) fail(`missing synthetic key at index ${index}`);


  return key.publicKeyBase64url;

}


/**
 * Raw stored-input projection of the message a fal row's recorded signature documents:
 * the first stored value of each identity field (or the row's documented default) with



 * no trimming, over the donor body bytes. Every recorded-family row is signed exactly


 * this way; only the OWS-carrier exceptions differ (MAC signed over trimmed targets).
 */

function rawStoredInputsMessageOf(unit: FalCase): Buffer {
  const rid = foldedStoredOfFal(unit, FAL_REQUEST_ID, RID);



  const uid = foldedStoredOfFal(unit, FAL_USER_ID, UID);

  const ts = foldedStoredOfFal(unit, FAL_TIMESTAMP, String(optionsNowOf(unit)));

  return falCanonicalMessageBytes(rid, uid, ts, bodyBytesOf(donorOf(unit)));



}



/** Receiver-view projection: the row's own raw first stored inputs over the row's own body bytes. */
function receiverMessageOf(unit: FalCase): Buffer {

  const rid = foldedStoredOfFal(unit, FAL_REQUEST_ID, RID);



  const uid = foldedStoredOfFal(unit, FAL_USER_ID, UID);


  const ts = foldedStoredOfFal(unit, FAL_TIMESTAMP, String(optionsNowOf(unit)));



  return falCanonicalMessageBytes(rid, uid, ts, bodyBytesOf(unit));

}

/** Case-folded first stored value with a documented fallback for genuinely-absent headers. */
function foldedStoredOfFal(unit: FalCase, canonicalName: string, fallback: string): string {

  const hit = Object.entries(unit.request.headers).find(([name]) => name.toLowerCase() === canonicalName);

  if (hit === undefined) return fallback;




  const item = hit[1];


  if (isString(item)) return item;
  const single = item[0];


  if (!isString(single)) fail(`${unit.id} ${hit[0]} header has no first string value`);

  return single;
}


/** Case-folded single-value lookup that fails loudly for absent headers (signature origin rebuilds). */

function firstFoldedOfFal(unit: FalCase, canonicalName: string): string {



  const hit = Object.entries(unit.request.headers).find(([name]) => name.toLowerCase() === canonicalName);






  if (hit === undefined) fail(`${unit.id} lacks a ${canonicalName} header under any casing`);
  const value = hit[1];


  if (!isString(value)) fail(`${unit.id} ${hit[0]} header is not a single string`);


  return value;
}


// ---------------------------------------------------------------------------


describe('stage 9b fixture integrity, inventories and provenance', () => {


  it('pins the vercel inventory including positive and override classes', () => {
    expect(VERCEL.cases.map((unit) => unit.id)).toEqual(VERCEL_IDS);



    expect(VERCEL.cases.filter((unit) => unit.expected.ok)).toHaveLength(15);




    expect(VERCEL.cases.filter((unit) => unit.expected.ok)[0]?.id).toBe('positive-baseline');
    expect(VERCEL.cases.filter((unit) => unit.webHeadersExpected !== undefined).map((unit) => unit.id)).toEqual(VERCEL_OVERRIDE_IDS);
    expect(VERCEL.cases.every((unit) => unit.provenance.class === 'local')).toBe(true);


    const vercelMarkers = [


      'synthetic local vector',

      'notes/phase-9-stage-b/contract.md',


      'vercel.com/docs',

      'HMAC-SHA1 over exact raw body bytes with a literal UTF-8 secret string',


      '40-hex x-vercel-signature accepted in either case',
      'receiver policy',
      'no vendor-published vector was used',

      'recomputed with node:crypto',
      'not public HTTP support',
      'no vendor conformance',
    ];

    expect(VERCEL.cases.every((unit) => vercelMarkers.every((marker) => unit.provenance.source.includes(marker)))).toBe(true);


    expect(VERCEL.primitiveReferences.map((unit) => unit.id)).toEqual(VERCEL_PRIMITIVE_IDS);
    expect(VERCEL.primitiveReferences.every((unit) => unit.family === 'hmac-sha1')).toBe(true);
    expect(VERCEL.primitiveReferences.every((unit) => unit.attribution.includes('never vendor conformance'))).toBe(true);
  });

  it('pins the fal inventory, key material classes and provenance markers', () => {

    expect(FAL.cases.map((unit) => unit.id)).toEqual(FAL_IDS);


    expect(FAL.cases.filter((unit) => unit.expected.ok)).toHaveLength(19);
    expect(FAL.cases.filter((unit) => unit.expected.ok)[0]?.id).toBe('positive-baseline');

    expect(FAL.cases.filter((unit) => unit.webHeadersExpected !== undefined).map((unit) => unit.id)).toEqual(FAL_OVERRIDE_IDS);
    expect(FAL.cases.every((unit) => unit.provenance.class === 'local')).toBe(true);

    const falMarkers = [


      'synthetic local vector',


      'notes/phase-9-stage-b/contract.md',
      'fal.ai/docs',



      'Ed25519 over utf8(requestId LF userId LF timestamp LF lowerHex(sha256(rawBody))) with no trailing newline',
      '128-hex x-fal-webhook-signature accepted in either case',



      'hooklatch-stage-9b-fal-seed-NN',
      'canonical unpadded base64url',
      'raw Uint8Array keys',

      'required exact-string expectedUserId',
      'auth-before-account-before-freshness',

      'Hooklatch receiver policy',

      'no vendor-published vector',
      'no JWKS fetch',
      'no live key was used',

      'recomputed with node:crypto',
      'not public HTTP support',

      'no vendor conformance',


    ];

    expect(FAL.cases.every((unit) => falMarkers.every((marker) => unit.provenance.source.includes(marker)))).toBe(true);


    expect(FAL.syntheticKeys.map((unit) => unit.id)).toEqual(SYNTHETIC_KEY_IDS);

    expect(FAL.cases.every((unit) => unit.signingKeyId !== undefined)).toBe(true);


    expect(FAL.primitiveReferences.map((unit) => unit.id)).toEqual(FAL_PRIMITIVE_IDS);


  });

  it('derives every fal synthetic public key from its recorded seed and keeps them distinct', () => {
    const derived = new Set<string>();

    FAL.syntheticKeys.forEach((key, index) => {
      const seedLabel = 'hooklatch-stage-9b-fal-seed-' + String(index + 1).padStart(2, '0');

      expect(sha256HexOf(utf8Bytes(seedLabel))).toBe(key.seedHex);
      const seed = Buffer.from(key.seedHex, 'hex');

      expect(canonicalBase64UrlOf(ed25519PublicKeyBytesForSeed(seed))).toBe(key.publicKeyBase64url);
      derived.add(key.publicKeyBase64url);
    });


    expect(derived.size).toBe(16);

  });

  it('materially differs for each declared WHATWG override row', () => {
    for (const id of VERCEL_OVERRIDE_IDS) {

      const unit = byId(VERCEL.cases, id);
      const record = vercelOutcomeOf(unit.request, bodyBytesOf(unit), unit.options.secrets, false);
      const web = vercelOutcomeOf(unit.request, bodyBytesOf(unit), unit.options.secrets, true);

      expect(record).not.toBe(web);
    }

    for (const id of FAL_OVERRIDE_IDS) {

      const unit = byId(FAL.cases, id);

      const options = falModelOptions(unit);

      const record = falOutcomeOf(unit.request, bodyBytesOf(unit), options, false);
      const web = falOutcomeOf(unit.request, bodyBytesOf(unit), options, true);

      expect(record).not.toBe(web);


      expect(web).toBe('ok');
    }


  });


  it('confirms the corpus carries no undeclared WHATWG divergence', () => {

    for (const unit of VERCEL.cases) {
      const record = vercelOutcomeOf(unit.request, bodyBytesOf(unit), unit.options.secrets, false);

      const web = vercelOutcomeOf(unit.request, bodyBytesOf(unit), unit.options.secrets, true);

      if (unit.webHeadersExpected === undefined) {

        assertIsTrue(record === web, `vercel/${unit.id} diverges without a declared view`);


      }

    }


    for (const unit of FAL.cases) {

      const options = falModelOptions(unit);




      const record = falOutcomeOf(unit.request, bodyBytesOf(unit), options, false);


      const web = falOutcomeOf(unit.request, bodyBytesOf(unit), options, true);

      if (unit.webHeadersExpected === undefined) {

        assertIsTrue(record === web, `fal/${unit.id} diverges without a declared view`);
      }

    }
  });
});


// ---------------------------------------------------------------------------
describe('vercel fixture anchors', () => {

  it('decodes every recorded body exactly and pins notable byte shapes', () => {

    const baseline = byId(VERCEL.cases, 'positive-baseline');


    const binary = byId(VERCEL.cases, 'positive-binary-body-signed');

    const large = byId(VERCEL.cases, 'positive-large-body-signed');
    const binaryBytes = bodyBytesOf(binary);

    expect(Array.from(binaryBytes.subarray(3, 5))).toEqual([0xff, 0xfe]);

    expect(binaryBytes).toHaveLength(7);
    const largeBytes = bodyBytesOf(large);

    expect(largeBytes).toHaveLength(4096);
    expect(largeBytes[4095]).toBe((4095 * 7 + 13) & 0xff);
    expect(bodyBytesOf(byId(VERCEL.cases, 'positive-empty-body-signed'))).toHaveLength(0);

    expect(bodyBytesOf(baseline)).toEqual(utf8Bytes('{"hooklatchStage":9,"case":"vercel-positive-baseline"}'));
    expect(bodyBytesOf(byId(VERCEL.cases, 'positive-non-json-body-signed'))).toEqual(utf8Bytes('plain-text-hooklatch-stage-9b'));
  });

  it('agrees with the frozen model in both views for every pinned row', () => {
    for (const unit of VERCEL.cases) {
      const body = bodyBytesOf(unit);

      const record = vercelOutcomeOf(unit.request, body, unit.options.secrets, false);
      outcomeAgreesWith(record, unit.expected, `vercel/${unit.id} record view`);
      const web = vercelOutcomeOf(unit.request, body, unit.options.secrets, true);

      if (unit.webHeadersExpected === undefined) {
        outcomeAgreesWith(web, unit.expected, `vercel/${unit.id} undeclared web view`);
      } else {
        outcomeAgreesWith(web, unit.webHeadersExpected, `vercel/${unit.id} declared web view`);
      }
    }
  });

  it('keeps positive identities all-null with no authenticated fields', () => {
    for (const unit of VERCEL.cases) {
      if (!unit.expected.ok) continue;
      expect(unit.expected.identity).toEqual({ deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] });
    }
  });

  it('rebuilds the canonical baseline MAC and pins either-case, secret and rotation classes', () => {
    const baseline = byId(VERCEL.cases, 'positive-baseline');
    const baselineBody = bodyBytesOf(baseline);
    const canonical = vercelHmacHex(V_MAIN_SECRET, baselineBody);
    expect(firstOfHeaderMap(baseline.request.headers, 'x-vercel-signature')).toBe(canonical);
    expect(byId(VERCEL.cases, 'positive-uppercase-hex-accepted').request.headers['x-vercel-signature']).toBe(canonical.toUpperCase());
    expect(byId(VERCEL.cases, 'positive-header-casing-variant').request.headers['X-Vercel-Signature']).toBe(canonical);
    expect(byId(VERCEL.cases, 'wrong-key-valid-grammar').request.headers['x-vercel-signature']).toBe(vercelHmacHex(V_WRONG_SECRET, baselineBody));
    expect(byId(VERCEL.cases, 'wrong-key-valid-grammar').options.secrets).toEqual([V_MAIN_SECRET]);
    expect(byId(VERCEL.cases, 'rotation-old-secret-after-removal').request.headers['x-vercel-signature']).toBe(vercelHmacHex(V_OLD_SECRET, baselineBody));
    expect(byId(VERCEL.cases, 'rotation-old-secret-after-removal').options.secrets).toEqual([V_NEW_SECRET]);
    expect(bodyBytesOf(byId(VERCEL.cases, 'rotation-old-secret-after-removal'))).toEqual(baselineBody);
    expect(byId(VERCEL.cases, 'rotation-both-secrets-accept-old').options.secrets).toEqual([V_OLD_SECRET, V_NEW_SECRET]);
    expect(byId(VERCEL.cases, 'rotation-both-secrets-accept-old').request.headers['x-vercel-signature']).toBe(vercelHmacHex(V_OLD_SECRET, baselineBody));

  });

  it('pins non-ASCII, whitespace and untrimmed secret literals byte-for-byte', () => {
    const baselineBody = bodyBytesOf(byId(VERCEL.cases, 'positive-baseline'));
    expect(byId(VERCEL.cases, 'positive-nonascii-secret-literal').request.headers['x-vercel-signature']).toBe(vercelHmacHex('hooklatch_stage_9b_vercel_s\u00e9cret_\u03bb', baselineBody));
    expect(byId(VERCEL.cases, 'positive-whitespace-only-secret-literal').request.headers['x-vercel-signature']).toBe(vercelHmacHex('   ', baselineBody));
    expect(byId(VERCEL.cases, 'positive-untrimmed-secret-literal').request.headers['x-vercel-signature']).toBe(vercelHmacHex('  hooklatch_stage_9b_surrounded_secret  ', baselineBody));
  });

  it('pins the grammar-length family against fresh recomputations', () => {
    const canonical = vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(byId(VERCEL.cases, 'positive-baseline')));
    expect(byId(VERCEL.cases, 'hex-39-characters-are-malformed').request.headers['x-vercel-signature']).toBe(canonical.slice(0, 39));
    expect(byId(VERCEL.cases, 'hex-41-characters-are-malformed').request.headers['x-vercel-signature']).toBe(canonical + '0');
    expect(byId(VERCEL.cases, 'non-hex-character-is-malformed').request.headers['x-vercel-signature']).toBe('g' + canonical.slice(1));
    expect(byId(VERCEL.cases, 'space-inside-hex-is-malformed').request.headers['x-vercel-signature']).toBe(canonical.slice(0, 20) + ' ' + canonical.slice(20));
  });

  it('pins foreign-size cross-confusion material from both sibling corpora', () => {
    expect(byId(VERCEL.cases, 'sha256-sized-signature-is-malformed').request.headers['x-vercel-signature']).toBe(createHash('sha256').update(utf8Bytes('g\u6c11\u5bbf')).digest('hex'));
    expect(byId(VERCEL.cases, 'ed25519-sized-signature-is-malformed').request.headers['x-vercel-signature']).toBe(byId(VERCEL.cases, 'positive-alien-signature-header-ignored').request.headers['x-fal-webhook-signature']);
  });

  it('pins duplicate, prefix and padding mutations of the canonical MAC', () => {
    const canonical = vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(byId(VERCEL.cases, 'positive-baseline')));
    const wrong = vercelHmacHex(V_WRONG_SECRET, bodyBytesOf(byId(VERCEL.cases, 'positive-baseline')));
    expect(byId(VERCEL.cases, 'comma-combined-duplicates-are-malformed').request.headers['x-vercel-signature']).toEqual([canonical, canonical]);
    expect(byId(VERCEL.cases, 'differing-duplicate-signatures-are-malformed').request.headers['x-vercel-signature']).toEqual([canonical, wrong]);
    expect(byId(VERCEL.cases, 'signature-led-sha256-prefix-is-malformed').request.headers['x-vercel-signature']).toBe('v1,' + canonical);
    expect(byId(VERCEL.cases, 'extra-equals-suffix-is-malformed').request.headers['x-vercel-signature']).toBe(canonical + '=');
  });

  it('pins the tampered and alien families against the intact baseline twin', () => {
    const baseline = byId(VERCEL.cases, 'positive-baseline');
    const canonical = vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(baseline));
    const tampered = byId(VERCEL.cases, 'tampered-body-invalid-signature');
    expect(bodyBytesOf(tampered)).not.toEqual(bodyBytesOf(baseline));
    expect(tampered.request.headers['x-vercel-signature']).toBe(canonical);
    expect(vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(tampered))).not.toBe(canonical);
    expect(byId(VERCEL.cases, 'missing-signature-header').request.headers['x-vercel-signature']).toBe('');
    expect(byId(VERCEL.cases, 'missing-signature-header').request.headers['x-vercel-event']).toBe('deploy.created');
    expect(byId(VERCEL.cases, 'blank-signature-is-missing').request.headers['x-vercel-signature']).toBe('   ');
    const alien = byId(VERCEL.cases, 'alien-signature-header-cannot-rescue');
    expect(alien.request.headers['x-vercel-signature']).toBe('');
    expect(alien.request.headers['x-hooklatch-signature']).toBe(canonical);
  });

  it('keeps the fal decoy byte-real but recipe-irrelevant', () => {
    const decoy = byId(VERCEL.cases, 'positive-alien-signature-header-ignored');
    const falMessage = falCanonicalMessageBytes(RID, UID, String(BASE_NOW), bodyBytesOf(decoy));
    expect(decoy.request.headers['x-fal-webhook-signature']).toBe(falSignHex(falMessage, seedHexOfKeyId('fal-stage-key-01')));
    expect(vercelOutcomeOf(decoy.request, bodyBytesOf(decoy), decoy.options.secrets, false)).toBe('ok');
  });

  it('pins spaced-versus-compact body bytes with distinct canonical MACs', () => {
    const spaced = byId(VERCEL.cases, 'positive-json-spaced-spelling-signed');
    expect(bodyBytesOf(spaced).toString('utf8')).toBe('{ "hooklatchStage" : 9, "case" : "layout-spaced" }');
    const spacedMac = vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(spaced));
    const baselineMac = vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(byId(VERCEL.cases, 'positive-baseline')));
    expect(spacedMac).not.toBe(baselineMac);
    expect(spaced.request.headers['x-vercel-signature']).toBe(spacedMac);
  });

  it('keeps tolerance inert when no signed timestamp exists', () => {
    const unit = byId(VERCEL.cases, 'positive-tolerance-set-inert-without-timestamp');
    expect(unit.options.toleranceSeconds).toBe(90);
    expect(hasField(unit.request.headers, 'x-vercel-timestamp')).toBe(false);
    expect(vercelOutcomeOf(unit.request, bodyBytesOf(unit), unit.options.secrets, false)).toBe('ok');
    expect(unit.expected).toEqual({ ok: true, identity: { deliveryId: null, eventId: null, timestamp: null, authenticatedFields: [] } });
  });
});

// ---------------------------------------------------------------------------
describe('fal fixture anchors', () => {
  it('decodes every recorded body exactly and pins notable byte shapes', () => {
    const baseline = byId(FAL.cases, 'positive-baseline');
    expect(bodyBytesOf(baseline)).toEqual(utf8Bytes('{"hooklatchStage":9,"case":"fal-positive-baseline"}'));
    const binaryBytes = bodyBytesOf(byId(FAL.cases, 'positive-invalid-utf8-body-binary-signed'));
    expect(Array.from(binaryBytes.subarray(3, 5))).toEqual([0xff, 0xfe]);
    const largeBytes = bodyBytesOf(byId(FAL.cases, 'positive-large-body-signed'));
    expect(largeBytes).toHaveLength(4096);
    expect(largeBytes[4095]).toBe((4095 * 7 + 13) & 0xff);
    expect(bodyBytesOf(byId(FAL.cases, 'positive-empty-body-signed'))).toHaveLength(0);
    expect(bodyBytesOf(byId(FAL.cases, 'positive-non-json-body-signed'))).toEqual(utf8Bytes('plainless-stage9b'));
  });

  it('agrees with the frozen eleven-step model in both views for every row', () => {
    for (const unit of FAL.cases) {
      const body = bodyBytesOf(unit);
      const options = falModelOptions(unit);
      const record = falOutcomeOf(unit.request, body, options, false);
      outcomeAgreesWith(record, unit.expected, `fal/${unit.id} record view`);
      const web = falOutcomeOf(unit.request, body, options, true);

      if (unit.webHeadersExpected === undefined) {

        outcomeAgreesWith(web, unit.expected, `fal/${unit.id} undeclared web view`);
      } else {

        outcomeAgreesWith(web, unit.webHeadersExpected, `fal/${unit.id} declared web view`);

      }

    }

  });


  it('pins row classes: are the special sig families exactly where designed', () => {

    expect(hasField(byId(FAL.cases, 'missing-signature-header').request.headers, FAL_SIGNATURE)).toBe(false);

    expect(firstOfHeaderMap(byId(FAL.cases, 'blank-signature-is-missing').request.headers, FAL_SIGNATURE).trim()).toBe('');
    const aliased = byId(FAL.cases, 'signature-under-vercel-header-cannot-rescue');

    expect(hasField(aliased.request.headers, FAL_SIGNATURE)).toBe(false);
    expect(aliased.request.headers['x-vercel-signature']).toBe(firstOfHeaderMap(byId(FAL.cases, 'positive-baseline').request.headers, FAL_SIGNATURE));
    const upper = byId(FAL.cases, 'positive-uppercase-hex-accepted');

    expect(upper.request.headers[FAL_SIGNATURE]).toBe(firstOfHeaderMap(byId(FAL.cases, 'positive-baseline').request.headers, FAL_SIGNATURE).toUpperCase());
    expect(byId(FAL.cases, 'positive-header-casing-variant').request.headers['X-Fal-Webhook-Signature']).toBe(firstOfHeaderMap(byId(FAL.cases, 'positive-baseline').request.headers, FAL_SIGNATURE));

  });


  it('rebuilds the canonical signature origin for every row that records one', () => {


    /**
     * Families that do not carry a canonical intact value under x-fal-webhook-signature:
     * an absent header, a blank header, the signature parked under the vercel name, the
     * single deliberately mutated MAC, the two OWS-carrier rows whose MAC is signed over
     * the trimmed target values (pinned by the dedicated OWS rescue test), and the seven
     * rows whose recorded bytes are documented shape mutations of canonical material
     * (pinned byte-for-byte by the dedicated shape/foreign/duplicate tests).
     */

    const exceptions = new Map<string, 'absent' | 'blank' | 'aliased' | 'mac-flip' | 'ows-identity' | 'mutated'>()
      .set('missing-signature-header', 'absent')
      .set('blank-signature-is-missing', 'blank')
      .set('signature-under-vercel-header-cannot-rescue', 'aliased')
      .set('bad-mac-stale-timestamp-is-invalid-signature', 'mac-flip')
      .set('outer-whitespace-request-id-is-malformed-record-view', 'ows-identity')
      .set('outer-whitespace-user-id-is-malformed-record-view', 'ows-identity')
      .set('malformed-signature-non-hex-character', 'mutated')
      .set('malformed-signature-127-characters', 'mutated')
      .set('malformed-signature-129-characters', 'mutated')
      .set('malformed-signature-40-hex-vercel-sized', 'mutated')
      .set('malformed-signature-64-hex-sha256-sized', 'mutated')
      .set('comma-combined-duplicates-are-malformed', 'mutated')
      .set('differing-duplicate-signatures-are-malformed', 'mutated');

    for (const unit of FAL.cases) {
      const family = exceptions.get(unit.id) ?? 'recorded';

      if (family !== 'recorded') continue;


      const message = rawStoredInputsMessageOf(unit);


      const canonical = falSignHex(message, seedHexOfKeyId(unit.signingKeyId ?? 'missing'));


      const recorded = firstFoldedOfFal(unit, FAL_SIGNATURE).trim();


      assertIsTrue(recorded.toLowerCase() === canonical.toLowerCase(), `fal/${unit.id} recorded signature is not the canonical rebuild`);

    }


  });

  it('pins the deleted-nibble MAC flip on the stale-clock row', () => {

    const unit = byId(FAL.cases, 'bad-mac-stale-timestamp-is-invalid-signature');

    const intact = falSignHex(rawStoredInputsMessageOf(unit), seedHexOfKeyId(unit.signingKeyId ?? 'missing'));
    const recorded = firstOfHeaderMap(unit.request.headers, FAL_SIGNATURE);

    expect(recorded.slice(0, 127)).toBe(intact.slice(0, 127));

    expect(recorded.slice(127)).toBe(intact.slice(127) === '0' ? '1' : '0');

    expect(firstStoredOfFal(unit, FAL_TIMESTAMP, '').trim()).toBe(String(BASE_NOW - 1000));


    expect(falVerifyAnyMatch(recorded, receiverMessageOf(unit), unit.options.publicKeysBase64url)).toBe(false);

  });


  it('pins signature-shape mutations against freshly rebuilt canonical material', () => {


    const baseline = byId(FAL.cases, 'positive-baseline');
    const body = bodyBytesOf(baseline);
    const canonical = falSignHex(falCanonicalMessageBytes(RID, UID, String(BASE_NOW), body), seedHexOfKeyId('fal-stage-key-01'));
    expect(byId(FAL.cases, 'malformed-signature-non-hex-character').request.headers[FAL_SIGNATURE]).toBe('g' + canonical.slice(1));
    expect(byId(FAL.cases, 'malformed-signature-127-characters').request.headers[FAL_SIGNATURE]).toBe(canonical.slice(0, 127));
    expect(byId(FAL.cases, 'malformed-signature-129-characters').request.headers[FAL_SIGNATURE]).toBe(canonical + '0');

    expect(byId(FAL.cases, 'signature-outer-whitespace-is-malformed-record-view').request.headers[FAL_SIGNATURE]).toBe(' ' + canonical + ' ');

    expect(byId(FAL.cases, 'signature-trailing-whitespace-is-headers-trim-accepts').request.headers[FAL_SIGNATURE]).toBe(canonical + ' ');
  });

  it('pins foreign-size cross-confusion material from the sibling corpora', () => {
    expect(byId(FAL.cases, 'malformed-signature-40-hex-vercel-sized').request.headers[FAL_SIGNATURE]).toBe(vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(byId(FAL.cases, 'positive-baseline'))));
    expect(byId(FAL.cases, 'malformed-signature-64-hex-sha256-sized').request.headers[FAL_SIGNATURE]).toBe(createHash('sha256').update(utf8Bytes('g\u6c11\u5bbf')).digest('hex'));
  });

  it('pins duplicate signature pairs as the canonical and foreign-key halves', () => {
    const baseline = byId(FAL.cases, 'positive-baseline');
    const body = bodyBytesOf(baseline);
    const canonical = falSignHex(falCanonicalMessageBytes(RID, UID, String(BASE_NOW), body), seedHexOfKeyId('fal-stage-key-01'));
    const foreign = falSignHex(falCanonicalMessageBytes(RID, UID, String(BASE_NOW), body), seedHexOfKeyId('fal-stage-key-02'));
    expect(byId(FAL.cases, 'comma-combined-duplicates-are-malformed').request.headers[FAL_SIGNATURE]).toEqual([canonical, canonical]);
    expect(byId(FAL.cases, 'differing-duplicate-signatures-are-malformed').request.headers[FAL_SIGNATURE]).toEqual([canonical, foreign]);
  });

  it('pins crypto reachability per row exactly from grammar state', () => {
    const verifyTrue = new Set<string>([
      ...FAL_POSITIVE_IDS,
      'wrong-recipient-is-invalid-signature',
      'recipient-case-difference-is-invalid-signature',
      'wrong-recipient-future-timestamp-is-invalid-signature',
      'freshness-boundary-minus-301-expired',
      'freshness-boundary-plus-301-future',
      'zero-timestamp-grammar-valid-but-expired',
      'large-safe-integer-timestamp-future',
      'tolerance-zero-plus-one-future',
      'tolerance-zero-minus-one-expired',
    ]);

    const verifyFalse = new Set<string>(['rotation-old-key-after-removal', 'wrong-key-valid-grammar', 'tampered-body-single-byte', 'bad-mac-stale-timestamp-is-invalid-signature', 'bad-mac-wrong-recipient-is-invalid-signature']);

    const reaching = FAL.cases.filter((unit) => reachesFalCrypto(unit)).map((unit) => unit.id);

    expect(new Set(reaching)).toEqual(new Set([...verifyTrue, ...verifyFalse]));

    for (const unit of FAL.cases) {
      if (!verifyTrue.has(unit.id) && !verifyFalse.has(unit.id)) continue;


      const options = falModelOptions(unit);

      const timestamp = firstStoredOfFal(unit, FAL_TIMESTAMP, String(optionsNowOf(unit))).trim();

      const message = falCanonicalMessageBytes(firstStoredOfFal(unit, FAL_REQUEST_ID, RID).trim(), firstStoredOfFal(unit, FAL_USER_ID, UID).trim(), timestamp, bodyBytesOf(unit));
      const verifies = falVerifyAnyMatch(firstFoldedOfFal(unit, FAL_SIGNATURE).trim().toLowerCase(), message, options.acceptSet);


      expect(verifies).toBe(verifyTrue.has(unit.id));

    }

  });


  it('pins rotation, cap, duplicate-key and order independence of accept-sets', () => {


    expect(byId(FAL.cases, 'rotation-both-keys-accept-old').options.publicKeysBase64url).toEqual([publicKeyOfKeyIndex(0), publicKeyOfKeyIndex(1)]);
    expect(byId(FAL.cases, 'rotation-old-key-after-removal').options.publicKeysBase64url).toEqual([publicKeyOfKeyIndex(1)]);


    expect(bodyBytesOf(byId(FAL.cases, 'rotation-old-key-after-removal'))).toEqual(bodyBytesOf(byId(FAL.cases, 'rotation-both-keys-accept-old')));
    expect(byId(FAL.cases, 'keyset-order-independence-reversed').options.publicKeysBase64url).toEqual([publicKeyOfKeyIndex(1), publicKeyOfKeyIndex(0)]);



    expect(byId(FAL.cases, 'keyset-duplicates-inside-cap-accept').options.publicKeysBase64url).toEqual([publicKeyOfKeyIndex(0), publicKeyOfKeyIndex(0)]);

    expect(byId(FAL.cases, 'keyset-all-sixteen-fill-cap-and-rotate').options.publicKeysBase64url).toHaveLength(16);

    expect(byId(FAL.cases, 'keyset-all-sixteen-fill-cap-and-rotate').signingKeyId).toBe('fal-stage-key-16');

    for (const unit of FAL.cases) {

      assertIsTrue(unit.options.publicKeysBase64url.length >= 1 && unit.options.publicKeysBase64url.length <= 16, `fal/${unit.id} accept-set size outside the cap`);

    }

  });


  it('pins freshness boundaries, zero-width tolerance and grammar-valid expiry', () => {

    expect(byId(FAL.cases, 'freshness-boundary-minus-300-accepted').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW - 300));

    expect(byId(FAL.cases, 'freshness-boundary-plus-300-accepted').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW + 300));
    expect(byId(FAL.cases, 'freshness-boundary-minus-301-expired').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW - 301));

    expect(byId(FAL.cases, 'freshness-boundary-plus-301-future').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW + 301));
    expect(byId(FAL.cases, 'tolerance-zero-now-accepted').options.toleranceSeconds).toBe(0);

    expect(byId(FAL.cases, 'tolerance-zero-plus-one-future').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW + 1));
    expect(byId(FAL.cases, 'tolerance-zero-minus-one-expired').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW - 1));
    expect(byId(FAL.cases, 'tolerance-100-boundary-plus-100-accepted').options.toleranceSeconds).toBe(100);


    expect(byId(FAL.cases, 'tolerance-100-boundary-plus-100-accepted').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW + 100));


    expect(byId(FAL.cases, 'zero-timestamp-grammar-valid-but-expired').request.headers[FAL_TIMESTAMP]).toBe('0');
    expect(byId(FAL.cases, 'large-safe-integer-timestamp-future').request.headers[FAL_TIMESTAMP]).toBe('9007199254740991');
    expect(Number.isSafeInteger(Number('9007199254740991'))).toBe(true);
  });

  it('pins zero-timestamp and large-safe-integer rows as crypto-passing freshness rejects', () => {
    for (const id of ['zero-timestamp-grammar-valid-but-expired', 'large-safe-integer-timestamp-future']) {
      const unit = byId(FAL.cases, id);
      const options = falModelOptions(unit);

      const signature = firstOfHeaderMap(unit.request.headers, FAL_SIGNATURE);
      const message = receiverMessageOf(unit);
      expect(falVerifyAnyMatch(signature, message, options.acceptSet)).toBe(true);
      expect(options.expectedUserId).toBe(UID);
    }
  });

  it('pins account binding as an exact string comparison with binding-first ordering', () => {
    expect(byId(FAL.cases, 'wrong-recipient-is-invalid-signature').options.expectedUserId).toBe('usr_hooklatch_alternate');
    expect(byId(FAL.cases, 'wrong-recipient-is-invalid-signature').request.headers[FAL_USER_ID]).toBe(UID);
    expect(byId(FAL.cases, 'recipient-case-difference-is-invalid-signature').request.headers[FAL_USER_ID]).toBe('USR_hooklatch_stage9');
    expect(byId(FAL.cases, 'recipient-case-difference-is-invalid-signature').options.expectedUserId).toBe(UID);
    const forwarding = byId(FAL.cases, 'wrong-recipient-future-timestamp-is-invalid-signature');
    expect(forwarding.request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW + 5000));
    expect(falOutcomeOf(forwarding.request, bodyBytesOf(forwarding), falModelOptions(forwarding), false)).toBe('invalid-signature');
  });

  it('pins identity presence and grammar families byte-for-byte', () => {
    expect(hasField(byId(FAL.cases, 'missing-identity-request-id-absent').request.headers, FAL_REQUEST_ID)).toBe(false);
    expect(hasField(byId(FAL.cases, 'missing-identity-user-id-absent').request.headers, FAL_USER_ID)).toBe(false);
    expect(hasField(byId(FAL.cases, 'missing-identity-both-absent').request.headers, FAL_REQUEST_ID)).toBe(false);
    expect(hasField(byId(FAL.cases, 'missing-identity-both-absent').request.headers, FAL_USER_ID)).toBe(false);
    expect(byId(FAL.cases, 'missing-identity-request-id-blank-value').request.headers[FAL_REQUEST_ID]).toBe('   ');
    expect(byId(FAL.cases, 'missing-identity-user-id-empty-value').request.headers[FAL_USER_ID]).toBe('');
    expect(hasField(byId(FAL.cases, 'order-presence-before-id-grammar').request.headers, FAL_REQUEST_ID)).toBe(false);
    expect(byId(FAL.cases, 'order-presence-before-id-grammar').request.headers[FAL_USER_ID]).toBe('bad user');
    expect(byId(FAL.cases, 'order-presence-before-id-grammar').request.headers[FAL_SIGNATURE]).toBe(falSignHex(falCanonicalMessageBytes(RID, 'bad user', String(BASE_NOW), bodyBytesOf(byId(FAL.cases, 'positive-baseline'))), seedHexOfKeyId('fal-stage-key-01')));
    expect(byId(FAL.cases, 'id-grammar-user-id-with-comma').request.headers[FAL_USER_ID]).toBe('user,extra');
    expect(byId(FAL.cases, 'id-grammar-user-id-with-space').request.headers[FAL_USER_ID]).toBe('bad user');
    expect(byId(FAL.cases, 'id-grammar-user-id-with-unicode').request.headers[FAL_USER_ID]).toBe('us\u00e9r_\u03bb');
    expect(byId(FAL.cases, 'id-grammar-user-id-crlf').request.headers[FAL_USER_ID]).toBe('bad\r\nuser');
    expect(byId(FAL.cases, 'id-grammar-user-id-del-byte').request.headers[FAL_USER_ID]).toBe('bad\u007fuser');
    expect(byId(FAL.cases, 'id-grammar-user-id-nul-byte').request.headers[FAL_USER_ID]).toBe('bad\u0000user');
    expect(byId(FAL.cases, 'id-grammar-user-id-too-long-1025').request.headers[FAL_USER_ID]).toHaveLength(1025);
    expect(byId(FAL.cases, 'id-boundary-request-id-1024-accepted').request.headers[FAL_REQUEST_ID]).toHaveLength(1024);
    expect(byId(FAL.cases, 'order-id-grammar-before-missing-timestamp').request.headers[FAL_USER_ID]).toBe('bad user');
    expect(hasField(byId(FAL.cases, 'order-id-grammar-before-missing-timestamp').request.headers, FAL_TIMESTAMP)).toBe(false);
    expect(byId(FAL.cases, 'order-id-grammar-before-missing-timestamp').request.headers[FAL_SIGNATURE]).toBe(falSignHex(falCanonicalMessageBytes(RID, 'bad user', String(BASE_NOW), bodyBytesOf(byId(FAL.cases, 'positive-baseline'))), seedHexOfKeyId('fal-stage-key-01')));
  });

  it('pins timestamp grammar exclusions byte-for-byte', () => {
    expect(byId(FAL.cases, 'ts-grammar-leading-zero-malformed').request.headers[FAL_TIMESTAMP]).toBe('0' + String(BASE_NOW));
    expect(byId(FAL.cases, 'ts-grammar-plus-sign-malformed').request.headers[FAL_TIMESTAMP]).toBe('+' + String(BASE_NOW));
    expect(byId(FAL.cases, 'ts-grammar-negative-malformed').request.headers[FAL_TIMESTAMP]).toBe('-' + String(BASE_NOW));
    expect(byId(FAL.cases, 'ts-grammar-decimal-malformed').request.headers[FAL_TIMESTAMP]).toBe(String(BASE_NOW) + '.5');
    expect(byId(FAL.cases, 'ts-grammar-inner-space-malformed').request.headers[FAL_TIMESTAMP]).toBe('17927 42400');
    expect(byId(FAL.cases, 'ts-grammar-unicode-digit-malformed').request.headers[FAL_TIMESTAMP]).toBe('\u0661\u0667\u0669\u0662\u0667\u0664\u0662\u0664\u0660\u0660');
  });

  it('pins missing-timestamp rows as genuinely header-free or trim-blank', () => {
    expect(hasField(byId(FAL.cases, 'missing-timestamp-header').request.headers, FAL_TIMESTAMP)).toBe(false);
    expect(byId(FAL.cases, 'missing-timestamp-blank-value').request.headers[FAL_TIMESTAMP]).toBe('   ');
    expect(byId(FAL.cases, 'missing-timestamp-header').request.headers[FAL_SIGNATURE]).toBe(firstOfHeaderMap(byId(FAL.cases, 'positive-baseline').request.headers, FAL_SIGNATURE));
  });

  it('pins duplicates inside identity and timestamp fields as comma rejections', () => {
    expect(byId(FAL.cases, 'duplicate-request-id-with-comma-are-malformed').request.headers[FAL_REQUEST_ID]).toEqual([RID, 'second-id']);
    expect(byId(FAL.cases, 'duplicate-user-id-equal-values-are-malformed').request.headers[FAL_USER_ID]).toEqual([UID, UID]);
    expect(byId(FAL.cases, 'duplicate-timestamp-are-malformed').request.headers[FAL_TIMESTAMP]).toEqual([String(BASE_NOW), String(BASE_NOW)]);
  });

  it('pins WHATWG declared views, record-only rows and comma combination through real Headers', () => {
    for (const id of FAL_RECORD_ONLY_IDS) {
      const unit = byId(FAL.cases, id);
      expect(unit.webHeadersExpected).toBeUndefined();
      const tuples: [string, string][] = [];

      for (const [name, value] of Object.entries(unit.request.headers)) {

        for (const item of isString(value) ? [value] : value) tuples.push([name, item]);

      }

      expect(() => new Headers(tuples)).toThrow();
    }

    const representable = FAL_IDS.filter((id) => !FAL_RECORD_ONLY_IDS.includes(id));
    expect(representable.length + FAL_RECORD_ONLY_IDS.length).toBe(FAL_IDS.length);



    for (const id of representable) {

      const unit = byId(FAL.cases, id);


      const tuples: [string, string][] = [];

      for (const [name, value] of Object.entries(unit.request.headers)) {

        for (const item of isString(value) ? [value] : value) tuples.push([name, item]);

      }


      const built = new Headers(tuples);



      if (id === 'comma-combined-duplicates-are-malformed') {



        const single = firstOfHeaderMap(unit.request.headers, FAL_SIGNATURE);


        expect(built.get(FAL_SIGNATURE)).toBe(`${single}, ${single}`);


      }



      if (id === 'positive-baseline') {



        expect(built.get(FAL_TIMESTAMP)).toBe(String(BASE_NOW));
      }



    }
  });


  it('pins positive identities to the signed timestamp with timestamp-only authentication', () => {

    for (const unit of FAL.cases) {

      if (!unit.expected.ok) continue;

      const identity = unit.expected.identity;
      expect(identity.deliveryId).toBe(null);

      expect(identity.eventId).toBe(null);
      expect(identity.timestamp).toBe(Number(firstStoredOfFal(unit, FAL_TIMESTAMP, String(optionsNowOf(unit))).trim()));


      expect(identity.authenticatedFields).toEqual(['timestamp']);
    }
  });

  it('keeps x-vercel decoys strictly inert and pins the transplanted-signature trap', () => {
    const decoy = byId(FAL.cases, 'positive-decoy-vercel-header-ignored');
    expect(decoy.request.headers['x-vercel-signature']).toBe(vercelHmacHex(V_MAIN_SECRET, bodyBytesOf(decoy)));
    expect(falOutcomeOf(decoy.request, bodyBytesOf(decoy), falModelOptions(decoy), false)).toBe('ok');
    const trap = byId(FAL.cases, 'signature-under-vercel-header-cannot-rescue');
    expect(falOutcomeOf(trap.request, bodyBytesOf(trap), falModelOptions(trap), false)).toBe('missing-signature');
  });

  it('documents inverted orders with same-body structural clones', () => {
    const presence = byId(FAL.cases, 'order-presence-before-id-grammar');
    const withRequest = structuredClone(presence);
    withRequest.request.headers[FAL_REQUEST_ID] = RID;
    expect(falOutcomeOf(withRequest.request, bodyBytesOf(presence), falModelOptions(presence), false)).toBe('malformed-signature');
    const grammar = byId(FAL.cases, 'order-id-grammar-before-missing-timestamp');
    const withGoodUser = structuredClone(grammar);
    withGoodUser.request.headers[FAL_USER_ID] = UID;
    expect(falOutcomeOf(withGoodUser.request, bodyBytesOf(grammar), falModelOptions(grammar), false)).toBe('missing-timestamp');
    const withTimestamp = structuredClone(grammar);
    withTimestamp.request.headers[FAL_TIMESTAMP] = String(BASE_NOW);
    expect(falOutcomeOf(withTimestamp.request, bodyBytesOf(grammar), falModelOptions(grammar), false)).toBe('malformed-signature');
  });

  it('shows the WHATWG view rescues OWS rows and keeps their identity projection', () => {
    const ridPadded = byId(FAL.cases, 'outer-whitespace-request-id-is-malformed-record-view');
    expect(ridPadded.webHeadersExpected).toEqual({ ok: true, identity: { deliveryId: null, eventId: null, timestamp: BASE_NOW, authenticatedFields: ['timestamp'] } });
    expect(firstStoredOfFal(ridPadded, FAL_REQUEST_ID, 'x')).toBe(' ' + RID + ' ');
    const message = falCanonicalMessageBytes(RID, UID, String(BASE_NOW), bodyBytesOf(ridPadded));
    expect(firstOfHeaderMap(ridPadded.request.headers, FAL_SIGNATURE)).toBe(falSignHex(message, seedHexOfKeyId('fal-stage-key-01')));
    const idPadded = byId(FAL.cases, 'outer-whitespace-user-id-is-malformed-record-view');
    expect(firstStoredOfFal(idPadded, FAL_USER_ID, 'x')).toBe(' ' + UID + ' ');
  });
});

// ---------------------------------------------------------------------------
describe('primitive references recomputed', () => {
  it('recomputes the seven RFC 2202 HMAC-SHA1 vectors including the 96-bit truncation', () => {
    for (const primitive of VERCEL.primitiveReferences) {
      const mac = createHmac('sha1', Buffer.from(primitive.keyHex, 'hex')).update(Buffer.from(primitive.dataHex, 'hex')).digest('hex');
      expect(mac).toBe(primitive.hmacHex);
      expect(Buffer.from(primitive.keyHex, 'hex')).toHaveLength(primitive.keyByteLength);

      if (primitive.truncated96Hex !== undefined) {

        expect(mac.startsWith(primitive.truncated96Hex)).toBe(true);

        expect(primitive.truncated96Hex).toHaveLength(24);

      }

    }

  });

  it('recomputes the RFC 8032 Ed25519 vectors and their canonical encodings', () => {

    for (const primitive of FAL.primitiveReferences) {
      if (primitive.family !== 'ed25519') continue;




      const seed = Buffer.from(primitive.seedHex, 'hex');
      expect(canonicalBase64UrlOf(ed25519PublicKeyBytesForSeed(seed))).toBe(canonicalBase64UrlOf(Buffer.from(primitive.publicKeyHex, 'hex')));
      expect(primitive.publicKeyBase64url).toBe(canonicalBase64UrlOf(Buffer.from(primitive.publicKeyHex, 'hex')));
      const keyObject = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: primitive.publicKeyBase64url }, format: 'jwk' });
      expect(verify(null, Buffer.from(primitive.messageHex, 'hex'), keyObject, Buffer.from(primitive.signatureHex, 'hex'))).toBe(true);
      expect(primitive.attribution.includes('never vendor conformance')).toBe(true);

    }
  });

  it('recomputes the published SHA-256 digests', () => {
    for (const primitive of FAL.primitiveReferences) {
      if (primitive.family !== 'sha-256') continue;
      expect(sha256HexOf(Buffer.from(primitive.messageHex, 'hex'))).toBe(primitive.digestHex);
      assertIsTrue(primitive.digestHex === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' || primitive.digestHex === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', `primitive ${primitive.id} digest is not a published SHA-256 constant`);
    }
  });
});

// ---------------------------------------------------------------------------
describe('independent message canonicalization anchors', () => {
  it('pins the exact baseline fal message framing: LF separators, lowercase digest, no trailing LF', () => {
    const baseline = byId(FAL.cases, 'positive-baseline');
    const body = bodyBytesOf(baseline);
    const message = falCanonicalMessageBytes(RID, UID, String(BASE_NOW), body);
    const text = message.toString('utf8');
    expect(text.endsWith('\n')).toBe(false);
    const parts = text.split('\n');
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe(RID);
    expect(parts[1]).toBe(UID);
    expect(parts[2]).toBe(String(BASE_NOW));
    expect(parts[3]).toBe(sha256HexOf(body));

    if (parts[3] !== undefined) {

      expect(parts[3]).toBe(parts[3].toLowerCase());

    }

  });


  it('never builds messages from OWS-decorated values: header carrier only', () => {

    const paddedRidRow = byId(FAL.cases, 'outer-whitespace-request-id-is-malformed-record-view');

    const body = bodyBytesOf(paddedRidRow);
    const message = falCanonicalMessageBytes(RID, UID, String(BASE_NOW), body);




    const canonical = falSignHex(message, seedHexOfKeyId('fal-stage-key-01'));
    expect(firstOfHeaderMap(paddedRidRow.request.headers, FAL_SIGNATURE)).toBe(canonical);
    const recordRid = firstStoredOfFal(paddedRidRow, FAL_REQUEST_ID, 'x');
    expect(recordRid).toBe(' ' + RID + ' ');
    expect(recordRid.trim()).toBe(RID);
  });

});

// ---------------------------------------------------------------------------
// Guard rejection and collection mutation controls. The mutated inputs below
// are deliberately invalid constructions, documented inline, used only to
// prove the guards and recomputation catch them; they are never written back.
// ---------------------------------------------------------------------------
describe('guard and collection negative controls', () => {
  function expectGuardThrows(block: () => void, label: string): void {
    let caught: unknown;

    try {

      block();

    } catch (error) {

      caught = error;
    }

    expect(caught instanceof Error && caught.message.startsWith('fixture-anchor failure:')).toBe(true);

    expect(label).toBeTruthy();
  }




  // The shape below feeds only the deliberate guard rejection paths, never fixtures.
  function malformedExpected(suspect: { ok: boolean; reason?: string; identity?: { deliveryId: string | number | null; eventId: string | number | null; timestamp: number | null; authenticatedFields?: string[] } }): CaseExpected {

    // SAFETY: this cast constructs a deliberately invalid expectation shape for the guard negative controls.

    return suspect as CaseExpected;


  }

  function malformedProvenance(suspect: { class: string; source: string }): CaseProvenance {
    // SAFETY: this cast constructs a deliberately invalid provenance shape for the guard negative controls.
    return suspect as CaseProvenance;
  }


  function malformedFalOptions(suspect: { publicKeysBase64url: unknown; expectedUserId: unknown; now: unknown; toleranceSeconds?: unknown; maxBodyBytes?: unknown }): FalOptionsMirror {
    // SAFETY: this cast constructs a deliberately invalid fal options shape for the guard negative controls.
    return suspect as FalOptionsMirror;
  }

  it('rejects fifteen distinct guard mutations of fal rows', () => {
    let mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.options.publicKeysBase64url = ['Q'.repeat(42)];
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.options.publicKeysBase64url = [publicKeyOfKeyIndex(0) + '='];
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.options.publicKeysBase64url = Array.from({ length: 17 }, () => publicKeyOfKeyIndex(0));
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.options.expectedUserId = 'user,extra';
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.options = malformedFalOptions({ ...mutation.options, now: '1792742400' });
    expect(isFalCase(mutation)).toBe(false);
    const negativeTolerance = structuredClone(byId(FAL.cases, 'tolerance-zero-now-accepted'));
    negativeTolerance.options.toleranceSeconds = -1;
    expect(isFalCase(negativeTolerance)).toBe(false);
    const negativeIdentity = structuredClone(byId(FAL.cases, 'wrong-recipient-is-invalid-signature'));
    negativeIdentity.expected = malformedExpected({ ok: false, reason: 'invalid-signature', identity: { deliveryId: null, eventId: null, timestamp: BASE_NOW, authenticatedFields: ['timestamp'] } });
    expect(isFalCase(negativeIdentity)).toBe(false);
    const missingAuthedFields = structuredClone(byId(FAL.cases, 'positive-baseline'));
    missingAuthedFields.expected = malformedExpected({ ok: true, identity: { deliveryId: null, eventId: null, timestamp: BASE_NOW } });
    expect(isFalCase(missingAuthedFields)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.request.headers = { 'bad name': 'x' };
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.request.headers = { 'x-fal-webhook-signature': 'a', 'X-Fal-Webhook-Signature': 'b' };
    expect(isFalCase(mutation)).toBe(false);
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.provenance = malformedProvenance({ class: 'blob', source: 'immaterial because class fails first' });
    expect(isFalCase(mutation)).toBe(false);
    const foreignReason = structuredClone(byId(FAL.cases, 'wrong-recipient-is-invalid-signature'));
    foreignReason.expected = malformedExpected({ ok: false, reason: 'recipient-mismatch' });
    expect(isFalCase(foreignReason)).toBe(false);
    const uuidDonor = structuredClone(byId(FAL.cases, 'positive-baseline'));
    uuidDonor.anchorDonorId = 'no-such-row';
    expectGuardThrows(() => falCorpusRefsOf(uuidDonor, new Set<string>(SYNTHETIC_KEY_IDS), new Set<string>(['positive-baseline'])), 'unknown donor reference');
    const alienKey = structuredClone(byId(FAL.cases, 'positive-baseline'));
    alienKey.signingKeyId = 'fal-stage-key-99';
    expectGuardThrows(() => falCorpusRefsOf(alienKey, new Set<string>(SYNTHETIC_KEY_IDS), new Set<string>(['positive-baseline'])), 'unknown key reference');
    mutation = structuredClone(byId(FAL.cases, 'positive-baseline'));
    mutation.request.headers = { 'x-fal-webhook-signature': [] };
    expect(isFalCase(mutation)).toBe(false);
  });

  it('rejects distinct guard mutations of vercel rows and demonstrates bad JSON is a parse failure', () => {
    const emptySecret = structuredClone(byId(VERCEL.cases, 'positive-baseline'));
    emptySecret.options.secrets = [''];
    expect(isVercelCase(emptySecret)).toBe(false);
    const unknownReason = structuredClone(byId(VERCEL.cases, 'wrong-key-valid-grammar'));
    unknownReason.expected = { ok: false, reason: 'not-really-a-reason' };
    expect(isVercelCase(unknownReason)).toBe(false);
    const missingNow = structuredClone(byId(VERCEL.cases, 'positive-baseline'));
    // SAFETY: erasing a required option key constructs the missing-now control without writing fixtures.
    const erasedOptions = missingNow.options as { secrets: string[]; now?: number; toleranceSeconds?: number };
    delete erasedOptions.now;
    expect(isVercelCase(missingNow)).toBe(false);
    const typedRepeat = structuredClone(byId(VERCEL.cases, 'positive-baseline'));
    // SAFETY: planting a numeric repeat element constructs the non-string-value control without writing fixtures.
    typedRepeat.request.headers = JSON.parse('{"x-vercel-signature":["a",5]}');
    expect(isVercelCase(typedRepeat)).toBe(false);
    let jsonCaught: unknown;

    try {

      JSON.parse('{"broken":');

    } catch (error) {

      jsonCaught = error;
    }

    expect(jsonCaught instanceof Error).toBe(true);


  });


  it('proves model-level tamper detection without rewriting fixture files', () => {

    const baseline = byId(FAL.cases, 'positive-baseline');

    const intactBody = bodyBytesOf(baseline);
    const flippedByte = intactBody[4];


    if (flippedByte === undefined) fail('baseline body is too short to tamper');

    const flippedBody = Buffer.concat([intactBody.subarray(0, 4), Buffer.from([flippedByte ^ 0x01]), intactBody.subarray(5)]);
    const flippedSignature = `${falSignHex(falCanonicalMessageBytes(RID, UID, String(BASE_NOW), bodyBytesOf(baseline)), seedHexOfKeyId('fal-stage-key-01')).slice(0, 127)}1`;
    const tampered = structuredClone(baseline);
    tampered.request.headers[FAL_SIGNATURE] = flippedSignature;

    const flippedRecord = falOutcomeOf(tampered.request, flippedBody, falModelOptions(baseline), false);
    let violated: unknown;

    try {

      outcomeAgreesWith(flippedRecord, baseline.expected, 'mutated replay');

    } catch (error) {

      violated = error;



    }


    expect(violated instanceof Error && violated.message.includes('fixture expects ok')).toBe(true);
  });

  it('detects key-swap mutation via re-derivation mismatch, not via silence', () => {
    const key01 = FAL.syntheticKeys[0];

    const key02 = FAL.syntheticKeys[1];

    if (key01 === undefined || key02 === undefined) fail('synthetic keys missing');

    const swapped = canonicalBase64UrlOf(ed25519PublicKeyBytesForSeed(Buffer.from(key02.seedHex, 'hex')));

    expect(swapped).not.toBe(key01.publicKeyBase64url);


    expect(swapped).toBe(key02.publicKeyBase64url);


  });

  it('detects inventory splices and renames against the pinned lists', () => {
    const renamed = FAL_IDS.map((id) => (id === 'positive-baseline' ? 'renamed-row' : id));

    expect(renamed).not.toEqual(FAL_IDS);
    const spliced = FAL_IDS.filter((id) => id !== 'positive-baseline');
    expect(spliced).toHaveLength(FAL_IDS.length - 1);
    const firstCase = FAL.cases[0];

    if (firstCase === undefined) fail('fal cases empty');

    expectFallsOver(() => uniqueIdsInOrder([...FAL.cases, firstCase], 'duplicate-insert'), 'duplicate id insert');

  });

});


// ---------------------------------------------------------------------------
describe('self-contained sourcing', () => {

  it('keeps this anchor file free of src, provider or shared-helper imports', () => {
    const importLines = TEST_FILE_BYTES.split('\n').filter((line) => line.startsWith('import ') && line.includes(' from '));
    const allowedHosts = ["'node:buffer'", "'node:crypto'", "'node:fs'", "'node:path'", "'node:url'"];
    expect(importLines).toHaveLength(5);

    for (const line of importLines) {

      assertIsTrue(allowedHosts.some((host) => line.includes(host)), `unexpected import host: ${line.trim()}`);

      expect(line.includes('src/')).toBe(false);

      expect(line.includes('helpers')).toBe(false);

      expect(line.includes('providers/')).toBe(false);
    }

    // The needles themselves are assembled at runtime so these source bytes do not claim to import the SDK.
    expect(TEST_FILE_BYTES.includes(["from", "'../../src"].join(' '))).toBe(false);
    expect(TEST_FILE_BYTES.includes(['verify', 'Request'].join(''))).toBe(false);
  });

  it('exposes no SDK verification behavior of its own', () => {

    expect(TEST_FILE_BYTES.toLowerCase().includes(['create', 'verifier'].join(''))).toBe(false);
    expect(TEST_FILE_BYTES.toLowerCase().includes(['diagnose', '('].join(''))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
function expectFallsOver(block: () => void, label: string): void {
  let caught: unknown;

  try {

    block();

  } catch (error) {

    caught = error;

  }

  expect(caught instanceof Error).toBe(true);

  expect(label).toBeTruthy();

}


function reachesFalCrypto(unit: FalCase): boolean {
  const signature = joinedOf(foldedOf(unit.request, false), FAL_SIGNATURE);

  if (signature === undefined || !/^([0-9a-fA-F]{128})$/.test(signature)) return false;

  const requestId = joinedOf(foldedOf(unit.request, false), FAL_REQUEST_ID);

  const userId = joinedOf(foldedOf(unit.request, false), FAL_USER_ID);

  if (requestId === undefined || userId === undefined || !visibleAsciiId(requestId) || !visibleAsciiId(userId)) return false;

  const timestamp = joinedOf(foldedOf(unit.request, false), FAL_TIMESTAMP);

  return timestamp !== undefined && canonicalTimestampText(timestamp);
}
