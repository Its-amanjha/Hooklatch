import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { renderTemplate } from '../../src/cli/templates.js';
import { resolveOutput, validateOutDir } from '../../src/cli/filesystem.js';

const CLI = path.resolve(process.cwd(), 'dist', 'cli', 'index.js');

const BASE = ['init', 'webhook', '--provider', 'stripe', '--framework', 'express'] as const;

const SENTINEL_NAME = 'SENTINEL.txt';
const SENTINEL_BYTES = 'phase6-boundary-sentinel-7f3c9a';

/** Built at runtime: argv cannot carry a NUL, so it may not appear in source. */
const NUL_PATH = `out${String.fromCharCode(0)}dir`;

/** Errno values an unprivileged host reports when it refuses link creation. */
const SYMLINK_PRIVILEGE_ERRNOS = ['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP', 'EINVAL'];

interface CliRunResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function isErrnoException(error: unknown): error is { readonly code: string } {
  return typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string';
}

function run(args: readonly string[], cwd: string): CliRunResult {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });

  return { status: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** Bounded async run: a hung child is killed rather than leaking a handle. */
function runAsync(args: readonly string[], cwd: string, timeoutMs = 30000): Promise<number> {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, stdio: 'ignore' });
    const timer = setTimeout(() => { child.kill(); }, timeoutMs);

    timer.unref();

    child.on('exit', (code) => { clearTimeout(timer); resolvePromise(code ?? 1); });
    child.on('error', () => { clearTimeout(timer); resolvePromise(-1); });
  });
}

/** An owned temp root with a sentinel that no test's output may disturb. */
function createRoot(tag: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `hooklatch-phase6-${tag}-`));

  fs.writeFileSync(path.join(root, SENTINEL_NAME), SENTINEL_BYTES);

  return root;
}

/** Recursively delete only after proving the target is still inside OS temp. */
function cleanup(root: string): void {
  const resolved = path.resolve(root);

  expect(resolved.startsWith(`${path.resolve(os.tmpdir())}${path.sep}`)).toBe(true);
  expect(fs.existsSync(resolved)).toBe(true);

  fs.rmSync(resolved, { recursive: true, force: true });
}

function assertSentinelUntouched(root: string): void {
  expect(fs.readFileSync(path.join(root, SENTINEL_NAME), 'utf8')).toBe(SENTINEL_BYTES);
}

/** Every file under `root` as POSIX-relative paths; links count as leaves. */
function listFiles(root: string): string[] {
  const found: string[] = [];

  const walk = (directory: string, prefix: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;

      if (entry.isDirectory()) walk(path.join(directory, entry.name), relative);
      else found.push(relative);
    }
  };

  walk(root, '');

  return found.sort();
}

test.each([
  ['absolute posix', '/abs'],
  ['posix root', '/'],
  ['absolute windows', 'C:\\tmp'],
  ['drive-relative windows', 'C:out'],
  ['drive-relative with separator', 'C:out\\nested'],
  ['bare drive letter', 'C:'],
  ['UNC with backslashes', '\\\\server\\share\\out'],
  ['UNC with forward slashes', '//server/share/out'],
])('rejects %s --out with exit 2 and writes nothing', (_label, out) => {
  const root = createRoot('absolute');

  try {
    const result = run([...BASE, '--out', out], root);

    expect(result.status).toBe(2);

    // The path validator rejected it, not the generic unexpected-error wrapper.
    expect(result.stderr.trim()).not.toBe('Unable to inspect output path.');
    expect(listFiles(root)).toEqual([SENTINEL_NAME]);
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test.each([
  ['empty', ''],
  ['blank', '   '],
  ['single slash', '/'],
  ['single backslash', '\\'],
  ['double slash', '//'],
  ['double backslash', '\\\\'],
])('rejects %s --out instead of resolving it to the working directory', (_label, out) => {
  // `parseArgs` rejects an empty value first; the filesystem layer must agree.
  expect(() => validateOutDir(out)).toThrow(expect.objectContaining({ exitCode: 2 }));
});

test.each([
  ['.git'], ['.GIT'], ['.Git'],
  ['node_modules'], ['NODE_MODULES'], ['NoDe_MoDuLeS'],
  ['con'], ['CON'], ['aux'], ['AUX'], ['nul'], ['NUL'], ['prn'],
  ['com1'], ['COM1'], ['lpt9'], ['LPT9'],
  ['con.txt'], ['nul.foo'], ['com1.bar'],
  ['nested/.git'], ['nested/CON'], ['a/node_modules/b'],
])('rejects reserved component %s case-insensitively at its own rule', (out) => {
  expect(() => validateOutDir(out)).toThrow(expect.objectContaining({ exitCode: 2 }));
});

test.each([
  ['concat'], ['conf'], ['constants'],
  ['com0'], ['lpt0'],
  ['node_modules_backup'], ['.github'], ['.gitignore'], ['my.git'], ['git'],
])('accepts %s, which only resembles a reserved name', (out) => {
  expect(validateOutDir(out)).toEqual(out.split('/'));
});

test.each(['dir.', 'dir ', 'dir..', 'dir  '])('rejects trailing dot or space in %s alone', (out) => {
  // Isolated from `.git.`/`node_modules ` so the trailing dot/space rule is the
  // only one that could be responsible.
  expect(() => validateOutDir(out)).toThrow(expect.objectContaining({ exitCode: 2 }));
});

test('normalizes mixed and trailing separators into one path', () => {
  expect(validateOutDir('a/b\\c')).toEqual(['a', 'b', 'c']);
  expect(validateOutDir('hooklatch\\')).toEqual(['hooklatch']);
  expect(validateOutDir('a/')).toEqual(['a']);
});

test.each(['a\\..\\..\\escape', 'a\\..\\b', '..\\escape', 'a\\../b'])(
  'rejects traversal hidden behind either separator: %s', (out) => {
    expect(() => validateOutDir(out)).toThrow(expect.objectContaining({ exitCode: 2 }));
  },
);

test('mixed separators land in the same nested target as forward slashes', () => {
  const root = createRoot('mixed');

  try {
    const result = run([...BASE, '--out', 'a/b\\c'], root);

    expect(result.status).toBe(0);
    expect(listFiles(root)).toEqual([SENTINEL_NAME, 'a/b/c/stripe.express.ts']);
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('an ancestor that is a regular file exits 2 and is left untouched', () => {
  const root = createRoot('ancestor-file');

  try {
    const blocker = path.join(root, 'blocker');

    fs.writeFileSync(blocker, 'BLOCKER-BYTES');

    expect(() => resolveOutput(root, 'blocker/nested', 'route.ts'))
      .toThrow(expect.objectContaining({ exitCode: 2 }));

    const result = run([...BASE, '--out', 'blocker/nested'], root);

    expect(result.status).toBe(2);
    expect(fs.readFileSync(blocker, 'utf8')).toBe('BLOCKER-BYTES');
    expect(listFiles(root)).toEqual([SENTINEL_NAME, 'blocker']);
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('an existing directory at the target file path exits 3 and is not removed', () => {
  const root = createRoot('directory-target');

  try {
    const directory = path.join(root, 'hooklatch', 'stripe.express.ts');

    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'keep.txt'), 'KEEP');

    const result = run(BASE, root);

    expect(result.status).toBe(3);
    expect(fs.statSync(directory).isDirectory()).toBe(true);
    expect(fs.readFileSync(path.join(directory, 'keep.txt'), 'utf8')).toBe('KEEP');
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('dry run over an existing target exits 3, writes nothing and prints no contents', () => {
  const root = createRoot('dry-conflict');

  try {
    const file = path.join(root, 'hooklatch', 'stripe.express.ts');

    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, 'ORIGINAL');

    const result = run([...BASE, '--dry-run'], root);

    expect(result.status).toBe(3);
    expect(result.stdout).toBe('');
    expect(fs.readFileSync(file, 'utf8')).toBe('ORIGINAL');
    expect(listFiles(root)).toEqual([SENTINEL_NAME, 'hooklatch/stripe.express.ts']);
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('dry run under a symlink ancestor exits 2 and writes nothing through it', () => {
  const root = createRoot('dry-symlink');

  try {
    const throughLink = path.join(root, 'through-link');

    fs.mkdirSync(throughLink);
    fs.symlinkSync(throughLink, path.join(root, 'hooklatch'), 'junction');

    const result = run([...BASE, '--dry-run'], root);

    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(fs.readdirSync(throughLink)).toEqual([]);
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('a live junction at the target path exits 2 rather than reporting a conflict', () => {
  const root = createRoot('live-junction');

  try {
    const referent = path.join(root, 'referent');
    const link = path.join(root, 'hooklatch', 'stripe.express.ts');

    fs.mkdirSync(referent);
    fs.writeFileSync(path.join(referent, 'REFERENT.txt'), 'REFERENT-BYTES');
    fs.mkdirSync(path.dirname(link));
    fs.symlinkSync(referent, link, 'junction');

    const result = run(BASE, root);

    // Unsafe path (2), never "target file already exists" (3).
    expect(result.status).toBe(2);
    expect(fs.readdirSync(referent)).toEqual(['REFERENT.txt']);
    expect(fs.readFileSync(path.join(referent, 'REFERENT.txt'), 'utf8')).toBe('REFERENT-BYTES');
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('a live file symlink target is rejected without touching its referent', () => {
  const root = createRoot('file-symlink');

  try {
    const referent = path.join(root, 'REFERENT.ts');
    const link = path.join(root, 'hooklatch', 'stripe.express.ts');

    fs.writeFileSync(referent, 'REFERENT-BYTES');
    fs.mkdirSync(path.dirname(link));

    let creationError: string | undefined;

    try { fs.symlinkSync(referent, link, 'file'); }
    catch (error) { creationError = isErrnoException(error) ? error.code : undefined; }

    if (creationError !== undefined) {
      // Unprivileged Windows hosts refuse file symlinks without Developer Mode.
      // Assert the limitation itself instead of claiming a behaviour that was
      // never exercised; nothing may have been written either way.
      expect(SYMLINK_PRIVILEGE_ERRNOS).toContain(creationError);
      expect(fs.existsSync(link)).toBe(false);
      expect(fs.readFileSync(referent, 'utf8')).toBe('REFERENT-BYTES');
      assertSentinelUntouched(root);

      return;
    }

    const result = run(BASE, root);

    expect(result.status).toBe(2);
    expect(fs.readFileSync(referent, 'utf8')).toBe('REFERENT-BYTES');
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});

test('rejects an embedded NUL in --out', () => {
  expect(() => validateOutDir(NUL_PATH)).toThrow(expect.objectContaining({ exitCode: 2 }));

  // Node refuses argv carrying a NUL outright, so this boundary is only
  // reachable through a direct parser call and never through the CLI process.
  expect(() => spawnSync(process.execPath, [CLI, ...BASE, '--out', NUL_PATH]))
    .toThrow(expect.objectContaining({ code: 'ERR_INVALID_ARG_VALUE' }));
});

test('concurrent writers into a fresh nested directory produce exactly one complete file', async () => {
  const root = createRoot('concurrent-nested');

  try {
    const nested = [...BASE, '--out', 'a/b/c'];

    const statuses = await Promise.all([
      runAsync(nested, root), runAsync(nested, root), runAsync(nested, root),
      runAsync(nested, root), runAsync(nested, root), runAsync(nested, root),
    ]);

    // The exclusive create guarantees at most one writer. A concurrent parent
    // mkdir may legitimately lose the race and exit 1; never two winners.
    expect(statuses.filter((code) => code === 0)).toHaveLength(1);
    expect(statuses.every((code) => [0, 1, 3].includes(code))).toBe(true);
    expect(listFiles(root)).toEqual([SENTINEL_NAME, 'a/b/c/stripe.express.ts']);

    const written = fs.readFileSync(path.join(root, 'a', 'b', 'c', 'stripe.express.ts'), 'utf8');

    // Full byte equality, not a substring: a truncated write must not pass.
    expect(written).toBe(renderTemplate('stripe', 'express', { secretEnv: 'STRIPE_WEBHOOK_SECRET', bodyLimit: 1048576 }));
    assertSentinelUntouched(root);
  } finally { cleanup(root); }
});
