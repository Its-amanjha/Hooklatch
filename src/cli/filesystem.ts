import fs from 'node:fs';
import path from 'node:path';

export class CliError extends Error {
  readonly exitCode: number;
  constructor(exitCode: number, message: string) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
  }
}

/** Narrow an unknown thrown value to a Node error with an errno `code`. */
function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}

function rejectUnsafeSegment(segment: string): void {
  if (segment === '' || segment === '.' || segment === '..') {
    throw new CliError(2, 'Unsafe output path.');
  }

  if (segment.toLowerCase() === '.git' || segment.toLowerCase() === 'node_modules') {
    throw new CliError(2, 'Unsafe output path.');
  }

  if (segment.includes('\0')) {
    throw new CliError(2, 'Unsafe output path.');
  }

  // Windows reserved device names.
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(segment.replace(/\.[^.]*$/, ''))) {
    throw new CliError(2, 'Unsafe output path.');
  }
}

function splitPath(input: string): string[] {
  const normalized = input.replace(/\\/g, '/');
  const trimmed = normalized.replace(/\/+$/, '');

  if (trimmed.length === 0) throw new CliError(2, 'Unsafe output path.');
  const segments = trimmed.split('/');

  for (const segment of segments) rejectUnsafeSegment(segment);

  return segments;
}

export function validateOutDir(input: string): string[] {
  if (input.length === 0) {
    throw new CliError(2, 'Unsafe output path.');
  }

  if (input.includes('\0')) throw new CliError(2, 'Unsafe output path.');
  const normalized = input.replace(/\\/g, '/');

  if (path.isAbsolute(input) || /^[a-zA-Z]:/.test(input) || normalized.startsWith('//')) {
    throw new CliError(2, 'Unsafe output path.');
  }

  return splitPath(input);
}

export function targetFileName(provider: string, framework: string): string {
  if (framework === 'nextjs') return 'route.ts';

  if (framework === 'cloudflare') return `${provider}.cloudflare.ts`;

  if (framework === 'hono') return `${provider}.hono.ts`;

  if (framework === 'express') return `${provider}.express.ts`;
  throw new CliError(2, 'Unsupported framework.');
}

interface ResolvedOutput {
  readonly relativePath: string;
  readonly absolutePath: string;
}

export function resolveOutput(cwd: string, outDir: string, fileName: string): ResolvedOutput {
  const outSegments = validateOutDir(outDir);
  const fileSegments = [fileName];

  // validate file name segments too (no traversal)
  for (const segment of fileSegments) {
    if (segment.includes('/') || segment.includes('\\') || segment.includes('\0')) {
      throw new CliError(2, 'Unsafe output path.');
    }

    if (segment === '..' || segment === '.' || segment === '') throw new CliError(2, 'Unsafe output path.');
  }

  const relativeSegments = [...outSegments, ...fileSegments];
  const absolutePath = path.resolve(cwd, ...relativeSegments);
  const relativePath = relativeSegments.join('/');

  const relativeFromCwd = path.relative(cwd, absolutePath);

  if (relativeFromCwd === '' || relativeFromCwd.startsWith('..') || path.isAbsolute(relativeFromCwd)) {
    throw new CliError(2, 'Unsafe output path.');
  }

  // Check existing ancestors for symlinks/junctions/non-directories.
  let current = cwd;
  const ancestorSegments = relativeSegments.slice(0, -1);

  for (const segment of ancestorSegments) {
    current = path.join(current, segment);

    if (fs.existsSync(current)) {
      let stat: fs.Stats;

      try { stat = fs.lstatSync(current); } catch { throw new CliError(1, 'Unable to inspect output path.'); }

      if (stat.isSymbolicLink()) throw new CliError(2, 'Unsafe output path.');

      if (!stat.isDirectory()) throw new CliError(2, 'Unsafe output path.');
    }
  }

  // Existing target.
  if (fs.existsSync(absolutePath)) {
    let stat: fs.Stats;

    try { stat = fs.lstatSync(absolutePath); } catch { throw new CliError(1, 'Unable to inspect output path.'); }

    if (stat.isSymbolicLink()) throw new CliError(2, 'Unsafe output path.');
    throw new CliError(3, `Target file already exists: ${relativePath}`);
  }

  return { relativePath, absolutePath };
}

export function ensureParentDirectories(cwd: string, absoluteFilePath: string): void {
  const dir = path.dirname(absoluteFilePath);
  const relative = path.relative(cwd, dir);
  const segments = relative === '' ? [] : relative.split(path.sep);
  let current = cwd;

  for (const segment of segments) {
    current = path.join(current, segment);

    if (fs.existsSync(current)) {
      let stat: fs.Stats;

      try { stat = fs.lstatSync(current); } catch { throw new CliError(1, 'Unable to inspect output path.'); }

      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new CliError(2, 'Unsafe output path.');
      }
    } else {
      try { fs.mkdirSync(current); } catch { throw new CliError(1, 'Unable to create output directory.'); }
    }
  }
}

export function writeFileExclusive(filePath: string, content: string): void {
  let fd: number | undefined;
  let created = false;

  try {
    fd = fs.openSync(filePath, 'wx');
    created = true;
    fs.writeFileSync(fd, content, 'utf8');

    try { fs.fsyncSync(fd); } catch { /* best effort */ }
  } catch (error) {
    if (created && fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }

      fd = undefined;

      try { fs.unlinkSync(filePath); } catch { /* ignore */ }
    }

    if (isErrnoException(error) && error.code === 'EEXIST') {
      const relative = path.basename(filePath);
      throw new CliError(3, `Target file already exists: ${relative}`);
    }

    throw new CliError(1, 'Unable to write output file.');
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
  }
}
