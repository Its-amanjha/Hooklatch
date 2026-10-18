import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveOutput, validateOutDir, writeFileExclusive, ensureParentDirectories, CliError } from '../../src/cli/filesystem.js';

test('validateOutDir rejects traversal', () => {
  expect(() => validateOutDir('../escape')).toThrow(CliError);
  expect(() => validateOutDir('a/../b')).toThrow(CliError);
});

test('validateOutDir rejects absolute and drive paths', () => {
  expect(() => validateOutDir('/abs')).toThrow(CliError);
  expect(() => validateOutDir('C:\\tmp')).toThrow(CliError);
});

test('validateOutDir allows spaces and unicode', () => {
  expect(validateOutDir('my dir/ünicode')).toEqual(['my dir', 'ünicode']);
});

test('resolveOutput rejects existing file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const file = path.join(root, 'hooklatch', 'stripe.express.ts');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, 'x');
    expect(() => resolveOutput(root, 'hooklatch', 'stripe.express.ts')).toThrow(CliError);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('resolveOutput rejects symlink ancestor', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const link = path.join(root, 'link');
    fs.symlinkSync(root, link, 'junction');
    expect(() => resolveOutput(root, 'link/sub', 'route.ts')).toThrow(CliError);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('writeFileExclusive refuses overwrite', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const file = path.join(root, 'a.ts');
    fs.writeFileSync(file, 'old');
    expect(() => writeFileExclusive(file, 'new')).toThrow(CliError);
    expect(fs.readFileSync(file, 'utf8')).toBe('old');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('writeFileExclusive writes new file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const file = path.join(root, 'a.ts');
    writeFileExclusive(file, 'content');
    expect(fs.readFileSync(file, 'utf8')).toBe('content');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ensureParentDirectories creates dirs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const file = path.join(root, 'a', 'b', 'c.ts');
    ensureParentDirectories(root, file);
    expect(fs.existsSync(path.join(root, 'a', 'b'))).toBe(true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
