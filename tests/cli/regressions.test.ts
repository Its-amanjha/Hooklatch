import ts from 'typescript';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs, FRAMEWORKS } from '../../src/cli/args.js';
import { renderTemplate } from '../../src/cli/templates.js';
import { validateOutDir, resolveOutput, writeFileExclusive } from '../../src/cli/filesystem.js';
import { SUPPORTED_PROVIDERS } from '../../src/providers/index.js';

test.each(SUPPORTED_PROVIDERS.flatMap((provider) => FRAMEWORKS.map((framework) => [provider, framework] as const)))(
  '%s/%s generates syntactically valid TypeScript', (provider, framework) => {
    const credentials = provider === 'fal'
      ? { publicKeyEnv: 'TEST_PUBLIC_KEYS', expectedUserEnv: 'TEST_USER_ID', bodyLimit: 1024 }
      : { secretEnv: 'TEST_SECRET', bodyLimit: 1024 };

    const content = renderTemplate(provider, framework, credentials);

    const output = ts.transpileModule(content, {
      reportDiagnostics: true,
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    });

    expect(output.diagnostics?.map((diagnostic) => diagnostic.code)).toEqual([]);
  },
);

test('rejects dangling junction ancestors and targets during dry-run validation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-dangling-'));

  try {
    const destination = path.join(root, 'destination');
    fs.mkdirSync(destination);
    fs.symlinkSync(destination, path.join(root, 'link'), 'junction');
    fs.rmdirSync(destination);
    expect(() => resolveOutput(root, 'link', 'route.ts')).toThrow(expect.objectContaining({ exitCode: 2 }));
    fs.mkdirSync(path.join(root, 'out'));
    fs.symlinkSync(destination, path.join(root, 'out', 'route.ts'), 'junction');
    expect(() => resolveOutput(root, 'out', 'route.ts')).toThrow(expect.objectContaining({ exitCode: 2 }));
  } finally {
    expect(root.startsWith(os.tmpdir() + path.sep)).toBe(true);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('failed writes leave their owned file and never unlink a target pathname', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hooklatch-write-failure-'));

  try {
    const target = path.join(root, 'route.ts');
    // SAFETY: Invalid content forces a real fs write failure after exclusive creation.
    expect(() => writeFileExclusive(target, undefined as never)).toThrow(expect.objectContaining({ exitCode: 1 }));
    expect(fs.readFileSync(target, 'utf8')).toBe('');
    expect(() => writeFileExclusive(target, 'replacement')).toThrow(expect.objectContaining({ exitCode: 3 }));
    expect(fs.readFileSync(target, 'utf8')).toBe('');
  } finally {
    expect(root.startsWith(os.tmpdir() + path.sep)).toBe(true);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test.each([
  ['--provider', 'PRIVATE_CANARY', '--framework', 'express'],
  ['--provider', 'stripe', '--framework', 'PRIVATE_CANARY'],
  ['--PRIVATE_CANARY'],
])('does not echo invalid arguments: %p', (...args) => {
  const result = parseArgs(['init', 'webhook', ...args]);
  expect(result.kind).toBe('error');
  expect(JSON.stringify(result)).not.toContain('PRIVATE_CANARY');
});

test.each(['CON.foo.bar', 'NUL.foo.bar', '.git.', 'node_modules ', 'folder:stream', 'folder\nname'])(
  'rejects platform aliases and invalid components: %s', (out) => {
    expect(() => validateOutDir(out)).toThrow();
  },
);
