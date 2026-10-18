import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CLI = path.resolve(process.cwd(), 'dist', 'cli', 'index.js');

interface CliRunResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function run(args: string[], cwd: string): CliRunResult {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function hashTree(root: string): string {
  const files: string[] = [];

  function walk(dir: string): void {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) walk(full);
      else files.push(full);
    }
  }

  if (fs.existsSync(root)) walk(root);
  files.sort();

  return files.map((file) => `${path.relative(root, file)}:${fs.readFileSync(file)}`).join('\n');
}

test('help exits 0', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const result = run(['--help'], root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Exit codes');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dry run prints path and contents without writing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const result = run(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--dry-run'], root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('hooklatch/stripe.express.ts');
    expect(result.stdout).toContain('createWebhookMiddleware');
    expect(fs.existsSync(path.join(root, 'hooklatch'))).toBe(false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('successful write creates one file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const result = run(['init', 'webhook', '--provider', 'stripe', '--framework', 'express'], root);
    expect(result.status).toBe(0);
    const file = path.join(root, 'hooklatch', 'stripe.express.ts');
    expect(fs.existsSync(file)).toBe(true);
    expect(fs.readFileSync(file, 'utf8')).toContain('createWebhookMiddleware');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('invalid args do not write', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const before = hashTree(root);
    const result = run(['init', 'webhook', '--provider', 'stripe'], root);
    expect(result.status).toBe(2);
    expect(hashTree(root)).toBe(before);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('existing file conflict exits 3 and preserves file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const dir = path.join(root, 'hooklatch');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'stripe.express.ts');
    fs.writeFileSync(file, 'ORIGINAL');
    const result = run(['init', 'webhook', '--provider', 'stripe', '--framework', 'express'], root);
    expect(result.status).toBe(3);
    expect(fs.readFileSync(file, 'utf8')).toBe('ORIGINAL');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('spaces and unicode output path', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const out = 'my dir/ünicode';
    const result = run(['init', 'webhook', '--provider', 'github', '--framework', 'hono', '--out', out], root);
    expect(result.status).toBe(0);
    const file = path.join(root, 'my dir', 'ünicode', 'github.hono.ts');
    expect(fs.existsSync(file)).toBe(true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('path traversal exits 2', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const result = run(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--out', '../escape'], root);
    expect(result.status).toBe(2);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('nextjs writes route.ts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const result = run(['init', 'webhook', '--provider', 'clerk', '--framework', 'nextjs', '--out', 'app/api/webhooks/clerk'], root);
    expect(result.status).toBe(0);
    const file = path.join(root, 'app', 'api', 'webhooks', 'clerk', 'route.ts');
    expect(fs.existsSync(file)).toBe(true);
    expect(fs.readFileSync(file, 'utf8')).toContain('export const POST');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function runAsync(args: string[], cwd: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, stdio: 'ignore' });

    child.on('exit', (code) => resolve(code ?? 1));
  });
}

test('concurrent writers: exactly one wins, file never corrupted', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));

  try {
    const args = ['init', 'webhook', '--provider', 'stripe', '--framework', 'express'];
    const statuses = await Promise.all([runAsync(args, root), runAsync(args, root)]);

    // Exactly one process succeeds; the loser exits 3 (existing target) or,
    // in a narrow parent-directory race, 1 (mkdir failed). Never two writers.
    expect(statuses.filter((code) => code === 0)).toHaveLength(1);
    expect(statuses.every((code) => code === 0 || code === 1 || code === 3)).toBe(true);
    const file = path.join(root, 'hooklatch', 'stripe.express.ts');
    expect(fs.readFileSync(file, 'utf8')).toContain('createWebhookMiddleware');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
