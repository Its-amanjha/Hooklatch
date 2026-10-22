import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

assert(process.env.npm_execpath, 'Run via npm run verify.');

for (const script of ['lint', 'typecheck', 'typecheck:workers', 'build',
  'typecheck:examples', 'test:coverage', 'test:workers', 'test:package', 'test:templates', 'test:provider-config', 'test:configured-templates', 'test:mutations', 'test:public-contracts']) {
  const result = spawnSync(process.execPath, [process.env.npm_execpath, 'run', script], { stdio: 'inherit' });

  if (result.error) throw result.error;

  if (result.status !== 0) process.exit(result.status ?? 1);
}

console.log('PASS: all local verification gates.');
