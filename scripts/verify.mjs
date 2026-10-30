import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

assert(process.env.npm_execpath, 'Run via npm run verify.');

for (const script of ['lint', 'build', 'typecheck', 'typecheck:workers',
  'typecheck:examples', 'test:coverage', 'test:workers', 'test:package', 'test:templates', 'test:provider-config', 'test:configured-templates', 'test:crypto-runtime', 'test:mutations', 'test:public-contracts', 'test:docs-contract', 'test:evidence', 'test:release-readiness', 'test:api-freeze', 'test:generated-runtime', 'test:node-distribution', 'test:compat-package', 'test:compat-types', 'test:compat-runtime', 'test:compat-frameworks']) {
  const result = spawnSync(process.execPath, [process.env.npm_execpath, 'run', script], { stdio: 'inherit' });

  if (result.error) throw result.error;

  if (result.status !== 0) process.exit(result.status ?? 1);
}

console.log('PASS: all local verification gates.');
