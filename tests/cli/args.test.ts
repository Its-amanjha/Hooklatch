import { parseArgs, HELP_TEXT } from '../../src/cli/args.js';

test('help on no args', () => {
  expect(parseArgs([])).toEqual({ kind: 'help' });
});

test('parses minimal valid command', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express']);
  expect(result).toEqual({
    kind: 'command',
    command: {
      provider: 'stripe',
      framework: 'express',
      out: 'hooklatch',
      secretEnv: 'STRIPE_WEBHOOK_SECRET',
      bodyLimit: 1048576,
      dryRun: false,
    },
  });
});

test('rejects unknown provider', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'nope', '--framework', 'express']);
  expect(result.kind).toBe('error');

  if (result.kind === 'error') expect(result.exitCode).toBe(2);
});

test('rejects duplicate flag', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--provider', 'github', '--framework', 'express']);
  expect(result.kind).toBe('error');
});

test('rejects missing value', () => {
  const result = parseArgs(['init', 'webhook', '--provider', '--framework', 'express']);
  expect(result.kind).toBe('error');
});

test('rejects unknown flag', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--foo', 'bar']);
  expect(result.kind).toBe('error');
});

test('rejects invalid body limit', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--body-limit', '0']);
  expect(result.kind).toBe('error');
});

test('rejects invalid secret env', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'stripe', '--framework', 'express', '--secret-env', '1BAD']);
  expect(result.kind).toBe('error');
});

test('dry run flag', () => {
  const result = parseArgs(['init', 'webhook', '--provider', 'github', '--framework', 'hono', '--dry-run']);
  expect(result.kind).toBe('command');

  if (result.kind === 'command') expect(result.command.dryRun).toBe(true);
});

test('help text mentions exit codes', () => {
  expect(HELP_TEXT).toContain('Exit codes');
});
