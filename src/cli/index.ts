#!/usr/bin/env node

import { parseArgs, HELP_TEXT } from './args.js';
import { renderTemplate } from './templates.js';
import { resolveOutput, targetFileName, ensureParentDirectories, writeFileExclusive, CliError } from './filesystem.js';

function main(): void {
  const result = parseArgs(process.argv.slice(2));

  if (result.kind === 'help') {
    process.stdout.write(HELP_TEXT);
    process.exit(0);
  }

  if (result.kind === 'error') {
    process.stderr.write(`${result.message}\n`);
    process.exit(result.exitCode);
  }

  const command = result.command;
  const fileName = targetFileName(command.provider, command.framework);
  let resolved;

  try {
    resolved = resolveOutput(process.cwd(), command.out, fileName);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unsafe output path.';
    const exitCode = error instanceof CliError ? error.exitCode : 2;

    process.stderr.write(`${message}\n`);
    process.exit(exitCode);
  }

  const content = renderTemplate(command.provider, command.framework, {
    secretEnv: command.secretEnv,
    bodyLimit: command.bodyLimit,
  });

  if (command.dryRun) {
    process.stdout.write(`${resolved.relativePath}\n${content}`);
    process.exit(0);
  }

  try {
    ensureParentDirectories(process.cwd(), resolved.absolutePath);
    writeFileExclusive(resolved.absolutePath, content);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to write output file.';
    const exitCode = error instanceof CliError ? error.exitCode : 1;

    process.stderr.write(`${message}\n`);
    process.exit(exitCode);
  }

  process.stdout.write(`Created ${resolved.relativePath}\n`);
  process.exit(0);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unexpected error.';

  process.stderr.write(`${message}\n`);
  process.exit(1);
}
