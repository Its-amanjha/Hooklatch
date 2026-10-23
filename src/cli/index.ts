#!/usr/bin/env node

import { parseArgs, HELP_TEXT } from './args.js';
import { renderTemplate } from './templates.js';
import type { TemplateOptions } from './templates.js';
import { resolveOutput, targetFileName, ensureParentDirectories, writeFileExclusive, CliError } from './filesystem.js';

function main(): void {
  const result = parseArgs(process.argv.slice(2));

  if (result.kind === 'help') {
    process.stdout.write(HELP_TEXT);

    return;
  }

  if (result.kind === 'error') {
    process.stderr.write(`${result.message}\n`);
    process.exitCode = result.exitCode;

    return;
  }

  const command = result.command;
  const fileName = targetFileName(command.provider, command.framework);
  let resolved;

  try {
    resolved = resolveOutput(process.cwd(), command.out, fileName);
  } catch (error) {
    const message = error instanceof CliError ? error.message : 'Unable to inspect output path.';
    const exitCode = error instanceof CliError ? error.exitCode : 2;

    process.stderr.write(`${message}\n`);
    process.exitCode = exitCode;

    return;
  }

  let templateOptions: TemplateOptions;

  if (command.publicKeyEnv !== undefined && command.expectedUserEnv !== undefined) {
    if (command.providerOptions === undefined) {
      templateOptions = {
        publicKeyEnv: command.publicKeyEnv,
        expectedUserEnv: command.expectedUserEnv,
        bodyLimit: command.bodyLimit,
      };
    } else {
      templateOptions = {
        publicKeyEnv: command.publicKeyEnv,
        expectedUserEnv: command.expectedUserEnv,
        bodyLimit: command.bodyLimit,
        providerOptions: command.providerOptions,
      };
    }
  } else {
    templateOptions = command.providerOptions === undefined
      ? { secretEnv: command.secretEnv, bodyLimit: command.bodyLimit }
      : {
        secretEnv: command.secretEnv,
        bodyLimit: command.bodyLimit,
        providerOptions: command.providerOptions,
      };
  }

  const content = renderTemplate(command.provider, command.framework, templateOptions);

  if (command.dryRun) {
    process.stdout.write(`${resolved.relativePath}\n${content}`);

    return;
  }

  try {
    ensureParentDirectories(process.cwd(), resolved.absolutePath);
    writeFileExclusive(resolved.absolutePath, content);
  } catch (error) {
    const message = error instanceof CliError ? error.message : 'Unable to write output file.';
    const exitCode = error instanceof CliError ? error.exitCode : 1;

    process.stderr.write(`${message}\n`);
    process.exitCode = exitCode;

    return;
  }

  process.stdout.write(`Created ${resolved.relativePath}\n`);
}

try {
  main();
} catch {
  process.stderr.write('Unexpected error.\n');
  process.exitCode = 1;
}
