/**
 * Phase 11 Node CommonJS emit (production).
 *
 * The canonical Node CommonJS graph is generated from the REAL `src/` TypeScript
 * sources of a checkout, never from compiled JavaScript copied out of a
 * candidate tarball:
 *
 *   staging/cjs-src   a `type: commonjs` copy of src/ (src/cli excluded) with a
 *                     pinned-TypeScript tsconfig using Node16/Node16 resolution
 *                     and the checkout's strict flags.
 *   staging/cjs       emitted .cjs modules and .d.cts declarations whose relative
 *                     module specifiers were rewritten from .js to .cjs with
 *                     edits bound to real TypeScript AST nodes, not regexes.
 *
 * This module also owns the graph validation that must pass BEFORE any output is
 * installed into `dist/cjs`, so an interrupted or incomplete emit can never be
 * reported as a successful build.
 */
import {
  cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  realpathSync, renameSync, rmdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export const STAGING_PREFIX = 'hooklatch-phase11-node-';
export const COMPILE_TIMEOUT_MS = 300000;
export const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
export const IS_WINDOWS = process.platform === 'win32';

/** Missing tool or missing original ESM output: exit 3, never a partial build. */
export class PrerequisiteError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'PrerequisiteError';
  }
}

/** A real build/validation failure: exit 1, outputs left as they were. */
export class BuildFailure extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'BuildFailure';
  }
}

export function toPosix(value) {
  return value.split(path.sep).join('/');
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/** Sorted, symlink-free file inventory. Ordering is part of determinism. */
export function walkFiles(root) {
  const files = [];

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const full = path.join(directory, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) files.push(full);
    }
  };

  visit(root);

  return files;
}

export function relativeFiles(root) {
  return walkFiles(root).map((file) => toPosix(path.relative(root, file)));
}

export function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function difference(left, right) {
  return left.filter((value) => !right.includes(value));
}

export function assertInsideTemp(target) {
  const resolved = path.resolve(target);
  const relative = path.relative(path.resolve(os.tmpdir()), resolved);
  const inside = relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);

  if (!inside) throw new BuildFailure(`Refusing to operate outside OS temp: ${resolved}`);

  return resolved;
}

/* ------------------------------------------------------------------ *
 * Pinned toolchain
 * ------------------------------------------------------------------ */

/** Resolve the checkout's installed TypeScript; absence is a blocked tool. */
export function loadTypeScript(repoRoot) {
  const manifest = path.join(repoRoot, 'package.json');

  if (!existsSync(manifest)) throw new PrerequisiteError(`No package.json in ${repoRoot}.`);

  const requireFromRepo = createRequire(pathToFileURL(manifest).href);

  try {
    return requireFromRepo('typescript');
  } catch (error) {
    throw new PrerequisiteError(`Pinned TypeScript is not installed: ${messageOf(error)}`);
  }
}

export function typescriptBinPath(repoRoot) {
  const bin = path.join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc');

  if (!existsSync(bin)) throw new PrerequisiteError(`Pinned TypeScript compiler missing: ${toPosix(path.relative(repoRoot, bin))}`);

  return bin;
}

/**
 * The temp compile scope resolves peer TYPE imports through one read-only link
 * into the checkout's dependency tree. The link itself is ledgered before it is
 * created and is unlinked directly (never followed) during cleanup.
 */
export function assertCompileDependencies(repoRoot) {
  const required = ['node_modules', 'node_modules/typescript', 'node_modules/@types/express', 'node_modules/hono'];
  const missing = required.filter((relative) => !existsSync(path.join(repoRoot, relative)));

  if (missing.length > 0) throw new PrerequisiteError(`Compile dependencies missing (read-only tree): ${missing.join(', ')}`);
}

/* ------------------------------------------------------------------ *
 * Original neutral/Workers ESM prerequisites
 * ------------------------------------------------------------------ */

/**
 * The additive Node distribution sits on top of the existing ESM build. Both
 * required outputs are checked before anything is created, so a missing ESM
 * build blocks (exit 3) without touching dist/cjs or dist/node.
 */
export function assertOriginalEsmOutput(repoRoot, entryBases) {
  const required = ['index.js', 'index.d.ts', 'cli/index.js'];

  for (const base of entryBases) required.push(`${base}.js`, `${base}.d.ts`);

  const missing = required.filter((relative) => !existsSync(path.join(repoRoot, 'dist', relative)));

  if (missing.length > 0) {
    throw new PrerequisiteError(`Original ESM output missing from dist/: ${missing.join(', ')}; run npm run build first`);
  }

  return required;
}

/* ------------------------------------------------------------------ *
 * Source inventory
 * ------------------------------------------------------------------ */

export function collectSourceModules(sourceRoot) {
  if (!existsSync(sourceRoot)) throw new PrerequisiteError(`Source tree missing: ${sourceRoot}`);

  const modules = [];

  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const full = path.join(directory, entry.name);

      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
        modules.push(toPosix(path.relative(sourceRoot, full)).slice(0, -'.ts'.length));
      }
    }
  };

  visit(sourceRoot);

  if (modules.length === 0) throw new PrerequisiteError(`No TypeScript sources under ${sourceRoot}.`);

  return modules.sort();
}

/* ------------------------------------------------------------------ *
 * Staging scope with an authoritative link ledger
 * ------------------------------------------------------------------ */

export function createStagingRoot() {
  const root = mkdtempSync(path.join(os.tmpdir(), STAGING_PREFIX));

  assertInsideTemp(root);

  if (!path.basename(root).startsWith(STAGING_PREFIX)) throw new BuildFailure(`Unexpected staging name: ${root}`);

  return { root, links: [] };
}

/** Ledger a link BEFORE creating it so a mid-step failure cannot hide it. */
export function trackStagingLink(stagingRoot, linkPath) {
  const resolved = path.resolve(linkPath);
  const relative = path.relative(stagingRoot.root, resolved);

  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new BuildFailure(`Refusing to track a link outside staging: ${resolved}`);
  }

  if (stagingRoot.links.includes(resolved)) throw new BuildFailure(`Link already tracked: ${resolved}`);

  stagingRoot.links.push(resolved);

  return resolved;
}

/**
 * Remove only the links this build created, then the staging root. Removal of
 * the root is gated on an absolute OS-temp path and the staging prefix.
 */
export function disposeStagingRoot(stagingRoot) {
  const resolved = assertInsideTemp(stagingRoot.root);

  if (!path.basename(resolved).startsWith(STAGING_PREFIX)) throw new BuildFailure(`Refusing to remove a non-staging root: ${resolved}`);

  const failures = [];

  for (const link of stagingRoot.links) {
    try {
      const stat = lstatSync(link, { throwIfNoEntry: false });

      if (stat === undefined) continue;

      if (!stat.isSymbolicLink()) throw new BuildFailure(`Expected a link at ${link}; refusing to remove an ordinary path.`);

      try {
        unlinkSync(link);
      } catch {
        rmdirSync(link);
      }

      if (existsSync(link)) throw new BuildFailure(`Failed to unlink ${link}.`);
    } catch (error) {
      failures.push(`unlink ${link}: ${messageOf(error)}`);
    }
  }

  if (failures.length === 0) {
    try {
      rmSync(resolved, { recursive: true, force: true });
    } catch (error) {
      failures.push(`remove ${resolved}: ${messageOf(error)}`);
    }

    if (existsSync(resolved)) failures.push(`staging root still present: ${resolved}`);
  }

  if (failures.length > 0) throw new BuildFailure(`Staging cleanup failed: ${failures.join('; ')}`);

  return { removed: true, linksUnlinked: stagingRoot.links.length };
}

/* ------------------------------------------------------------------ *
 * TypeScript invocation
 * ------------------------------------------------------------------ */

export function extractDiagnostics(text) {
  const lines = [];

  for (const match of text.matchAll(/([^\r\n]*\berror TS\d{4}\b[^\r\n]*)/g)) lines.push(match[1].trim());

  return [...new Set(lines)].slice(0, 20);
}

/** Bounded compiler child: a timeout, signal or output flood is never a pass. */
export function runTypeScript(typescriptBin, configPath, timeoutMs = COMPILE_TIMEOUT_MS) {
  return new Promise((done) => {
    const evidence = {
      exitCode: null, signal: null, stdout: '', stderr: '', timedOut: false,
      outputLimitExceeded: false, spawnError: null, closeConfirmed: false,
    };

    let bytes = 0;
    let settled = false;
    let closeDeadline;

    const child = spawn(process.execPath, [typescriptBin, '-p', configPath], {
      cwd: path.dirname(configPath), windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'],
    });

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(closeDeadline);
      evidence.diagnostics = extractDiagnostics(`${evidence.stdout}\n${evidence.stderr}`);
      evidence.ok = evidence.exitCode === 0 && evidence.signal === null && !evidence.timedOut
        && !evidence.outputLimitExceeded && evidence.spawnError === null && evidence.closeConfirmed;
      done(evidence);
    };

    const stop = () => {
      clearTimeout(timer);
      child.kill('SIGKILL');
      closeDeadline = setTimeout(() => {
        evidence.spawnError ??= 'child-close-not-confirmed';
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
        finish();
      }, 10000);
    };

    const timer = setTimeout(() => {
      evidence.timedOut = true;
      stop();
    }, timeoutMs);

    const capture = (field, chunk) => {
      bytes += chunk.length;

      if (bytes > MAX_OUTPUT_BYTES) {
        if (!evidence.outputLimitExceeded) {
          evidence.outputLimitExceeded = true;
          stop();
        }

        return;
      }

      evidence[field] += chunk.toString('utf8');
    };

    child.stdout.on('data', (chunk) => capture('stdout', chunk));
    child.stderr.on('data', (chunk) => capture('stderr', chunk));
    child.on('error', (error) => {
      evidence.spawnError = error.message;

      if (child.pid === undefined) evidence.closeConfirmed = true;

      finish();
    });
    child.on('close', (code, signal) => {
      evidence.exitCode = code;
      evidence.signal = signal;
      evidence.closeConfirmed = true;
      finish();
    });
  });
}

/* ------------------------------------------------------------------ *
 * Compiler scope
 * ------------------------------------------------------------------ */

/** The strict flags of the checkout plus the CJS module format. */
export function commonJsCompilerOptions(sourceDir, outDir) {
  return {
    target: 'ES2022',
    module: 'Node16',
    moduleResolution: 'Node16',
    lib: ['ES2022', 'DOM', 'DOM.Iterable'],
    types: [],
    strict: true,
    noUncheckedIndexedAccess: true,
    exactOptionalPropertyTypes: true,
    verbatimModuleSyntax: false,
    declaration: true,
    declarationMap: false,
    sourceMap: false,
    noEmitOnError: true,
    outDir: toPosix(outDir),
    rootDir: toPosix(sourceDir),
    skipLibCheck: true,
  };
}

/**
 * Copy the real sources into an owned `type: commonjs` scope and emit CommonJS.
 * The checkout's src/ and tsconfig files are never written to.
 */
export async function emitCommonJsModules(options) {
  const { repoRoot, stagingRoot, typescriptBin, timeoutMs = COMPILE_TIMEOUT_MS } = options;
  const sourceRoot = path.join(repoRoot, 'src');

  if (!existsSync(sourceRoot)) throw new PrerequisiteError('No src/ tree to compile.');

  const scopeRoot = path.join(stagingRoot.root, 'scope');
  const sourceDir = path.join(scopeRoot, 'cjs-src');
  const outDir = path.join(stagingRoot.root, 'cjs');

  mkdirSync(scopeRoot, { recursive: true });
  cpSync(sourceRoot, sourceDir, { recursive: true });
  rmSync(path.join(sourceDir, 'cli'), { recursive: true, force: true });
  writeFileSync(path.join(sourceDir, 'package.json'), `${JSON.stringify({ type: 'commonjs' })}\n`);

  const linkPath = trackStagingLink(stagingRoot, path.join(scopeRoot, 'node_modules'));

  mkdirSync(path.dirname(linkPath), { recursive: true });
  symlinkSync(realpathSync(path.join(repoRoot, 'node_modules')), linkPath, IS_WINDOWS ? 'junction' : 'dir');

  const configPath = path.join(scopeRoot, 'tsconfig.cjs.json');

  const config = {
    compilerOptions: commonJsCompilerOptions(sourceDir, outDir),
    include: [`${toPosix(sourceDir)}/**/*.ts`],
  };

  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);

  const modules = collectSourceModules(sourceDir);
  const compile = await runTypeScript(typescriptBin, configPath, timeoutMs);

  if (!compile.ok) {
    const detail = compile.diagnostics.length > 0
      ? compile.diagnostics.join(' | ')
      : `${compile.spawnError ?? 'no diagnostic'}; exit=${String(compile.exitCode)} signal=${String(compile.signal)} timedOut=${String(compile.timedOut)}`;

    throw new BuildFailure(`CommonJS emit failed: ${detail}`);
  }

  const renamed = renameAndRewriteOutputs(loadTypeScript(repoRoot), outDir);

  return { sourceDir, outDir, modules, renamed, compile: { exitCode: compile.exitCode, diagnostics: compile.diagnostics.length } };
}

function renameAndRewriteOutputs(typescript, outDir) {
  if (!existsSync(outDir)) throw new BuildFailure('CommonJS emit produced no output directory.');

  const files = walkFiles(outDir);
  const unexpected = files.filter((file) => !file.endsWith('.js') && !file.endsWith('.d.ts'));

  if (unexpected.length > 0) {
    throw new BuildFailure(`Unexpected emit artifacts (maps or incremental state are not part of this graph): ${unexpected.map((file) => path.basename(file)).join(', ')}`);
  }

  const renamed = { runtime: 0, declarations: 0 };
  const rewritten = { runtime: 0, declarations: 0 };

  for (const file of files.filter((candidate) => candidate.endsWith('.d.ts'))) {
    const next = `${file.slice(0, -'.d.ts'.length)}.d.cts`;

    renameSync(file, next);
    renamed.declarations += 1;
    rewritten.declarations += rewriteModuleSpecifiers(typescript, next, 'declaration').rewritten;
  }

  for (const file of files.filter((candidate) => candidate.endsWith('.js'))) {
    const next = `${file.slice(0, -'.js'.length)}.cjs`;

    renameSync(file, next);
    renamed.runtime += 1;
    rewritten.runtime += rewriteModuleSpecifiers(typescript, next, 'runtime').rewritten;
  }

  return { renamed, rewritten };
}

/* ------------------------------------------------------------------ *
 * AST-bound specifier rewriting
 * ------------------------------------------------------------------ */

function isRequireCall(typescript, node) {
  return typescript.isCallExpression(node)
    && typescript.isIdentifier(node.expression)
    && node.expression.text === 'require';
}

export function isRelativeSpecifier(text) {
  return text.startsWith('./') || text.startsWith('../');
}

/**
 * Only real module-specifier positions are returned. An ordinary string literal
 * that happens to look like `'./never-rewrite.js'` is not a module specifier and
 * therefore never enters this list.
 */
export function moduleSpecifierLiterals(typescript, sourceFile) {
  const literals = [];

  const visit = (node) => {
    if (typescript.isImportDeclaration(node) && typescript.isStringLiteral(node.moduleSpecifier)) {
      literals.push(node.moduleSpecifier);
    } else if (typescript.isExportDeclaration(node) && node.moduleSpecifier !== undefined && typescript.isStringLiteral(node.moduleSpecifier)) {
      literals.push(node.moduleSpecifier);
    } else if (typescript.isImportEqualsDeclaration(node)
      && typescript.isExternalModuleReference(node.moduleReference)
      && node.moduleReference.expression !== undefined
      && typescript.isStringLiteral(node.moduleReference.expression)) {
      literals.push(node.moduleReference.expression);
    } else if (typescript.isImportTypeNode(node)
      && typescript.isLiteralTypeNode(node.argument)
      && typescript.isStringLiteral(node.argument.literal)) {
      literals.push(node.argument.literal);
    } else if ((isRequireCall(typescript, node)
      || (typescript.isCallExpression(node) && node.expression.kind === typescript.SyntaxKind.ImportKeyword))
      && node.arguments.length === 1
      && typescript.isStringLiteral(node.arguments[0])) {
      literals.push(node.arguments[0]);
    } else if (typescript.isModuleDeclaration(node) && typescript.isStringLiteral(node.name)) {
      literals.push(node.name);
    }

    typescript.forEachChild(node, visit);
  };

  visit(sourceFile);

  return literals;
}

/**
 * Rewrite `.js` -> `.cjs` ONLY on AST-identified relative module specifiers.
 * Each edit replaces the inside of the original string literal at its own node
 * range, so quoting, formatting, source mapping comments and ordinary strings
 * are untouched.
 */
export function rewriteModuleSpecifiers(typescript, filePath, kind) {
  const source = readFileSync(filePath, 'utf8');
  const scriptKind = kind === 'declaration' ? typescript.ScriptKind.TS : typescript.ScriptKind.JS;
  const sourceFile = typescript.createSourceFile(filePath, source, typescript.ScriptTarget.ES2022, true, scriptKind);
  const literals = moduleSpecifierLiterals(typescript, sourceFile);
  const edits = [];

  for (const literal of literals) {
    const text = literal.text;

    if (!isRelativeSpecifier(text) || !text.endsWith('.js')) continue;

    const start = literal.getStart(sourceFile);
    const end = literal.getEnd();
    const raw = source.slice(start, end);
    const quote = raw.slice(0, 1);

    if ((quote !== '"' && quote !== "'") || raw.slice(-1) !== quote) {
      throw new BuildFailure(`Module specifier at ${path.basename(filePath)} is not a plain quoted literal.`);
    }

    edits.push({ start, end, text: `${quote}${text.slice(0, -'.js'.length)}.cjs${quote}` });
  }

  if (edits.length === 0) return { rewritten: 0, specifiers: literals.length };

  const ordered = [...edits].sort((left, right) => right.start - left.start);
  let next = source;

  for (const edit of ordered) next = `${next.slice(0, edit.start)}${edit.text}${next.slice(edit.end)}`;

  if (next === source) throw new BuildFailure(`Specifier rewrite produced no change for ${path.basename(filePath)}.`);

  writeFileSync(filePath, next);

  return { rewritten: edits.length, specifiers: literals.length };
}

/* ------------------------------------------------------------------ *
 * Graph validation (must pass BEFORE installation)
 * ------------------------------------------------------------------ */

function isInsideRoot(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));

  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

/**
 * Validate one generated CommonJS graph:
 *  - every relative runtime edge ends `.cjs` and resolves to an existing file
 *    INSIDE the canonical graph (never an original ESM `.js` module);
 *  - every relative declaration edge resolves to the matching `.d.cts`;
 *  - no emitted `.cjs` contains ESM syntax;
 *  - the only bare runtime specifiers are Node builtins (core stays zero-dep).
 */
export function validateCommonJsGraph(typescript, cjsRoot) {
  const report = {
    root: cjsRoot, files: 0, runtimeFiles: 0, declarationFiles: 0,
    runtimeEdges: 0, declarationEdges: 0, unresolved: [], stale: [], escapes: [],
    esmSyntax: [], unexpectedFiles: [], externalRuntimeSpecifiers: [],
  };

  if (!existsSync(cjsRoot)) return { ...report, ok: false, missingRoot: true };

  for (const file of walkFiles(cjsRoot)) {
    const relative = toPosix(path.relative(cjsRoot, file));

    if (file.endsWith('.cjs')) {
      report.runtimeFiles += 1;
      inspectRuntimeModule(typescript, cjsRoot, file, relative, report);
    } else if (file.endsWith('.d.cts')) {
      report.declarationFiles += 1;
      inspectDeclarationModule(typescript, cjsRoot, file, relative, report);
    } else {
      report.unexpectedFiles.push(relative);
    }
  }

  report.files = report.runtimeFiles + report.declarationFiles + report.unexpectedFiles.length;
  report.ok = report.runtimeFiles > 0 && report.declarationFiles > 0
    && report.unresolved.length === 0 && report.stale.length === 0
    && report.escapes.length === 0 && report.esmSyntax.length === 0
    && report.unexpectedFiles.length === 0 && report.externalRuntimeSpecifiers.length === 0;

  return report;
}

function inspectRuntimeModule(typescript, cjsRoot, file, relative, report) {
  const source = readFileSync(file, 'utf8');
  const sourceFile = typescript.createSourceFile(file, source, typescript.ScriptTarget.ES2022, true, typescript.ScriptKind.JS);

  const inspectDynamic = (node) => {
    if (typescript.isCallExpression(node)
      && (isRequireCall(typescript, node) || node.expression.kind === typescript.SyntaxKind.ImportKeyword)
      && (node.arguments.length !== 1 || !typescript.isStringLiteral(node.arguments[0]))) {
      report.externalRuntimeSpecifiers.push({ file: relative, specifier: '<unprovable module edge>' });
    }

    typescript.forEachChild(node, inspectDynamic);
  };

  inspectDynamic(sourceFile);

  for (const statement of sourceFile.statements) {
    if (typescript.isImportDeclaration(statement) || typescript.isExportDeclaration(statement)) {
      report.esmSyntax.push(relative);
      break;
    }
  }

  for (const literal of moduleSpecifierLiterals(typescript, sourceFile)) {
    const specifier = literal.text;

    if (!isRelativeSpecifier(specifier)) {
      report.externalRuntimeSpecifiers.push({ file: relative, specifier });

      continue;
    }

    report.runtimeEdges += 1;

    if (!specifier.endsWith('.cjs')) {
      report.stale.push({ file: relative, specifier });

      continue;
    }

    const target = path.resolve(path.dirname(file), specifier);

    if (!isInsideRoot(cjsRoot, target)) report.escapes.push({ file: relative, specifier });
    else if (!existsSync(target)) report.unresolved.push({ file: relative, specifier, target: toPosix(path.relative(cjsRoot, target)) });
  }
}

function inspectDeclarationModule(typescript, cjsRoot, file, relative, report) {
  const source = readFileSync(file, 'utf8');
  const sourceFile = typescript.createSourceFile(file, source, typescript.ScriptTarget.ES2022, true, typescript.ScriptKind.TS);

  for (const literal of moduleSpecifierLiterals(typescript, sourceFile)) {
    const specifier = literal.text;

    if (!isRelativeSpecifier(specifier)) continue;

    report.declarationEdges += 1;

    if (!specifier.endsWith('.cjs')) {
      report.stale.push({ file: relative, specifier });

      continue;
    }

    const target = path.resolve(path.dirname(file), `${specifier.slice(0, -'.cjs'.length)}.d.cts`);

    if (!isInsideRoot(cjsRoot, target)) report.escapes.push({ file: relative, specifier });
    else if (!existsSync(target)) report.unresolved.push({ file: relative, specifier, target: toPosix(path.relative(cjsRoot, target)) });
  }
}

/**
 * One module per emitted runtime file and per declaration file, mirroring the
 * source inventory exactly. No per-entry bundles, no missing modules.
 */
export function compareModuleInventory(modules, cjsRoot) {
  const present = relativeFiles(cjsRoot);
  const runtime = present.filter((file) => file.endsWith('.cjs')).map((file) => file.slice(0, -'.cjs'.length)).sort();
  const declarations = present.filter((file) => file.endsWith('.d.cts')).map((file) => file.slice(0, -'.d.cts'.length)).sort();
  const expected = [...modules].sort();
  const unexpected = present.filter((file) => !file.endsWith('.cjs') && !file.endsWith('.d.cts'));

  return {
    ok: sameStrings(runtime, expected) && sameStrings(declarations, expected) && unexpected.length === 0,
    expected: expected.length,
    runtime: runtime.length,
    declarations: declarations.length,
    missingRuntime: difference(expected, runtime),
    extraRuntime: difference(runtime, expected),
    missingDeclarations: difference(expected, declarations),
    extraDeclarations: difference(declarations, expected),
    unexpected,
  };
}

/** No generated byte may embed an author checkout or staging path. */
export function findAbsolutePathLeaks(root, forbiddenPrefixes) {
  const leaks = [];

  for (const file of walkFiles(root)) {
    if (!file.endsWith('.cjs') && !file.endsWith('.d.cts') && !file.endsWith('.js') && !file.endsWith('.d.ts')) continue;

    const text = readFileSync(file, 'utf8');

    for (const prefix of forbiddenPrefixes) {
      if (prefix.length > 0 && text.includes(prefix)) leaks.push({ file: toPosix(path.relative(root, file)), prefix });
    }
  }

  return leaks;
}
