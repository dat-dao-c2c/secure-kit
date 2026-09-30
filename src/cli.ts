#!/usr/bin/env node
import { readFileSync } from 'fs';
import { basename } from 'path';
import { run, DEFAULT_PROGRAM_NAME, PROGRAM_NAMES } from './cli/run.js';

declare const __SECRET_KIT_VERSION__: string | undefined;

const version = typeof __SECRET_KIT_VERSION__ === 'string' ? __SECRET_KIT_VERSION__ : 'dev';

// npm links both bin names to this file; show whichever name the user typed.
// Windows shims invoke the file directly ("cli.js"), so fall back to the default.
const invokedAs = basename(process.argv[1] ?? '').replace(/\.(c|m)?js$/, '');
const programName = (PROGRAM_NAMES as readonly string[]).includes(invokedAs) ? invokedAs : DEFAULT_PROGRAM_NAME;

function readStdin(): string | undefined {
  if (process.stdin.isTTY) return undefined;
  return readFileSync(0, 'utf8');
}

try {
  process.exitCode = run(
    process.argv.slice(2),
    {
      readStdin,
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
      env: process.env,
    },
    { version, programName },
  );
} catch {
  // Unexpected failure: don't print internals (stack traces may include input or paths).
  process.stderr.write(`${programName}: unexpected error\n`);
  process.exitCode = 1;
}
