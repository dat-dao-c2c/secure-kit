#!/usr/bin/env node
import { readFileSync } from 'fs';
import { run } from './cli/run.js';

declare const __SECRET_KIT_VERSION__: string | undefined;

const version = typeof __SECRET_KIT_VERSION__ === 'string' ? __SECRET_KIT_VERSION__ : 'dev';

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
    version,
  );
} catch {
  // Unexpected failure: don't print internals (stack traces may include input or paths).
  process.stderr.write('secret-kit: unexpected error\n');
  process.exitCode = 1;
}
