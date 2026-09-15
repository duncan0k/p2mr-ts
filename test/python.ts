import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { REPO_ROOT } from './vectors.js';

/** Locate a local Python 3; returns null when none is found, leaving skip-or-fail to the caller. */
export function findPython(): string | null {
  for (const candidate of ['python', 'python3']) {
    try {
      const out = execFileSync(candidate, ['--version'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      if (/^Python 3\./.test(out.trim())) return candidate;
    } catch {
      // move on to the next candidate
    }
  }
  return null;
}

/** Run a Python script from the repo root and parse its stdout as JSON; optional `input` goes to stdin. */
export function runPythonJson<T>(bin: string, scriptRelPath: string, input?: string): T {
  const stdout = execFileSync(bin, [resolve(REPO_ROOT, scriptRelPath)], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    ...(input === undefined ? {} : { input }),
  });
  return JSON.parse(stdout) as T;
}
