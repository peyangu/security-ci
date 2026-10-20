#!/usr/bin/env node
// Installs or updates the security-ci callers in another repository.
//
//   node scripts/install.mjs <repo-dir> [--ref <sha>] [--release] [--force]
//   node scripts/install.mjs <repo-dir> --update [--ref <sha>]
//
// Install copies templates/ into <repo-dir> (existing files are kept unless
// --force) and pins every reference to security-ci at <sha>. --release also
// copies examples/release-electron-windows.yml to .github/workflows/release.yml.
// --update only re-pins the references already in <repo-dir>/.github/workflows.
// <sha> defaults to this checkout's HEAD, which must already be pushed.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const target = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--ref');
if (!target) {
  console.error('usage: node scripts/install.mjs <repo-dir> [--ref <sha>] [--release] [--force] [--update]');
  process.exit(2);
}
const dest = resolve(target);
if (!existsSync(join(dest, '.git'))) throw new Error(`${dest} is not a git repository`);

const git = (...a) => execFileSync('git', ['-C', root, ...a], { encoding: 'utf8' }).trim();
const ref = opt('--ref') ?? git('rev-parse', 'HEAD');
if (!/^[0-9a-f]{40}$/.test(ref)) throw new Error(`--ref must be a full commit SHA, got ${ref}`);
if (!git('branch', '-r', '--contains', ref)) {
  throw new Error(`${ref} is not on any remote branch of security-ci — push it first`);
}

const PIN = /(peyangu\/security-ci\/\.github\/workflows\/[\w.-]+@)(?:[0-9a-f]{40}|__SECURITY_CI_REF__)/g;
const TOOLKIT_REF = /(toolkit-ref:\s*)(?:[0-9a-f]{40}|__SECURITY_CI_REF__)/g;
const pin = (text) => text.replace(PIN, `$1${ref}`).replace(TOOLKIT_REF, `$1${ref}`);

function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const changed = [];
function write(rel, text) {
  const out = join(dest, rel);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, text);
  changed.push(rel);
}

if (flag('--update')) {
  const wf = join(dest, '.github', 'workflows');
  for (const file of existsSync(wf) ? walk(wf) : []) {
    const before = readFileSync(file, 'utf8');
    const after = pin(before);
    if (after !== before) write(relative(dest, file), after);
  }
} else {
  const sources = walk(join(root, 'templates')).map((f) => [f, relative(join(root, 'templates'), f)]);
  if (flag('--release')) {
    sources.push([join(root, 'examples', 'release-electron-windows.yml'), join('.github', 'workflows', 'release.yml')]);
  }
  for (const [src, rel] of sources) {
    if (existsSync(join(dest, rel)) && !flag('--force')) {
      console.log(`skip (exists): ${rel}`);
      continue;
    }
    write(rel, pin(readFileSync(src, 'utf8')));
  }
}

for (const c of changed) console.log(`wrote: ${c}`);
console.log(changed.length ? `security-ci pinned at ${ref}` : 'nothing to change');
