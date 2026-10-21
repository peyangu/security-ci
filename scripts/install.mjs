#!/usr/bin/env node
// Installs or updates the security-ci callers in another repository.
//
//   node scripts/install.mjs <repo-dir> [--ref <sha>] [--release] [--force] [--only <text>]
//   node scripts/install.mjs <repo-dir> --update [--ref <sha>]
//
// Install copies templates/ into <repo-dir> (existing files are kept unless
// --force) and pins every reference to security-ci at <sha>. --release also
// copies examples/release-electron-windows.yml to .github/workflows/release.yml.
// --only limits the install to template paths containing <text> (e.g. ci.yml).
// The build check (ci.yml) runs the npm scripts found in package.json; it is
// skipped, with a message, when there is no package.json or no usable script.
// --update only re-pins the references already in <repo-dir>/.github/workflows.
// <sha> defaults to this checkout's HEAD, which must already be pushed.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const target = args.find((a, i) => !a.startsWith('--') && !['--ref', '--only'].includes(args[i - 1]));
if (!target) {
  console.error('usage: node scripts/install.mjs <repo-dir> [--ref <sha>] [--release] [--force] [--only <text>] [--update]');
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

// Which npm scripts the build check runs. A `verify` script is taken to be the
// project's own all-in-one check; otherwise lint → typecheck → build →
// electron:compile → test → test:security, skipping a typecheck the build
// already does and npm's placeholder test script.
function detectCiCommands() {
  const file = join(dest, 'package.json');
  if (!existsSync(file)) return { skip: 'no package.json (not a Node project)' };
  const scripts = JSON.parse(readFileSync(file, 'utf8')).scripts ?? {};
  if (scripts.verify) return { commands: ['verify'] };
  const picked = ['lint', 'typecheck', 'build', 'electron:compile', 'test', 'test:security'].filter((name) => {
    const cmd = scripts[name];
    if (!cmd) return false;
    if (name === 'typecheck' && /\btsc\b/.test(scripts.build ?? '')) return false;
    if (name === 'test' && /no test specified/.test(cmd)) return false;
    return true;
  });
  return picked.length ? { commands: picked } : { skip: 'package.json has no build/test scripts' };
}

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
  const only = opt('--only');
  for (const [src, rel] of sources) {
    if (only && !rel.split(sep).join('/').includes(only)) continue;
    if (existsSync(join(dest, rel)) && !flag('--force')) {
      console.log(`skip (exists): ${rel}`);
      continue;
    }
    let text = pin(readFileSync(src, 'utf8'));
    if (text.includes('__CI_COMMANDS__')) {
      const ci = detectCiCommands();
      if (ci.skip) {
        console.log(`skip (${ci.skip}): ${rel}`);
        continue;
      }
      text = text.replace('__CI_COMMANDS__', ci.commands.map((c) => `        ${c}`).join('\n'));
    }
    write(rel, text);
  }
}

for (const c of changed) console.log(`wrote: ${c}`);
console.log(changed.length ? `security-ci pinned at ${ref}` : 'nothing to change');
