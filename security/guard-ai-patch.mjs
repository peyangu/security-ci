#!/usr/bin/env node
// Deterministic guard for patches produced by the AI audit agent.
// The agent is treated as untrusted: its patch may only add or edit test files
// under tests/security/, and those tests may not reach the network, spawn
// processes or read the environment. Anything else rejects the whole patch
// (it is never "filtered" — a misbehaving agent should be visible, not hidden).
//
// Usage: node guard-ai-patch.mjs <patch-file>   → exit 0 = allowed, 1 = rejected

import { readFileSync } from 'node:fs';

const ALLOWED_PATH = /^tests\/security\/[A-Za-z0-9._\-/]+\.ts$/;
const MAX_FILES = 20;
const MAX_ADDED_LINES = 3000;
const FORBIDDEN_CODE = [
  [/\bchild_process\b/, 'child_process'],
  [/\bnode:(net|http|https|http2|dgram|dns|tls|worker_threads|vm)\b|from\s+['"](net|http|https|http2|dgram|dns|tls|vm)['"]/, 'network/vm module'],
  [/\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b/, 'network call'],
  [/\bprocess\.env\b/, 'process.env'],
  [/\bprocess\.(binding|dlopen)\b/, 'native binding'],
  [/\beval\s*\(|\bnew\s+Function\s*\(/, 'dynamic code execution'],
  [/\bwriteFile(Sync)?\s*\(|\bappendFile(Sync)?\s*\(|\brm(Sync)?\s*\(|\bunlink(Sync)?\s*\(/, 'filesystem write'],
  [/\b(require|import)\s*\(\s*[^'"`]/, 'dynamic import/require'],
];

const patch = readFileSync(process.argv[2], 'utf8');
const problems = [];
const files = new Set();
let added = 0;
let current = null;

for (const line of patch.split('\n')) {
  let m;
  if ((m = line.match(/^diff --git a\/(.+) b\/(.+)$/))) {
    current = m[2];
    files.add(m[1]);
    files.add(m[2]);
    continue;
  }
  if (/^(deleted file mode|rename from|rename to|copy from|copy to|old mode|new mode)/.test(line)) {
    problems.push(`${current}: ${line.trim()} (only adding/editing files is allowed)`);
  } else if ((m = line.match(/^new file mode (\d+)/)) && m[1] !== '100644') {
    problems.push(`${current}: file mode ${m[1]} (symlinks/executables not allowed)`);
  } else if (/^(GIT binary patch|Binary files )/.test(line)) {
    problems.push(`${current}: binary content`);
  } else if (line.startsWith('+') && !line.startsWith('+++')) {
    added++;
    for (const [re, what] of FORBIDDEN_CODE) {
      if (re.test(line)) problems.push(`${current}: ${what}: ${line.slice(1).trim().slice(0, 120)}`);
    }
  }
}

for (const f of files) {
  if (!ALLOWED_PATH.test(f) || f.includes('..')) problems.push(`${f}: outside tests/security/**/*.ts`);
}
if (files.size > MAX_FILES) problems.push(`${files.size} files touched (max ${MAX_FILES})`);
if (added > MAX_ADDED_LINES) problems.push(`${added} lines added (max ${MAX_ADDED_LINES})`);

if (problems.length) {
  console.log('AI patch REJECTED:');
  for (const p of [...new Set(problems)]) console.log(`  - ${p}`);
  process.exit(1);
}
console.log(`AI patch accepted: ${files.size} file(s), +${added} lines`);
