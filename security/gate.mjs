#!/usr/bin/env node
// Security gate: normalizes OSV-Scanner / Semgrep / Gitleaks results, applies
// reviewed exceptions, and exits non-zero when a blocking finding remains.
//
// Fail-closed by design: a missing or unreadable result file, an unexpected
// scanner exit code, a malformed exception, or a scanner-bypass file all block.
// Zero dependencies so it runs on any runner with Node >= 18.
//
// Usage:
//   node gate.mjs --results <dir> --mode pr|full [--fail-on high]
//                 [--exceptions .security/exceptions.json] [--repo .]
//                 [--summary $GITHUB_STEP_SUMMARY] [--out gate-result.json]
//
// <dir> must contain, per tool, <tool>.json and <tool>.exit (scanner exit code):
//   osv.json / osv.exit        (pr mode: also osv-base.json / osv-base.exit)
//   semgrep.json / semgrep.exit
//   gitleaks.json / gitleaks.exit

import { readFileSync, existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const MAX_EXCEPTION_DAYS = 90;
// Files that let a scanner silently skip findings. Exceptions must go through
// .security/exceptions.json instead, so every suppression is reviewed in one place.
const BYPASS_FILES = ['.gitleaksignore', '.gitleaks.toml', 'osv-scanner.toml', '.semgrepignore'];
// Scanner exit codes that mean "ran to completion" (with or without findings).
const OK_EXIT = {
  osv: [0, 1, 128], // 128 = no packages found
  semgrep: [0, 1],
  gitleaks: [0],    // run with --exit-code 0, anything else is an error
};

function parseArgs(argv) {
  const args = { mode: 'full', failOn: 'high', exceptions: '.security/exceptions.json', repo: '.' };
  for (let i = 2; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, '');
    const v = argv[i + 1];
    if (v === undefined) throw new Error(`missing value for --${k}`);
    args[k.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
  }
  if (!args.results) throw new Error('--results is required');
  if (!['pr', 'full'].includes(args.mode)) throw new Error(`--mode must be pr|full, got ${args.mode}`);
  if (!SEVERITIES.includes(args.failOn)) throw new Error(`--fail-on must be one of ${SEVERITIES.join('|')}`);
  return args;
}

const errors = []; // gate-level problems; each one blocks

function readResult(dir, name) {
  const exitPath = join(dir, `${name}.exit`);
  const jsonPath = join(dir, `${name}.json`);
  const tool = name.replace(/-base$/, '');
  if (!existsSync(exitPath)) {
    errors.push(`${name}: result missing (scanner did not run or crashed)`);
    return null;
  }
  const code = Number(readFileSync(exitPath, 'utf8').trim());
  if (!OK_EXIT[tool].includes(code)) {
    errors.push(`${name}: scanner exited with unexpected code ${code}`);
    return null;
  }
  // osv-scanner exits 128 without writing (or with an empty) output file when
  // the repo has no package sources at all. Only that exact case means "nothing".
  const raw = existsSync(jsonPath) ? readFileSync(jsonPath, 'utf8').trim() : null;
  if (tool === 'osv' && code === 128 && !raw) return { results: [] };
  if (raw === null) {
    errors.push(`${name}: result missing (scanner did not run or crashed)`);
    return null;
  }
  if (raw === '') {
    errors.push(`${name}: empty result file`);
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    errors.push(`${name}: unparseable result (${e.message})`);
    return null;
  }
}

function cvssToSeverity(score) {
  const n = Number.parseFloat(score);
  if (Number.isNaN(n)) return 'unknown';
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
}

function osvFindings(doc) {
  const out = [];
  for (const r of doc?.results ?? []) {
    for (const p of r.packages ?? []) {
      const pkg = p.package ?? {};
      for (const g of p.groups ?? []) {
        const ids = g.ids ?? [];
        const id = ids[0];
        // MAL-* = known malicious package: always critical regardless of CVSS.
        const malicious = [...ids, ...(g.aliases ?? [])].some((x) => x.startsWith('MAL-'));
        const vuln = (p.vulnerabilities ?? []).find((v) => ids.includes(v.id));
        out.push({
          tool: 'osv',
          key: `osv:${id}:${pkg.name}`,
          severity: malicious ? 'critical' : cvssToSeverity(g.max_severity),
          title: `${pkg.name}@${pkg.version} — ${id}${vuln?.summary ? `: ${vuln.summary}` : ''}`,
          location: r.source?.path?.replace(/^.*?\/(?=[^/]+$)/, '') ?? '',
          scope: (p.dependency_groups ?? []).join(',') || 'prod',
        });
      }
    }
  }
  return out;
}

function semgrepFindings(doc) {
  const map = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };
  const out = (doc?.results ?? []).map((r) => {
    // Rules may raise themselves above the default mapping via metadata.
    const override = r.extra?.metadata?.['gate-severity'];
    return {
      tool: 'semgrep',
      key: `semgrep:${r.check_id}:${r.path}`,
      severity: SEVERITIES.includes(override) ? override : (map[r.extra?.severity] ?? 'unknown'),
      title: `${r.check_id.split('.').pop()} — ${(r.extra?.message ?? '').split('\n')[0].slice(0, 160)}`,
      location: `${r.path}:${r.start?.line ?? '?'}`,
    };
  });
  for (const e of doc?.errors ?? []) {
    // Parse errors on individual files are tolerated; config/rule errors are not.
    const type = String(Array.isArray(e.type) ? e.type[0] : (e.type ?? ''));
    if ((e.level ?? 'error') === 'error' && !/Syntax|Lexical|PartialParsing|Timeout/i.test(type)) {
      errors.push(`semgrep: ${type}: ${(e.message ?? '').slice(0, 200)}`);
    }
  }
  return out;
}

function gitleaksFindings(doc) {
  return (Array.isArray(doc) ? doc : []).map((f) => ({
    tool: 'gitleaks',
    key: `gitleaks:${f.Fingerprint}`,
    severity: 'critical', // a committed secret is compromised the moment it is pushed
    title: `${f.RuleID} — ${f.Description ?? ''}`,
    location: `${f.File}:${f.StartLine} @ ${String(f.Commit ?? '').slice(0, 8)}`,
  }));
}

function loadExceptions(path, today) {
  if (!existsSync(path)) return [];
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    errors.push(`exceptions: ${path} is not valid JSON (${e.message})`);
    return [];
  }
  const list = [];
  for (const [i, ex] of (doc.exceptions ?? []).entries()) {
    const where = `exceptions[${i}] (${ex.key ?? 'no key'})`;
    if (!ex.key || !ex.reason || !ex.expires) {
      errors.push(`${where}: key, reason and expires are all required`);
      continue;
    }
    const expires = new Date(`${ex.expires}T23:59:59Z`);
    if (Number.isNaN(expires.getTime())) {
      errors.push(`${where}: expires must be YYYY-MM-DD`);
      continue;
    }
    const days = (expires - today) / 86_400_000;
    if (days > MAX_EXCEPTION_DAYS) {
      errors.push(`${where}: expires more than ${MAX_EXCEPTION_DAYS} days out; exceptions must be revisited`);
      continue;
    }
    list.push({ ...ex, expired: days < 0, used: false });
  }
  return list;
}

function findBypassFiles(repo) {
  let files = [];
  try {
    files = execFileSync('git', ['-C', repo, 'ls-files'], { encoding: 'utf8' }).split('\n');
  } catch {
    errors.push('bypass-check: could not list repository files');
  }
  return files.filter((f) => BYPASS_FILES.includes(f.split('/').pop()));
}

function rank(sev, unknownAs) {
  return SEVERITIES.indexOf(sev === 'unknown' ? unknownAs : sev);
}

function main() {
  const args = parseArgs(process.argv);
  const today = new Date();
  const dir = args.results;

  const osv = readResult(dir, 'osv');
  const semgrep = readResult(dir, 'semgrep');
  const gitleaks = readResult(dir, 'gitleaks');

  let findings = [
    ...(osv ? osvFindings(osv) : []),
    ...(semgrep ? semgrepFindings(semgrep) : []),
    ...(gitleaks ? gitleaksFindings(gitleaks) : []),
  ];

  // PR mode: dependency findings already present on the base branch are not
  // this PR's doing; report them but only block on what the PR introduces.
  // (Semgrep and Gitleaks are already diff-scoped by the workflow.)
  let preexisting = [];
  if (args.mode === 'pr') {
    const base = readResult(dir, 'osv-base');
    if (base) {
      const baseKeys = new Set(osvFindings(base).map((f) => f.key));
      preexisting = findings.filter((f) => f.tool === 'osv' && baseKeys.has(f.key));
      findings = findings.filter((f) => !(f.tool === 'osv' && baseKeys.has(f.key)));
    }
  }

  // Dedupe (Gitleaks can report the same secret in several commits, OSV the
  // same advisory for several versions of one package).
  findings = [...new Map(findings.map((f) => [`${f.key}|${f.location}|${f.title}`, f])).values()];

  for (const file of findBypassFiles(args.repo)) {
    findings.push({
      tool: 'gate',
      key: `bypass-file:${file}`,
      severity: 'high',
      title: 'scanner suppression file — move suppressions to .security/exceptions.json',
      location: file,
    });
  }

  const exceptions = loadExceptions(args.exceptions, today);
  const threshold = SEVERITIES.indexOf(args.failOn);
  const unknownAs = 'high'; // fail closed: an unscored advisory is treated as high

  for (const f of findings) {
    const ex = exceptions.find((e) => e.key === f.key);
    if (ex) {
      ex.used = true;
      f.exception = ex.expired ? `EXPIRED ${ex.expires}` : `until ${ex.expires}: ${ex.reason}`;
    }
    f.blocking = rank(f.severity, unknownAs) >= threshold && !(ex && !ex.expired);
  }

  const blocking = findings.filter((f) => f.blocking);
  const blocked = blocking.length > 0 || errors.length > 0;
  const unused = exceptions.filter((e) => !e.used);

  const result = {
    mode: args.mode,
    failOn: args.failOn,
    blocked,
    errors,
    counts: Object.fromEntries(['osv', 'semgrep', 'gitleaks', 'gate'].map((t) => [t, findings.filter((f) => f.tool === t).length])),
    blockingCount: blocking.length,
    findings,
    preexistingCount: preexisting.length,
    unusedExceptions: unused.map((e) => e.key),
  };
  if (args.out) writeFileSync(args.out, JSON.stringify(result, null, 2));

  const md = renderMarkdown(result, blocking, preexisting);
  if (args.summary) appendFileSync(args.summary, md);
  process.stdout.write(md);

  process.exit(blocked ? 1 : 0);
}

function renderMarkdown(r, blocking, preexisting) {
  const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const row = (f) => `| ${f.severity} | ${f.tool} | ${esc(f.title)} | \`${esc(f.location)}\` | ${esc(f.exception ?? '')} |`;
  const header = '| severity | tool | finding | location | exception |\n|---|---|---|---|---|';
  const sorted = (xs) => [...xs].sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity));
  const lines = [];
  lines.push(`## Security gate: ${r.blocked ? '🛑 BLOCKED' : '✅ PASSED'}`);
  lines.push('');
  lines.push(`mode \`${r.mode}\` · fail-on \`${r.failOn}\` · findings: OSV ${r.counts.osv}, Semgrep ${r.counts.semgrep}, Gitleaks ${r.counts.gitleaks}, gate ${r.counts.gate} · blocking ${r.blockingCount}`);
  lines.push('');
  if (r.errors.length) {
    lines.push('### Gate errors (fail-closed)');
    for (const e of r.errors) lines.push(`- ${esc(e)}`);
    lines.push('');
  }
  if (blocking.length) {
    lines.push('### Blocking findings');
    lines.push(header);
    for (const f of sorted(blocking).slice(0, 100)) lines.push(row(f));
    if (blocking.length > 100) lines.push(`\n…and ${blocking.length - 100} more (see gate-result.json artifact)`);
    lines.push('');
  }
  const rest = r.findings.filter((f) => !f.blocking);
  if (rest.length) {
    lines.push(`<details><summary>Non-blocking findings (${rest.length})</summary>\n`);
    lines.push(header);
    for (const f of sorted(rest).slice(0, 200)) lines.push(row(f));
    lines.push('\n</details>\n');
  }
  if (preexisting.length) {
    lines.push(`ℹ️ ${preexisting.length} dependency finding(s) already exist on the base branch and are not blocking this PR; the weekly scan and release gate still count them.\n`);
  }
  if (r.unusedExceptions.length) {
    lines.push(`⚠️ Unused exceptions (remove them): ${r.unusedExceptions.map((k) => `\`${k}\``).join(', ')}\n`);
  }
  return lines.join('\n') + '\n';
}

try {
  main();
} catch (e) {
  console.error(`security gate crashed: ${e.stack ?? e}`);
  process.exit(2);
}
