#!/usr/bin/env node
/**
 * CLI: audit workflow files in a repo (default: .github/workflows).
 *
 *   node src/cli.ts                          # audit ./.github/workflows
 *   node src/cli.ts path/to/workflows        # a directory
 *   node src/cli.ts a.yml b.yml              # specific files
 *   node src/cli.ts --json out.json          # machine-readable
 *   node src/cli.ts --fail-on high           # exit 1 for CI gating
 *
 * Exit codes: 0 clean / below threshold, 1 findings at or above --fail-on,
 * 2 usage or parse error.
 */

import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { basename, join, relative } from 'node:path';
import { auditFiles } from './core/audit.ts';
import type { AuditReport, Severity } from './core/types.ts';
import { SEVERITY_ORDER } from './core/types.ts';
import { toMarkdown } from './ui/report-markdown.ts';

interface Args {
  paths: string[];
  json: string | null;
  markdown: string | null;
  failOn: Severity | null;
  quiet: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { paths: [], json: null, markdown: null, failOn: null, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = argv[++i] ?? 'workflow-audit.json';
    else if (a === '--markdown' || a === '--md') args.markdown = argv[++i] ?? 'workflow-audit.md';
    else if (a === '--fail-on') {
      const v = argv[++i];
      if (!v || !SEVERITY_ORDER.includes(v as Severity)) {
        throw new Error('--fail-on 需要 critical|high|medium|low');
      }
      args.failOn = v as Severity;
    } else if (a === '--quiet' || a === '-q') args.quiet = true;
    else if (a === '--help' || a === '-h') {
      console.log(`用法: workflow-audit [路径...] [--json 文件] [--markdown 文件] [--fail-on 级别] [--quiet]`);
      process.exit(0);
    } else if (a.startsWith('-')) {
      throw new Error(`未知参数 ${a}`);
    } else args.paths.push(a);
  }
  return args;
}

async function collect(dir: string): Promise<string[]> {
  const info = await stat(dir).catch(() => null);
  if (!info) throw new Error(`路径不存在：${dir}`);
  if (info.isFile()) return /\.ya?ml$/i.test(dir) ? [dir] : [];
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await collect(full)));
    else if (/\.ya?ml$/i.test(entry.name)) out.push(full);
  }
  return out;
}

const C = process.stdout.isTTY
  ? {
      reset: '\x1b[0m',
      bold: '\x1b[1m',
      dim: '\x1b[2m',
      red: '\x1b[31m',
      orange: '\x1b[33m',
      yellow: '\x1b[93m',
      grey: '\x1b[90m',
      green: '\x1b[32m',
    }
  : { reset: '', bold: '', dim: '', red: '', orange: '', yellow: '', grey: '', green: '' };

const SEV_COLOR: Record<Severity, string> = {
  critical: C.red,
  high: C.orange,
  medium: C.yellow,
  low: C.grey,
};

const SEV_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高  ',
  medium: '中  ',
  low: '低  ',
};

function printReport(report: AuditReport): void {
  const t = report.totals;
  console.log('');
  console.log(
    `${C.bold}工作流安全审计${C.reset} ${C.dim}· ${t.files} 个文件 · ${t.findings} 处问题${C.reset}`,
  );
  console.log(
    `总评 ${gradeColor(report.grade)}${report.grade}${C.reset} (${report.score}/100)  ` +
      `严重 ${C.red}${t.critical}${C.reset} · 高 ${C.orange}${t.high}${C.reset} · ` +
      `中 ${C.yellow}${t.medium}${C.reset} · 低 ${C.grey}${t.low}${C.reset}`,
  );

  for (const file of report.files) {
    console.log('');
    const head = `${C.bold}${file.name}${C.reset} ${C.dim}${file.file}${C.reset}`;
    console.log(`${head}  ${gradeColor(file.grade)}${file.grade}${C.reset} ${C.dim}${file.score}/100${C.reset}`);
    if (file.errors.length) {
      for (const e of file.errors) console.log(`  ${C.red}解析失败${C.reset} ${e}`);
      continue;
    }
    for (const w of file.warnings) console.log(`  ${C.dim}· ${w}${C.reset}`);
    if (!file.findings.length) {
      console.log(`  ${C.green}✓${C.reset} ${C.dim}未发现已知风险写法${C.reset}`);
      continue;
    }
    for (const f of file.findings) {
      const color = SEV_COLOR[f.severity];
      console.log(`  ${color}${SEV_LABEL[f.severity]}${C.reset} ${C.dim}${f.ruleId}${C.reset} ${f.ruleTitle}`);
      console.log(`        ${C.dim}${f.file}:${f.line}:${f.column}  ${f.path}${C.reset}`);
      console.log(`        ${C.dim}证据${C.reset} ${f.evidence}`);
      if (!process.argv.includes('--quiet')) {
        console.log(`        ${C.dim}建议${C.reset} ${f.advice.split('\n')[0]}`);
      }
    }
  }
  console.log('');
}

function gradeColor(grade: string): string {
  if (grade === 'A' || grade === 'B') return C.green;
  if (grade === 'C') return C.yellow;
  return C.red;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const roots = args.paths.length ? args.paths : ['.github/workflows'];

  const paths: string[] = [];
  for (const root of roots) paths.push(...(await collect(root)));
  if (!paths.length) {
    console.error(`没有找到工作流文件（${roots.join(', ')}）`);
    return 2;
  }

  const files = await Promise.all(
    paths.map(async (p) => ({ path: relative(process.cwd(), p) || basename(p), text: await readFile(p, 'utf8') })),
  );

  const report = auditFiles(files);
  printReport(report);

  if (args.json) {
    await writeFile(args.json, JSON.stringify(report, null, 2));
    console.log(`${C.dim}JSON 报告已写入 ${args.json}${C.reset}`);
  }
  if (args.markdown) {
    await writeFile(args.markdown, toMarkdown(report));
    console.log(`${C.dim}Markdown 报告已写入 ${args.markdown}${C.reset}`);
  }

  if (args.failOn) {
    const threshold = SEVERITY_ORDER.indexOf(args.failOn);
    const hit = report.files.some((f) => f.findings.some((x) => SEVERITY_ORDER.indexOf(x.severity) <= threshold));
    const broken = report.files.some((f) => f.errors.length > 0);
    if (broken) return 2;
    if (hit) return 1;
  }
  return report.files.some((f) => f.errors.length) ? 2 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err: Error) => {
    console.error(`${C.red}${err.message}${C.reset}`);
    process.exit(2);
  });
