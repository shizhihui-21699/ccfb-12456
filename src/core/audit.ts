/**
 * Audit engine: parse one or more workflow files, run the rule set, score.
 *
 * Scoring is a simple severity-weighted penalty normalised by the number of
 * jobs, so a 400-line workflow with one critical finding does not look better
 * than a 20-line one with two. The point is triage order, not a precise metric.
 */

import { parseWorkflowText } from './yaml.ts';
import { buildModel } from './model.ts';
import type { WorkflowModel } from './model.ts';
import { FindingSink } from './rules/context.ts';
import type { Rule } from './rules/context.ts';
import { untrustedCodeRules } from './rules/untrusted-code.ts';
import { scriptInjectionRules } from './rules/script-injection.ts';
import { permissionRules } from './rules/permissions.ts';
import { supplyChainRules } from './rules/supply-chain.ts';
import { runnerRules, secretRules } from './rules/secrets.ts';
import type {
  AuditReport,
  Finding,
  Severity,
  WorkflowJobReport,
  WorkflowReport,
} from './types.ts';
import { SEVERITY_ORDER } from './types.ts';

export const TOOL_VERSION = '0.1.0';

export const ALL_RULES: Rule[] = [
  ...untrustedCodeRules,
  ...scriptInjectionRules,
  ...permissionRules,
  ...supplyChainRules,
  ...secretRules,
  ...runnerRules,
];

export interface AuditOptions {
  /** rules to skip, by id */
  disabledRules?: Iterable<string>;
  /** extra rules, e.g. from tests */
  extraRules?: Iterable<Rule>;
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 15,
  medium: 5,
  low: 1,
};

/** Rules that are only worth one finding per file, not one per step. */
const DEDUPE_PER_FILE = new Set(['WF021', 'WF040', 'WF050']);

export function auditWorkflowText(
  path: string,
  text: string,
  options: AuditOptions = {},
): WorkflowReport {
  const disabled = new Set(options.disabledRules ?? []);
  const { doc, source, errors } = parseWorkflowText(path, text);
  const sink = new FindingSink(path, source);

  if (errors.length) {
    return {
      name: path,
      file: path,
      triggers: [],
      rawTriggers: [],
      jobs: [],
      findings: [],
      score: 100,
      grade: 'A',
      errors,
      warnings: ['YAML 解析失败，未执行审计。'],
    };
  }

  const model: WorkflowModel = buildModel(doc, source, errors);
  const rules = [...ALL_RULES.filter((r) => !disabled.has(r.meta.id)), ...(options.extraRules ?? [])];

  for (const rule of rules) {
    try {
      rule.run({ model, source, sink });
    } catch (err) {
      model.warnings.push(`规则 ${rule.meta.id} 执行失败：${(err as Error).message}`);
    }
  }

  const findings = dedupe(sink.findings);
  const score = scoreFindings(findings, Math.max(1, model.jobs.length));

  return {
    name: model.name?.trim() || path,
    file: path,
    triggers: model.triggers.map((t) => mapTrigger(t.key)),
    rawTriggers: model.triggers.map((t) => t.raw),
    jobs: model.jobs.map(describeJob),
    findings,
    score,
    grade: gradeFor(score),
    errors: [],
    warnings: model.warnings,
  };
}

function describeJob(job: WorkflowModel['jobs'][number]): WorkflowJobReport {
  return {
    id: job.id,
    name: job.name ?? undefined,
    line: job.line,
    runsOn: job.runsOn,
    checksOutUntrustedCode: false,
    writePermissions: job.permissions.writeScopes,
  };
}

function mapTrigger(key: string): WorkflowReport['triggers'][number] {
  const known = [
    'pull_request',
    'pull_request_target',
    'workflow_run',
    'issue_comment',
    'issues',
    'discussion',
    'discussion_comment',
    'push',
    'workflow_dispatch',
    'workflow_call',
    'schedule',
    'release',
    'merge_group',
  ];
  return known.includes(key) ? (key as WorkflowReport['triggers'][number]) : 'other';
}

/**
 * WF021 ("no permissions block") fires once per file; the same is true for
 * supply-chain findings on the same action. Keep the most severe of a group.
 */
function dedupe(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const f of findings) {
    const perFile = DEDUPE_PER_FILE.has(f.ruleId);
    const key = perFile ? `${f.ruleId}:${f.path.split('.steps')[0]}:${f.evidence}` : f.id;
    const existing = byKey.get(key);
    if (!existing || SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(existing.severity)) {
      byKey.set(key, f);
    }
  }
  return [...byKey.values()].sort(compareFindings);
}

export function compareFindings(a: Finding, b: Finding): number {
  const sev = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  if (sev !== 0) return sev;
  if (a.file !== b.file) return a.file.localeCompare(b.file);
  return a.line - b.line || a.column - b.column;
}

export function scoreFindings(findings: Finding[], jobCount: number): number {
  let penalty = 0;
  for (const f of findings) {
    const weight = SEVERITY_WEIGHT[f.severity];
    // A critical in a workflow with many jobs is still critical; scale slowly.
    penalty += weight / Math.max(1, Math.sqrt(jobCount / 2));
  }
  return Math.max(0, Math.round(100 - penalty));
}

export function gradeFor(score: number): WorkflowReport['grade'] {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  if (score >= 20) return 'E';
  return 'F';
}

export function auditFiles(
  files: Array<{ path: string; text: string }>,
  options: AuditOptions = {},
  now = new Date(),
): AuditReport {
  const reports = files.map((f) => auditWorkflowText(f.path, f.text, options));
  const totals = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    findings: 0,
    files: reports.length,
  };
  for (const r of reports) {
    for (const f of r.findings) {
      totals[f.severity] += 1;
      totals.findings += 1;
    }
  }
  const score = reports.length
    ? Math.round(reports.reduce((sum, r) => sum + r.score, 0) / reports.length)
    : 100;

  return {
    generatedAt: now.toISOString(),
    toolVersion: TOOL_VERSION,
    files: reports,
    totals,
    score,
    grade: gradeFor(score),
  };
}
