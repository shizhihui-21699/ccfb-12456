/**
 * Rule plumbing: source anchors, severity helpers, and the finding sink.
 */

import type { Node } from 'yaml';
import type { SourceText } from '../yaml.ts';
import type { Category, Finding, RuleMeta, Severity } from '../types.ts';
import type { JobModel, StepModel, WorkflowModel } from '../model.ts';
import { findExpressions } from '../expressions.ts';

export interface Anchor {
  line: number;
  column: number;
  endLine: number;
}

export function anchorOf(source: SourceText, node: Node | null | undefined): Anchor {
  if (!node?.range) return { line: 1, column: 1, endLine: 1 };
  const [from, to] = node.range;
  const start = source.position(from);
  // YAML node ranges are half-open and a block node's end typically points at
  // the newline that terminates its last line -- or at the first character of
  // the *next* key. Use the last character actually inside the node, then walk
  // back over trailing blank lines, so a highlight never bleeds into the next
  // step.
  let endOffset = Math.max(from, to - 1);
  while (endOffset > from && source.text[endOffset] === '\n') endOffset -= 1;
  let end = source.position(endOffset);
  while (end.line > start.line && source.lineText(end.line).trim() === '') {
    end = source.position(source.lineStarts[end.line - 2] ?? from);
    while (end.line > start.line && source.text[end.offset] === '\n') end = source.position(end.offset - 1);
  }
  return { line: start.line, column: start.column, endLine: Math.max(start.line, end.line) };
}

/** Locate `needle` inside a node's raw source, starting the search at `from`. */
export function locateInNode(
  source: SourceText,
  node: Node | null | undefined,
  needle: string,
  from = 0,
): { line: number; column: number; next: number } | null {
  if (!node?.range) return null;
  const start = node.range[0];
  const end = node.range[1];
  const slice = source.text.slice(start, end);
  const idx = slice.indexOf(needle, from);
  if (idx < 0) return null;
  const pos = source.position(start + idx);
  return { line: pos.line, column: pos.column, next: idx + needle.length };
}

/**
 * Locate the i-th occurrence of an expression within a scalar. Scalar values are
 * verbatim inside their raw range for block scalars; for flows we fall back to
 * the node start so we never point at the wrong line.
 */
export function locateExpression(
  source: SourceText,
  node: Node | null | undefined,
  raw: string,
  occurrence: number,
): { line: number; column: number } {
  let from = 0;
  for (let i = 0; i <= occurrence; i++) {
    const hit = locateInNode(source, node, raw, from);
    if (!hit) return fallback(node, source);
    if (i === occurrence) return { line: hit.line, column: hit.column };
    from = hit.next;
  }
  return fallback(node, source);
}

function fallback(node: Node | null | undefined, source: SourceText): { line: number; column: number } {
  const a = anchorOf(source, node);
  return { line: a.line, column: a.column };
}

/** Severity helpers -------------------------------------------------------- */

const LADDER: Severity[] = ['low', 'medium', 'high', 'critical'];

export function bump(severity: Severity, steps = 1): Severity {
  const i = LADDER.indexOf(severity);
  return LADDER[Math.min(LADDER.length - 1, Math.max(0, i + steps))];
}

export function lower(severity: Severity, steps = 1): Severity {
  return bump(severity, -steps);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return LADDER.indexOf(a) >= LADDER.indexOf(b) ? a : b;
}

/** Finding sink ----------------------------------------------------------- */

export interface FindingInput {
  rule: RuleMeta;
  severity: Severity;
  category?: Category;
  anchor: Anchor;
  path: string;
  evidence: string;
  message: string;
  advice: string;
  patch?: string;
  references?: string[];
}

export class FindingSink {
  readonly findings: Finding[] = [];
  readonly file: string;
  readonly source: SourceText;
  private seq = 0;

  constructor(file: string, source: SourceText) {
    this.file = file;
    this.source = source;
  }

  add(input: FindingInput): Finding {
    const finding: Finding = {
      id: `${this.file}#${++this.seq}`,
      ruleId: input.rule.id,
      ruleTitle: input.rule.title,
      severity: input.severity,
      category: input.category ?? input.rule.category,
      file: this.file,
      line: input.anchor.line,
      column: input.anchor.column,
      endLine: input.anchor.endLine,
      path: input.path,
      evidence: truncate(input.evidence, 220),
      message: input.message,
      advice: input.advice,
      patch: input.patch,
      references: input.references ?? input.rule.references,
    };
    this.findings.push(finding);
    return finding;
  }
}

export function truncate(text: string, max: number): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/** Context helpers --------------------------------------------------------- */

export interface RuleContext {
  model: WorkflowModel;
  source: SourceText;
  sink: FindingSink;
}

export interface Rule {
  meta: RuleMeta;
  run(ctx: RuleContext): void;
}

export function stepLabel(step: StepModel): string {
  if (step.name) return step.name;
  if (step.uses) return step.uses;
  if (step.run) return truncate(step.run.text, 60);
  return `step ${step.index + 1}`;
}

export function jobPath(job: JobModel): string {
  return `jobs.${job.id}`;
}

export function stepPath(job: JobModel, step: StepModel): string {
  return `jobs.${job.id}.steps[${step.index}]`;
}

/** All (job, step, expression) triples in a workflow, for expression rules. */
export function* expressionsInStep(
  step: StepModel,
): Generator<{ expr: string; raw: string; field: 'run' | 'script' | 'if' | 'with' | 'env'; key?: string; node: Node; occurrence: number; text: string }> {
  const buckets: Array<{ field: 'run' | 'script' | 'if' | 'with' | 'env'; key?: string; node: Node; text: string }> = [];
  if (step.run) buckets.push({ field: 'run', node: step.run.node, text: step.run.text });
  if (step.script) buckets.push({ field: 'script', key: 'script', node: step.script.node, text: step.script.value });
  if (step.ifExpr) buckets.push({ field: 'if', node: step.ifExpr.node, text: step.ifExpr.value });
  for (const [key, v] of step.with) buckets.push({ field: 'with', key, node: v.node, text: v.value });
  for (const [key, v] of step.env) buckets.push({ field: 'env', key, node: v.node, text: v.value });

  for (const bucket of buckets) {
    const matches = findExpressions(bucket.text);
    // occurrence index is per identical raw text within this scalar
    const seen = new Map<string, number>();
    for (const m of matches) {
      const occurrence = seen.get(m.raw) ?? 0;
      seen.set(m.raw, occurrence + 1);
      yield { expr: m.expr, raw: m.raw, field: bucket.field, key: bucket.key, node: bucket.node, occurrence, text: bucket.text };
    }
  }
}
