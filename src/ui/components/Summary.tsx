/**
 * Top-of-rail summary: overall grade, severity counts, worst rule.
 */

import type { AuditReport, Severity } from '../../core/types.ts';
import { SEVERITY_LABEL } from '../labels.ts';

export function Summary({ report }: { report: AuditReport }) {
  const t = report.totals;
  const worst = worstSeverity(report);
  return (
    <div class={`summary ${worst ? `has-${worst}` : 'has-clean'}`}>
      <div class="summary-head">
        <div class={`big-grade grade-${report.grade}`}>{report.grade}</div>
        <div>
          <div class="summary-score">{report.score}<span class="of">/100</span></div>
          <div class="summary-label">{verdict(report.grade, t.critical, t.high)}</div>
        </div>
      </div>
      <div class="severity-bar" role="img" aria-label="严重度分布">
        {(Object.keys(SEVERITY_LABEL) as Severity[]).map((sev) => {
          const n = t[sev];
          const pct = t.findings ? (n / t.findings) * 100 : 0;
          return n > 0 ? (
            <span key={sev} class={`seg sev-${sev}`} style={{ width: `${pct}%` }} title={`${SEVERITY_LABEL[sev]} ${n}`} />
          ) : null;
        })}
      </div>
      <div class="severity-counts">
        {(Object.keys(SEVERITY_LABEL) as Severity[]).map((sev) => (
          <span key={sev} class={`count sev-${sev} ${t[sev] ? '' : 'zero'}`}>
            <b>{t[sev]}</b>
            {SEVERITY_LABEL[sev]}
          </span>
        ))}
      </div>
    </div>
  );
}

function worstSeverity(report: AuditReport): Severity | null {
  const order: Severity[] = ['critical', 'high', 'medium', 'low'];
  return order.find((s) => report.totals[s] > 0) ?? null;
}

function verdict(grade: string, critical: number, high: number): string {
  if (critical > 0) return `${critical} 个严重问题需要先处理`;
  if (high > 0) return `${high} 个高风险项建议尽快修复`;
  if (grade === 'A' || grade === 'B') return '没有外部贡献者可直接利用的路径';
  return '有若干加固项可以一起做';
}
