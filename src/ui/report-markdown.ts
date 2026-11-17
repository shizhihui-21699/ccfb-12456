/**
 * Convert an audit report to Markdown, for pasting into a PR / issue / chat.
 */

import type { AuditReport, Severity } from '../core/types.ts';
import { CATEGORY_LABEL } from './labels.ts';

const SEVERITY_HEADING: Record<Severity, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
};

export function toMarkdown(report: AuditReport): string {
  const lines: string[] = [];
  const t = report.totals;
  lines.push('# GitHub Actions 工作流安全审计');
  lines.push('');
  lines.push(`生成时间：${new Date(report.generatedAt).toLocaleString('zh-CN')} · 工具版本 ${report.toolVersion}`);
  lines.push('');
  lines.push(
    `**总评 ${report.grade}（${report.score}/100）** — 严重 ${t.critical} · 高 ${t.high} · 中 ${t.medium} · 低 ${t.low}，共 ${t.findings} 处问题，覆盖 ${t.files} 个文件。`,
  );
  lines.push('');

  for (const file of report.files) {
    lines.push(`## ${file.name}`);
    lines.push('');
    lines.push(`\`${file.file}\` · 评级 ${file.grade}（${file.score}/100）`);
    lines.push('');
    if (file.rawTriggers.length) {
      lines.push(`触发事件：${file.rawTriggers.map((x) => '`' + x + '`').join('、')}`);
      lines.push('');
    }
    if (file.errors.length) {
      lines.push('> YAML 解析失败，未执行审计：');
      lines.push('>');
      for (const e of file.errors) lines.push(`> - ${e}`);
      lines.push('');
      continue;
    }
    if (file.warnings.length) {
      for (const w of file.warnings) lines.push(`> ${w}`);
      lines.push('');
    }
    if (file.findings.length === 0) {
      lines.push('未发现已知风险写法。');
      lines.push('');
      continue;
    }

    for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
      const group = file.findings.filter((f) => f.severity === severity);
      if (!group.length) continue;
      lines.push(`### ${SEVERITY_HEADING[severity]}（${group.length}）`);
      lines.push('');
      for (const f of group) {
        lines.push(`- **${f.ruleId} ${f.ruleTitle}** · ${CATEGORY_LABEL[f.category] ?? f.category}`);
        lines.push(`  - 位置：\`${f.file}:${f.line}:${f.column}\` · \`${f.path}\``);
        lines.push(`  - 证据：\`${f.evidence.replace(/`/g, '\\`')}\``);
        lines.push(...bullet('  - 说明：', f.message));
        lines.push(...bullet('  - 建议：', f.advice));
        if (f.patch) {
          lines.push('  - 参考改法：');
          lines.push('    ```yaml');
          for (const pl of f.patch.split('\n')) lines.push(`    ${pl}`);
          lines.push('    ```');
        }
        if (f.references?.length) {
          lines.push(`  - 参考：${f.references.map((r) => `<${r}>`).join(' ')}`);
        }
      }
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');
  lines.push(
    '审查口径：特权事件（`pull_request_target` / `workflow_run` / `issue_comment` 等）下检出并执行 fork 代码、外部可控文本拼进脚本、令牌权限过大、第三方动作未固定提交哈希。分级按「外部贡献者能否借此拿到密钥或写权限」判断，仅供参考，不替代人工复核。',
  );
  lines.push('');
  return lines.join('\n');
}

/**
 * Strip an indent level rather than nesting: a flat list is more readable in a
 * pasted report. The rule text carries its own "1. 2. 3." steps, which render
 * as plain lines inside the bullet.
 */
function stripListIndent(text: string): string {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join('\n    ');
}

/** Return the whole field as a single Markdown list item (may be multi-line). */
function bullet(prefix: string, text: string): string[] {
  const body = stripListIndent(text);
  return [`${prefix}${body}`];
}

