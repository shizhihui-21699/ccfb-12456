/**
 * Source viewer with line numbers, finding gutter markers and a highlighted
 * range. Uses the exact line/column of each finding so the highlight lands on
 * the expression rather than the whole step.
 */

import { useMemo } from 'preact/hooks';
import type { Finding } from '../../core/types.ts';
import { SEVERITY_LABEL, SEVERITY_RANK } from '../labels.ts';

export function SourceView({
  path,
  text,
  highlightLines,
  findings = [],
  onSelectFinding,
  compact = false,
}: {
  path: string;
  text: string;
  /** [start, end] inclusive, 1-based */
  highlightLines: number[];
  findings?: Finding[];
  onSelectFinding?: (id: string) => void;
  compact?: boolean;
}) {
  const lines = useMemo(() => text.replace(/\r\n/g, '\n').split('\n'), [text]);
  const [start, end] = highlightLines.length ? highlightLines : [0, 0];

  const byLine = useMemo(() => {
    const map = new Map<number, Finding[]>();
    for (const f of findings) {
      for (let l = f.line; l <= Math.max(f.line, f.endLine); l++) {
        const arr = map.get(l) ?? [];
        arr.push(f);
        map.set(l, arr);
      }
    }
    for (const arr of map.values()) {
      arr.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    }
    return map;
  }, [findings]);

  const gutterWidth = String(lines.length).length;

  if (!text.trim()) {
    return <div class="source-view empty">（文件为空）</div>;
  }

  return (
    <div class={`source-view ${compact ? 'compact' : ''}`}>
      <div class="source-head">
        <code>{path}</code>
        <span class="muted">{lines.length} 行</span>
      </div>
      <div class="source-scroll">
        <table class="source-table">
          <tbody>
            {lines.map((line, index) => {
              const lineNo = index + 1;
              const hits = byLine.get(lineNo) ?? [];
              const worst = hits[0];
              const inRange = start > 0 && lineNo >= start && lineNo <= end;
              return (
                <tr
                  key={lineNo}
                  class={`${inRange ? 'hl' : ''} ${worst ? 'has-finding' : ''}`}
                  id={`line-${lineNo}`}
                >
                  <td class="gutter" style={{ width: `${gutterWidth + 2}ch` }}>
                    {worst && (
                      <button
                        class={`gutter-mark sev-${worst.severity}`}
                        title={hits.map((h) => `${h.ruleId} ${SEVERITY_LABEL[h.severity]}`).join('\n')}
                        onClick={() => onSelectFinding?.(worst.id)}
                        aria-label={`第 ${lineNo} 行：${hits.map((h) => h.ruleTitle).join('，')}`}
                      />
                    )}
                  </td>
                  <td class="line-no">{lineNo}</td>
                  <td class="code">
                    <code>{line || ' '}</code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
