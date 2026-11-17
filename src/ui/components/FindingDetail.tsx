/**
 * Detail panel for one finding: what it is, why it matters, the exact fix.
 */

import { useState } from 'preact/hooks';
import type { Finding } from '../../core/types.ts';
import { SEVERITY_LABEL, CATEGORY_LABEL } from '../labels.ts';
import { RichText } from './RichText.tsx';

export function FindingDetail({
  finding,
  onShowSource,
}: {
  finding: Finding;
  onShowSource: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: leave the text selectable */
    }
  };

  return (
    <article class={`detail sev-${finding.severity}`}>
      <header class="detail-head">
        <div class="detail-badges">
          <span class={`sev-pill sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
          <span class="cat-pill">{CATEGORY_LABEL[finding.category] ?? finding.category}</span>
          <code class="rule-id">{finding.ruleId}</code>
        </div>
        <h2 class="detail-title">
          <RichText text={finding.ruleTitle} />
        </h2>
        <div class="detail-loc">
          <code>{finding.path}</code>
          <button class="link" onClick={onShowSource}>跳到源码第 {finding.line} 行 →</button>
        </div>
      </header>

      <section class="detail-block">
        <h3>证据</h3>
        <div class="evidence">
          <code>{finding.evidence}</code>
          <button class="copy" onClick={() => void copy(finding.evidence)}>
            {copied ? '已复制' : '复制'}
          </button>
        </div>
      </section>

      <section class="detail-block">
        <h3>为什么危险</h3>
        <div class="prose">
          <RichText text={finding.message} />
        </div>
      </section>

      <section class="detail-block advice">
        <h3>怎么改</h3>
        <div class="prose">
          <RichText text={finding.advice} />
        </div>
        {finding.patch && (
          <div class="patch">
            <div class="patch-head">
              <span>参考改法</span>
              <button class="copy" onClick={() => void copy(finding.patch ?? '')}>
                {copied ? '已复制' : '复制'}
              </button>
            </div>
            <pre>
              <code>{finding.patch}</code>
            </pre>
          </div>
        )}
      </section>

      {finding.references && finding.references.length > 0 && (
        <section class="detail-block refs">
          <h3>参考</h3>
          <ul>
            {finding.references.map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noreferrer noopener">
                  {r.replace(/^https?:\/\//, '').slice(0, 80)}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </article>
  );
}
