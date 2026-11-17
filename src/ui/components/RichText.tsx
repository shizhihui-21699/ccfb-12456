/**
 * Minimal inline formatter for rule text.
 *
 * Rule messages are written with `code`, **bold**, fenced code blocks and blank
 * lines between paragraphs. Rendering them as plain text leaves visible
 * backticks and asterisks, so this turns them into elements -- and only those
 * constructs, never raw HTML, because the strings can carry attacker-authored
 * evidence such as a pull request title.
 */

import type { ComponentChildren } from 'preact';

type Token = { kind: 'text' | 'code' | 'bold'; text: string };

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)/g;

function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let last = 0;
  for (const match of text.matchAll(INLINE)) {
    const index = match.index ?? 0;
    if (index > last) tokens.push({ kind: 'text', text: text.slice(last, index) });
    const raw = match[0];
    if (raw.startsWith('`')) tokens.push({ kind: 'code', text: raw.slice(1, -1) });
    else tokens.push({ kind: 'bold', text: raw.slice(2, -2) });
    last = index + raw.length;
  }
  if (last < text.length) tokens.push({ kind: 'text', text: text.slice(last) });
  return tokens;
}

function Inline({ text }: { text: string }) {
  return (
    <>
      {tokenize(text).map((token, i) => {
        if (token.kind === 'code') return <code key={i}>{token.text}</code>;
        if (token.kind === 'bold') return <strong key={i}>{token.text}</strong>;
        return <span key={i}>{token.text}</span>;
      })}
    </>
  );
}

interface Block {
  kind: 'prose' | 'code';
  /** for code blocks */
  lang?: string;
  lines: string[];
}

/** Split on ``` fences first, then on blank lines inside prose. */
function toBlocks(text: string): Block[] {
  const blocks: Block[] = [];
  const fence = /```([\w-]*)\n([\s\S]*?)```/g;
  let cursor = 0;
  let match: RegExpExecArray | null;

  const pushProse = (chunk: string) => {
    if (!chunk.trim()) return;
    for (const para of chunk.split(/\n{2,}/)) {
      if (para.trim()) blocks.push({ kind: 'prose', lines: para.split('\n') });
    }
  };

  while ((match = fence.exec(text)) !== null) {
    pushProse(text.slice(cursor, match.index));
    blocks.push({ kind: 'code', lang: match[1] || undefined, lines: match[2].replace(/\n$/, '').split('\n') });
    cursor = match.index + match[0].length;
  }
  pushProse(text.slice(cursor));
  return blocks;
}

/**
 * Render text with paragraphs, line breaks, inline code/bold and fenced code
 * blocks. Everything goes through Preact's text nodes, so a PR title that
 * contains `<script>` stays inert.
 */
export function RichText({ text }: { text: string }) {
  const blocks = toBlocks(text);
  const children: ComponentChildren[] = blocks.map((block, i) => {
    if (block.kind === 'code') {
      return (
        <pre class="rich-code" key={i}>
          <code>{block.lines.join('\n')}</code>
        </pre>
      );
    }
    return (
      <p key={i}>
        {block.lines.map((line, li) => (
          <span key={li}>
            <Inline text={line} />
            {li < block.lines.length - 1 ? <br /> : null}
          </span>
        ))}
      </p>
    );
  });
  return <div class="rich">{children}</div>;
}
