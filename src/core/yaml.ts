/**
 * Source text + YAML node helpers.
 *
 * The audit needs line/column positions for two different things: the node a
 * value lives on (for the finding anchor) and the exact offset of a `${{ }}`
 * expression inside a block scalar (for the whiteboard highlight). YAML's
 * `range` gives us the first; for the second we search the raw source slice,
 * which is accurate because block scalars keep their text verbatim apart from
 * leading indentation.
 */

import { isMap, isScalar, isSeq, parseDocument, type Document, type Node } from 'yaml';

export interface Position {
  offset: number;
  /** 1-based */
  line: number;
  /** 1-based, counted in UTF-16 code units */
  column: number;
}

export class SourceText {
  readonly path: string;
  readonly text: string;
  readonly lineStarts: number[];

  constructor(path: string, text: string) {
    this.path = path;
    this.text = text;
    const starts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text[i] === '\n') starts.push(i + 1);
    }
    this.lineStarts = starts;
  }

  position(offset: number): Position {
    const clamped = Math.max(0, Math.min(offset, this.text.length));
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid] <= clamped) lo = mid;
      else hi = mid - 1;
    }
    return { offset: clamped, line: lo + 1, column: clamped - this.lineStarts[lo] + 1 };
  }

  lineText(line: number): string {
    const start = this.lineStarts[line - 1] ?? 0;
    const end = line < this.lineStarts.length ? this.lineStarts[line] - 1 : this.text.length;
    return this.text.slice(start, Math.max(start, end));
  }

  lineCount(): number {
    return this.lineStarts.length;
  }
}

export interface ParsedWorkflow {
  doc: Document.Parsed;
  source: SourceText;
  errors: string[];
}

export function parseWorkflowText(path: string, text: string): ParsedWorkflow {
  const source = new SourceText(path, text);
  let doc: Document.Parsed;
  try {
    doc = parseDocument(text, { keepSourceTokens: true, prettyErrors: false, uniqueKeys: false });
  } catch (err) {
    return { doc: parseDocument('', {}) as Document.Parsed, source, errors: [String(err)] };
  }
  const errors = doc.errors.map((e) => `${e.linePos?.[0]?.line ?? '?'}: ${e.message}`);
  return { doc, source, errors };
}

/** Map lookup that tolerates missing / non-map nodes. */
export function mapGet(node: unknown, key: string): Node | undefined {
  if (!isMap(node)) return undefined;
  for (const pair of node.items) {
    const k = pair.key;
    if (isScalar(k) && String(k.value) === key) return pair.value as Node | undefined;
  }
  return undefined;
}

/** Key node lookup, for anchoring a finding on the key rather than the value. */
export function mapKeyNode(node: unknown, key: string): Node | undefined {
  if (!isMap(node)) return undefined;
  for (const pair of node.items) {
    const k = pair.key;
    if (isScalar(k) && String(k.value) === key) return k as Node;
  }
  return undefined;
}

export function mapPairs(node: unknown): Array<{ key: string; keyNode: Node; value: Node | undefined }> {
  if (!isMap(node)) return [];
  const out: Array<{ key: string; keyNode: Node; value: Node | undefined }> = [];
  for (const pair of node.items) {
    if (isScalar(pair.key)) {
      out.push({ key: String(pair.key.value), keyNode: pair.key as Node, value: pair.value as Node | undefined });
    }
  }
  return out;
}

export function seqItems(node: unknown): Node[] {
  if (!isSeq(node)) return [];
  return node.items.filter((i): i is Node => Boolean(i));
}

export function scalarValue(node: unknown): string | null {
  if (isScalar(node) && node.value != null) return String(node.value);
  return null;
}

export function scalarBoolean(node: unknown): boolean | null {
  if (!isScalar(node)) return null;
  if (node.value === true || node.value === 'true') return true;
  if (node.value === false || node.value === 'false') return false;
  return null;
}

