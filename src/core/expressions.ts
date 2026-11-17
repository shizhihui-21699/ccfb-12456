/**
 * Expression scanner for `${{ ... }}` and the catalog of contexts an outside
 * contributor can write to.
 *
 * Positions matter: a finding that says "line 42" but points at the whole
 * `run:` block is hard to act on, so every match keeps its own offset inside
 * the scalar it came from.
 */

import type { TriggerKey } from './model.ts';

export type { TriggerKey };

export interface ExpressionMatch {
  /** Full text including the `${{` / `}}` delimiters. */
  raw: string;
  /** Trimmed inner expression. */
  expr: string;
  /** Offset of the `${{` within the searched string. */
  index: number;
  /** Offset of the inner expression (after `${{` and whitespace). */
  innerIndex: number;
}

/** Find all `${{ ... }}` occurrences, tolerating nested braces inside strings. */
export function findExpressions(text: string): ExpressionMatch[] {
  const out: ExpressionMatch[] = [];
  let i = 0;
  while (i < text.length) {
    const start = text.indexOf('${{', i);
    if (start < 0) break;
    let j = start + 3;
    let depth = 1;
    let quote: string | null = null;
    while (j < text.length) {
      const ch = text[j];
      if (quote) {
        if (ch === '\\') j++;
        else if (ch === quote) quote = null;
        j++;
        continue;
      }
      if (ch === '\'' || ch === '"') {
        quote = ch;
        j++;
        continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          // expect `}}`
          if (text[j + 1] === '}') {
            const raw = text.slice(start, j + 2);
            const inner = text.slice(start + 3, j);
            out.push({
              raw,
              expr: inner.trim(),
              index: start,
              innerIndex: start + 3 + (inner.length - inner.trimStart().length),
            });
            i = j + 2;
          } else {
            i = j + 1;
          }
          break;
        }
        j++;
        continue;
      }
      j++;
    }
    if (j >= text.length) break;
  }
  return out;
}

/**
 * Contexts that an outside contributor controls. Anything here lands in a
 * workflow without passing through the repository's own review, so it must be
 * treated as hostile text.
 *
 * `confirmed` entries are fields that GitHub documents as attacker-writable in
 * the matching event. `suspicious` entries are generic shapes (`*.title`) used
 * to catch custom event payloads — they are reported as "possible" so the
 * console can rank them below the documented ones.
 */
export interface UntrustedSource {
  pattern: RegExp;
  label: string;
  confidence: 'confirmed' | 'possible';
  /** Events in which this field is attacker-controlled. */
  events: TriggerKey[];
}

const PR_EVENTS: TriggerKey[] = ['pull_request', 'pull_request_target'];

export const UNTRUSTED_SOURCES: UntrustedSource[] = [
  { pattern: /^github\.event\.pull_request\.title$/, label: 'PR title', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.body$/, label: 'PR description', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.head\.ref$/, label: 'PR head branch name', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.head\.label$/, label: 'PR head label (owner:branch)', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.head\.sha$/, label: 'PR head commit SHA', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.head\.repo\.(full_name|name|owner\.login)$/, label: 'fork repository name', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.pull_request\.(user|sender)\.login$/, label: 'contributor login', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.head_ref$/, label: 'PR head branch name', confidence: 'confirmed', events: PR_EVENTS },
  { pattern: /^github\.event\.issue\.title$/, label: 'issue title', confidence: 'confirmed', events: ['issues', 'issue_comment'] },
  { pattern: /^github\.event\.issue\.body$/, label: 'issue body', confidence: 'confirmed', events: ['issues', 'issue_comment'] },
  { pattern: /^github\.event\.label\.name$/, label: 'PR/issue label', confidence: 'confirmed', events: ['issues', 'pull_request', 'pull_request_target'] },
  { pattern: /^github\.event\.comment\.body$/, label: 'comment body', confidence: 'confirmed', events: ['issue_comment', 'pull_request_review_comment'] as TriggerKey[] },
  { pattern: /^github\.event\.review\.body$/, label: 'review body', confidence: 'confirmed', events: ['pull_request_review'] as TriggerKey[] },
  { pattern: /^github\.event\.review_comment\.body$/, label: 'review comment body', confidence: 'confirmed', events: ['pull_request_review_comment'] as TriggerKey[] },
  { pattern: /^github\.event\.discussion\.(title|body)$/, label: 'discussion text', confidence: 'confirmed', events: ['discussion', 'discussion_comment'] },
  { pattern: /^github\.event\.discussion_comment\.body$/, label: 'discussion comment', confidence: 'confirmed', events: ['discussion_comment'] },
  { pattern: /^github\.event\.pages\[[^\]]*\]\.page_name$/, label: 'wiki page name', confidence: 'confirmed', events: ['gollum'] },
  { pattern: /^github\.event\.commits\[[^\]]*\]\.(message|author\.(name|email))$/, label: 'commit message / author', confidence: 'confirmed', events: ['push'] },
  { pattern: /^github\.event\.head_commit\.(message|author\.(name|email))$/, label: 'head commit message / author', confidence: 'confirmed', events: ['push'] },
  { pattern: /^github\.event\.workflow_run\.head_branch$/, label: 'upstream branch name', confidence: 'confirmed', events: ['workflow_run'] },
  { pattern: /^github\.event\.workflow_run\.head_sha$/, label: 'upstream commit SHA', confidence: 'confirmed', events: ['workflow_run'] },
  { pattern: /^github\.event\.workflow_run\.head_repository\.full_name$/, label: 'upstream repository', confidence: 'confirmed', events: ['workflow_run'] },
  { pattern: /^github\.event\.workflow_run\.display_title$/, label: 'upstream run title', confidence: 'confirmed', events: ['workflow_run'] },
  { pattern: /^github\.event\.client_payload\./, label: 'repository_dispatch client payload', confidence: 'confirmed', events: ['repository_dispatch'] },
  { pattern: /^github\.event\.release\.(name|body|tag_name)$/, label: 'release name / body / tag', confidence: 'confirmed', events: ['release'] },
  { pattern: /^github\.event\.inputs\./, label: 'workflow_dispatch input', confidence: 'possible', events: ['workflow_dispatch'] },
  { pattern: /^inputs\./, label: 'workflow_call / dispatch input', confidence: 'possible', events: ['workflow_dispatch', 'workflow_call'] },

  // Generic shapes for payloads we did not enumerate above.
  { pattern: /^github\.event\.[\w.[\]'-]*\.(title|body|message)$/, label: 'event title / body / message', confidence: 'possible', events: ['other'] },
  { pattern: /^github\.event\.[\w.[\]'-]*\.head\.ref$/, label: 'event head branch', confidence: 'possible', events: ['other'] },
  { pattern: /^github\.event\.[\w.[\]'-]*\.label$/, label: 'event label', confidence: 'possible', events: ['other'] },
  { pattern: /^github\.event\.[\w.[\]'-]*\.labels?(?:\.[\w.*[\]'-]+)*$/, label: 'event label', confidence: 'possible', events: ['other'] },
  { pattern: /^github\.event\.[\w.[\]'-]*\.(?:branch|tag_name|ref)$/, label: 'event branch / tag', confidence: 'possible', events: ['other'] },
];

/** Extremely common hand-written mistakes that are not worth a "possible" hit. */
const TRUSTED_EXACT = new Set([
  'github.event_name',
  'github.event.action',
  'github.run_id',
  'github.run_number',
  'github.repository',
  'github.repository_owner',
  'github.actor',
  'github.sha',
  'github.ref',
  'github.ref_name',
  'github.workspace',
  'github.event.number',
  'github.event.pull_request.number',
  'github.event.pull_request.base.ref',
  'github.event.pull_request.base.sha',
  'github.event.pull_request.merged',
  'github.event.workflow_run.conclusion',
  'github.event.workflow_run.id',
  'github.event.workflow_run.event',
]);

export interface UntrustedUse {
  source: UntrustedSource;
  /** The sub-expression that matched, e.g. `github.event.pull_request.title`. */
  path: string;
}

/**
 * Does this expression read attacker-controlled data in the given triggers?
 * `github.actor` etc. are explicitly allowed; `secrets.*` is handled by other
 * rules.
 */
export function findUntrustedUse(expr: string, triggers: TriggerKey[]): UntrustedUse | null {
  // An expression can contain several context reads -- `fromJSON(github.event
  // .pull_request.labels.*.name)[0]` or `format('{0}', github.head_ref)`. Test
  // every `github.*`/`inputs.*` path it mentions, not just the first operand.
  const paths = [...expr.matchAll(/\b(?:github|inputs)\.[\w.*[\]'-]+/g)].map((m) =>
    m[0].replace(/[.\]]+$/, ''),
  );
  if (paths.length === 0) paths.push(expr.replace(/\s+/g, ''));

  for (const path of paths) {
    if (TRUSTED_EXACT.has(path)) continue;
    for (const source of UNTRUSTED_SOURCES) {
      if (!source.pattern.test(path)) continue;
      const eventMatch = source.events.some((e) => triggers.includes(e));
      const generic = source.events.length === 1 && source.events[0] === 'other';
      if (eventMatch || generic) {
        return { source, path };
      }
    }
  }
  return null;
}

/** Does a scalar read any `secrets.*` value? */
export function findSecrets(text: string): string[] {
  const names = new Set<string>();
  for (const m of findExpressions(text)) {
    for (const hit of m.expr.matchAll(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
      names.add(hit[1]);
    }
  }
  return [...names];
}
