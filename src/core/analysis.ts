/**
 * Shared analysis: "does this job run code an outside contributor controls?"
 *
 * Almost every severity decision depends on this answer, so it is computed once
 * per job and shared by the rules. Keeping it in one place also means the web UI
 * and the CLI agree about what counts as untrusted execution.
 */

import type { Node } from 'yaml';
import type { JobModel, StepModel, WorkflowModel } from './model.ts';
import {
  UNTRUSTED_CODE_EVENTS,
  isCheckoutAction,
  looksLikeInstallOrBuild,
  looksLikeManualCheckout,
} from './model.ts';
import type { TriggerKey } from './model.ts';

export type UntrustedExecutionKind =
  | 'checkout-head'      // actions/checkout with ref pointing at the PR head
  | 'checkout-fork-repo' // actions/checkout with repository pointing at the fork
  | 'manual-checkout'    // git fetch/checkout of the PR ref by hand
  | 'workflow-run-head'  // workflow_run: checkout of the upstream run's head SHA
  | 'artifact-from-fork';// workflow_run: executing an artifact built by the fork

export interface UntrustedExecution {
  kind: UntrustedExecutionKind;
  step: StepModel;
  /** The `ref:`/`repository:`/command text that triggered the match. */
  evidence: string;
  line: number;
  node: Node | null;
  /** A later step in the same job builds/tests/runs something. */
  executessCode: boolean;
  /** Step that performs the execution, when it is different from `step`. */
  execStep?: StepModel;
}

const HEAD_REF_RE =
  /github\.(?:event\.pull_request\.head\.(?:sha|ref|label)|event\.pull_request\.merge_commit_sha|head_ref|event\.workflow_run\.head_(?:sha|branch))/;

/**
 * In a privileged workflow, a `ref:`/`repository:` built from *any* event field
 * is untrusted unless it is a known-safe field. Contributors control far more
 * of the payload than the documented "head.*" fields (e.g. `issue.pull_request`).
 */
const ANY_EVENT_FIELD_RE = /github\.(?:event|head_ref)\b/;
// Base-branch refs only. Head refs and merge SHAs are handled above and are
// deliberately absent: they carry the fork's code.
const SAFE_REF_FIELDS = new Set([
  'github.event.number',
  'github.event.pull_request.number',
  'github.event.pull_request.base.ref',
  'github.event.pull_request.base.sha',
  'github.ref',
  'github.ref_name',
  'github.sha',
]);
const FORK_REPO_RE = /github\.event\.pull_request\.head\.repo\.(?:full_name|clone_url|html_url|ssh_url)/;
const WORKFLOW_RUN_HEAD_RE = /github\.event\.workflow_run\.head_(?:sha|branch)/;
const PR_REF_RE = /refs\/pull\//;
const PR_NUMBER_RE = /github\.event\.(?:number|pull_request\.number)/;

/** Steps that would execute freshly checked-out code. */
export function performsExecution(step: StepModel): boolean {
  if (step.run) {
    const text = step.run.text;
    if (looksLikeInstallOrBuild(text)) return true;
    // Any shell script at all can execute checked-out code; only pure echo /
    // reporting steps are considered inert.
    const meaningful = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    return meaningful.some((l) => !/^(?:echo|printf|cat|ls|pwd|true|exit)\b/.test(l));
  }
  if (step.uses) {
    // Actions that build/test the working tree.
    return /\b(?:gradle|maven|setup-node|setup-python|setup-java|setup-go|setup-dotnet|rust-cache)\b/.test(step.uses);
  }
  return false;
}

function stepWithValue(step: StepModel, key: string): { value: string; line: number; node: Node | null } | null {
  const entry = step.with.get(key);
  if (!entry) return null;
  return { value: entry.value, line: entry.line, node: entry.node };
}

function classifyCheckout(step: StepModel, triggers: TriggerKey[]): UntrustedExecution | null {
  const refEntry = stepWithValue(step, 'ref');
  const repoEntry = stepWithValue(step, 'repository');
  const ref = refEntry?.value ?? '';
  const repo = repoEntry?.value ?? '';

  if (WORKFLOW_RUN_HEAD_RE.test(ref) && triggers.includes('workflow_run')) {
    return {
      kind: 'workflow-run-head',
      step,
      evidence: ref,
      line: refEntry?.line ?? step.line,
      node: refEntry?.node ?? step.node,
      executessCode: false,
    };
  }

  if (FORK_REPO_RE.test(repo) || FORK_REPO_RE.test(ref)) {
    return {
      kind: 'checkout-fork-repo',
      step,
      evidence: repo || ref,
      line: repoEntry?.line ?? step.line,
      node: repoEntry?.node ?? step.node,
      executessCode: false,
    };
  }

  if (HEAD_REF_RE.test(ref)) {
    return {
      kind: 'checkout-head',
      step,
      evidence: ref,
      line: refEntry?.line ?? step.line,
      node: refEntry?.node ?? step.node,
      executessCode: false,
    };
  }

  // `ref: refs/pull/123/merge` or `ref: ${{ github.event.number }}/merge`
  if (PR_REF_RE.test(ref) || (PR_NUMBER_RE.test(ref) && /head|merge/.test(ref))) {
    return {
      kind: 'checkout-head',
      step,
      evidence: ref,
      line: refEntry?.line ?? step.line,
      node: refEntry?.node ?? step.node,
      executessCode: false,
    };
  }

  return null;
}

/**
 * Fallback for privileged events: if the checkout `ref:`/`repository:` is built
 * from an event field we did not explicitly classify, treat it as untrusted --
 * the cost of a false positive here is a review comment, the cost of a false
 * negative is a leaked token.
 */
function classifyEventRefCheckout(step: StepModel, triggers: TriggerKey[]): UntrustedExecution | null {
  if (!triggers.some((t) => UNTRUSTED_CODE_EVENTS.has(t))) return null;
  for (const key of ['ref', 'repository'] as const) {
    const entry = stepWithValue(step, key);
    if (!entry) continue;
    if (!ANY_EVENT_FIELD_RE.test(entry.value)) continue;
    const fields = [...entry.value.matchAll(/github\.[\w.[\]'-]+/g)].map((m) => m[0].replace(/[.\]]+$/, ''));
    const onlySafe = fields.length > 0 && fields.every((f) => SAFE_REF_FIELDS.has(f));
    if (onlySafe) continue;
    return {
      kind: key === 'repository' ? 'checkout-fork-repo' : 'checkout-head',
      step,
      evidence: entry.value,
      line: entry.line,
      node: entry.node,
      executessCode: false,
    };
  }
  return null;
}

function classifyManualCheckout(step: StepModel): UntrustedExecution | null {
  if (!step.run) return null;
  const text = step.run.text;
  if (!looksLikeManualCheckout(text)) return null;
  const usesUntrusted =
    HEAD_REF_RE.test(text) ||
    PR_REF_RE.test(text) ||
    WORKFLOW_RUN_HEAD_RE.test(text) ||
    (PR_NUMBER_RE.test(text) && /pull|fetch|checkout/.test(text));
  if (!usesUntrusted) return null;
  const lineText = text
    .split('\n')
    .find((l) => HEAD_REF_RE.test(l) || PR_REF_RE.test(l) || WORKFLOW_RUN_HEAD_RE.test(l) || PR_NUMBER_RE.test(l));
  return {
    kind: 'manual-checkout',
    step,
    evidence: (lineText ?? text).trim(),
    line: step.run.line,
    node: step.run.node,
    executessCode: false,
  };
}

/**
 * Downloads an artifact produced by an untrusted workflow run and then runs
 * something. `actions/download-artifact` with the upstream run's id is the
 * classic artifact-poisoning sink.
 */
/**
 * Does this step treat the downloaded artifact as *code* rather than data?
 *
 * The distinction is the point of artifact handling: parsing
 * `results/report.json` with a script from your own repository is fine, while
 * `chmod +x dist/x && ./dist/x`, `source dist/env.sh`, or running `npm ci` after
 * the artifact was unpacked over the workspace root is not.
 */
export function executesDownloadedArtifact(step: StepModel, downloadPath: string): boolean {
  if (step.uses) {
    const uses = step.uses.trim();
    if (uses.startsWith('./')) return isUnder(uses.slice(2), downloadPath);
    return /^docker\s+build/i.test(uses);
  }
  const text = step.run?.text ?? '';
  if (!text) return false;

  const unpackedIntoWorkspace = downloadPath === '.' || downloadPath === '';
  if (
    unpackedIntoWorkspace &&
    /^\s*(?:npm\s+(?:ci|install|i|run|test)\b|pnpm\s+(?:i|install|run|test)\b|yarn(?:\s|$)|bun\s+(?:i|install|run|test)\b|make\b|cmake\b|gradlew?\b|mvn\b|tox\b|pytest\b|python3?\s+setup\.py\b)/m.test(
      text,
    )
  ) {
    return true;
  }

  for (const m of text.matchAll(
    /(?:^|[\s;&|(])(?:chmod\s+\+x\s+|source\s+|\.\s+|sh\s+|bash\s+|\/bin\/(?:ba)?sh\s+|node\s+|python3?\s+|\.\/)([^\s;&|)`]+)/g,
  )) {
    const target = m[1].replace(/^["']|["']$/g, '');
    if (isUnder(target, downloadPath)) return true;
  }
  return false;
}

/** Is `target` inside `dir`? A repo-owned script path at the root is not. */
function isUnder(target: string, dir: string): boolean {
  const clean = target.replace(/^\.\//, '');
  if (dir === '.' || dir === '') {
    // Workspace root: only report top-level executables, not repo scripts.
    return !clean.includes('/') || !/^(?:scripts|src|\.github|bin)\//.test(clean);
  }
  const base = dir.replace(/^\.\//, '').replace(/\/$/, '');
  return clean === base || clean.startsWith(`${base}/`);
}

function classifyArtifactFromFork(
  job: JobModel,
  triggers: TriggerKey[],
): UntrustedExecution | null {
  if (!triggers.includes('workflow_run')) return null;
  for (let i = 0; i < job.steps.length; i++) {
    const step = job.steps[i];
    const uses = (step.uses ?? '').toLowerCase();
    const runId = step.with.get('run-id')?.value ?? '';
    const downloads =
      uses.includes('download-artifact') ||
      (step.run ? /gh\s+run\s+download/.test(step.run.text) : false);
    if (!downloads) continue;
    const fromUpstream =
      /github\.event\.workflow_run\.id/.test(runId) ||
      (step.run ? /workflow_run\.id/.test(step.run.text) : false) ||
      (step.with.get('github-token') != null && /workflow_run/.test(step.with.get('github-token')?.value ?? ''));
    if (!fromUpstream) continue;
    const downloadPath = (step.with.get('path')?.value ?? '.').trim();
    const later = job.steps.slice(i + 1).find((s) => executesDownloadedArtifact(s, downloadPath));
    return {
      kind: 'artifact-from-fork',
      step,
      evidence: runId || step.run?.text?.trim() || step.uses || '',
      line: step.with.get('run-id')?.line ?? step.line,
      node: step.with.get('run-id')?.node ?? step.node,
      executessCode: Boolean(later),
      execStep: later,
    };
  }
  return null;
}

export function triggersFor(model: WorkflowModel): TriggerKey[] {
  return model.triggers.map((t) => t.key);
}

/** Events where the workflow runs with base-repo secrets and a writable token. */
export function isPrivilegedEvent(triggers: TriggerKey[]): boolean {
  return triggers.some((t) => UNTRUSTED_CODE_EVENTS.has(t));
}

/** Detect untrusted code execution inside a job, including downstream steps. */
export function findUntrustedExecution(
  model: WorkflowModel,
  job: JobModel,
): UntrustedExecution | null {
  const triggers = triggersFor(model);
  const privileged = isPrivilegedEvent(triggers);
  const checkoutEvents =
    triggers.some((t) => t === 'pull_request_target' || t === 'pull_request' || t === 'pull_request_review' || t === 'pull_request_review_comment') ||
    isPrivilegedEvent(triggers);

  // 1. A workflow_run job that executes an artifact from the upstream run.
  const artifact = classifyArtifactFromFork(job, triggers);
  if (artifact) {
    if (artifact.executessCode) return artifact;
    // Download-only is reported by a separate rule, still worth returning.
    if (privileged) return artifact;
  }

  // 2. Checkout steps pointing at an untrusted ref.
  for (let i = 0; i < job.steps.length; i++) {
    const step = job.steps[i];
    if (isCheckoutAction(step.uses) && checkoutEvents) {
      // Plain `actions/checkout` (no ref) on `pull_request` checks out the
      // fork's merge commit.
      if (!step.with.has('ref') && !step.with.has('repository') && triggers.includes('pull_request')) {
        const later = job.steps.slice(i + 1).find(performsExecution);
        return {
          kind: 'checkout-head',
          step,
          evidence: 'actions/checkout（默认检出 PR 合并提交）',
          line: step.line,
          node: step.node,
          executessCode: Boolean(later),
          execStep: later,
        };
      }
      const hit = classifyCheckout(step, triggers) ?? classifyEventRefCheckout(step, triggers);
      if (hit) {
        const later = job.steps.slice(i + 1).find(performsExecution);
        hit.executessCode = Boolean(later);
        if (later) hit.execStep = later;
        return hit;
      }
    }
    const manual = classifyManualCheckout(step);
    if (manual) {
      const later = job.steps.slice(i + 1).find(performsExecution);
      manual.executessCode = Boolean(later) || performsExecution(step);
      if (later) manual.execStep = later;
      return manual;
    }
  }

  return null;
}

