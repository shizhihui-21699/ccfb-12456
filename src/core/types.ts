/**
 * Shared types for the workflow audit engine.
 *
 * Severity model:
 *   critical – an external contributor can turn this into code execution with
 *              repository secrets or a write-scoped token.
 *   high     – realistic escalation path or direct secret exposure.
 *   medium   – weakens defence in depth; needs a second bug to matter.
 *   low      – hygiene / hardening.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

export type Category =
  | 'untrusted-code'      // checking out and running a fork's code
  | 'script-injection'    // attacker-controlled data interpolated into a shell
  | 'permissions'         // GITHUB_TOKEN / OIDC over-scoped
  | 'supply-chain'        // third-party action not pinned to a commit
  | 'secrets'             // secrets reachable from untrusted code
  | 'runner'              // self-hosted runners on untrusted events
  | 'hygiene';

export type TriggerEvent =
  | 'pull_request'
  | 'pull_request_target'
  | 'workflow_run'
  | 'issue_comment'
  | 'issues'
  | 'discussion'
  | 'discussion_comment'
  | 'push'
  | 'workflow_dispatch'
  | 'workflow_call'
  | 'schedule'
  | 'release'
  | 'merge_group'
  | 'other';

export interface Finding {
  /** stable id, e.g. `r001:jobs.build.steps[2]` */
  id: string;
  ruleId: string;
  ruleTitle: string;
  severity: Severity;
  category: Category;
  file: string;
  /** 1-based */
  line: number;
  /** 1-based */
  column: number;
  endLine: number;
  /** YAML path inside the document, e.g. `jobs.build.steps[2].run` */
  path: string;
  /** The offending expression / value, trimmed for display. */
  evidence: string;
  /** Why this is dangerous, in one or two sentences. */
  message: string;
  /** Concrete change to make. */
  advice: string;
  /** Optional suggested replacement YAML / shell. */
  patch?: string;
  /** Further reading. */
  references?: string[];
}

export interface RuleMeta {
  id: string;
  title: string;
  category: Category;
  /** default severity; rules may escalate per finding */
  severity: Severity;
  summary: string;
  references?: string[];
}

export interface WorkflowJobReport {
  id: string;
  name?: string;
  line: number;
  runsOn: string[];
  /** Does this job check out the pull request head (fork code)? */
  checksOutUntrustedCode: boolean;
  /** write scopes granted to GITHUB_TOKEN at job or workflow level */
  writePermissions: string[];
}

export interface WorkflowReport {
  /** display name, falls back to the file path */
  name: string;
  file: string;
  triggers: TriggerEvent[];
  /** raw trigger keys, as written in the YAML */
  rawTriggers: string[];
  jobs: WorkflowJobReport[];
  findings: Finding[];
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
  /** parse problems, if any */
  errors: string[];
  /** non-fatal notes, e.g. "file has no `on:` block" */
  warnings: string[];
}

export interface AuditReport {
  generatedAt: string;
  toolVersion: string;
  files: WorkflowReport[];
  totals: Record<Severity, number> & { findings: number; files: number };
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
}
