/**
 * Workflow model: turns a parsed YAML document into the handful of structures
 * the rules care about (triggers, jobs, steps, permissions, checkout behaviour)
 * and attaches source positions to each of them.
 */

import { isMap, isScalar, isSeq, type Node } from 'yaml';
import type { SourceText } from './yaml.ts';
import { mapGet, mapKeyNode, mapPairs, scalarValue, seqItems } from './yaml.ts';
import { findExpressions } from './expressions.ts';

export type TriggerKey =
  | 'pull_request'
  | 'pull_request_target'
  | 'workflow_run'
  | 'issue_comment'
  | 'issues'
  | 'discussion'
  | 'discussion_comment'
  | 'pull_request_review'
  | 'pull_request_review_comment'
  | 'push'
  | 'workflow_dispatch'
  | 'workflow_call'
  | 'schedule'
  | 'release'
  | 'merge_group'
  | 'repository_dispatch'
  | 'gollum'
  | 'other';

/**
 * Events where the workflow gets the base repository's secrets and a
 * write-capable token while an outside contributor can still influence the
 * payload (or the code that gets checked out).
 */
export const UNTRUSTED_CODE_EVENTS: ReadonlySet<TriggerKey> = new Set<TriggerKey>([
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'issues',
  'discussion',
  'discussion_comment',
  'pull_request_review',
  'pull_request_review_comment',
]);

/** Events where the workflow executes code from a pull request head. */
export const PR_CODE_EVENTS: ReadonlySet<TriggerKey> = new Set<TriggerKey>([
  'pull_request',
  'pull_request_target',
  'pull_request_review',
  'pull_request_review_comment',
]);

const KNOWN_TRIGGERS: ReadonlySet<string> = new Set<string>([
  'pull_request',
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'issues',
  'discussion',
  'discussion_comment',
  'pull_request_review',
  'pull_request_review_comment',
  'push',
  'workflow_dispatch',
  'workflow_call',
  'schedule',
  'release',
  'merge_group',
  'repository_dispatch',
  'workflow_run',
  'create',
  'delete',
  'deployment',
  'deployment_status',
  'fork',
  'gollum',
  'label',
  'milestone',
  'page_build',
  'public',
  'pull_request_review_comment',
  'registry_package',
  'status',
  'watch',
  'branch_protection_rule',
  'check_run',
  'check_suite',
  'merge_group',
  'projects_v2',
  'projects_v2_item',
  'workflow_job',
]);

export interface ScalarModel {
  key: string;
  value: string;
  node: Node;
  line: number;
}

export interface RunModel {
  text: string;
  node: Node;
  line: number;
}

export interface StepModel {
  index: number;
  node: Node;
  line: number;
  name: string | null;
  /** `uses:` value for action steps. */
  uses: string | null;
  usesLine: number | null;
  /** `run:` value for shell steps. */
  run: RunModel | null;
  /** `with:` entries. */
  with: Map<string, ScalarModel>;
  /** `env:` entries. */
  env: Map<string, ScalarModel>;
  /** `if:` expression. */
  ifExpr: ScalarModel | null;
  /** `script:` inside actions/github-script style steps. */
  script: ScalarModel | null;
}

export interface PermissionsModel {
  /** where the effective permissions were declared */
  source: 'workflow' | 'job' | 'default';
  node: Node | null;
  /** `permissions: write-all` */
  writeAll: boolean;
  /** `permissions: read-all` */
  readAll: boolean;
  /** explicit scope -> level */
  scopes: Map<string, string>;
  /** scopes set to `write` */
  writeScopes: string[];
  /** scopes set to `none` */
  noneScopes: string[];
  /** `id-token: write` */
  oidc: boolean;
  /** `permissions: {}` */
  empty: boolean;
  /** whether the workflow declares any permissions block at all */
  declared: boolean;
  line: number | null;
}

export interface JobModel {
  id: string;
  node: Node;
  line: number;
  name: string | null;
  runsOn: string[];
  runsOnNode: Node | null;
  selfHosted: boolean;
  permissions: PermissionsModel;
  steps: StepModel[];
  /** job-level `env:` */
  env: Map<string, ScalarModel>;
  /** reusable workflow reference (`jobs.<id>.uses`) */
  reusableWorkflow: string | null;
  reusableWorkflowLine: number | null;
  secretsInherit: boolean;
  /** `strategy.matrix` values keyed by matrix variable */
  matrix: Map<string, ScalarModel>;
  /** secret names reachable from this job */
  secretRefs: Array<{ name: string; line: number; path: string }>;
}

export interface TriggerModel {
  key: TriggerKey;
  raw: string;
  node: Node | null;
  line: number | null;
  /** `types:` filters on a pull_request trigger */
  types: string[];
}

export interface WorkflowModel {
  name: string | null;
  nameLine: number | null;
  triggers: TriggerModel[];
  onNode: Node | null;
  permissions: PermissionsModel;
  jobs: JobModel[];
  /** workflow-level env */
  env: Map<string, ScalarModel>;
  secretRefs: Array<{ name: string; line: number; path: string }>;
  errors: string[];
  warnings: string[];
}

const CHECKOUT_RE = /^(?:[A-Za-z0-9_.-]+\/)?checkout@/;
const INSTALL_RE =
  /\b(?:npm\s+(?:ci|install|i)\b|npm\s+run\b|yarn(?:\s|$)|pnpm\s+(?:i|install|run)\b|bun\s+(?:i|install|run|x)\b|pip3?\s+install\b|poetry\s+install\b|uv\s+(?:sync|pip)\b|bundle\s+(?:install|exec)\b|composer\s+(?:install|update)\b|mvn\b|\.\/mvnw\b|gradle\b|\.\/gradlew\b|cargo\s+(?:build|test|run)\b|go\s+(?:build|test|run|generate)\b|make\b|cmake\b|dotnet\s+(?:build|test|run|restore)\b|tox\b|pytest\b|python3?\s+\S*setup\.py\b|node\s+\S+\.(?:js|mjs|cjs|ts)\b|bash\s+\S+\.sh\b|sh\s+\S+\.sh\b)/;

/** Commands that pull the pull request's code into the workspace by hand. */
const MANUAL_CHECKOUT_RE =
  /\bgit\s+(?:fetch|checkout|switch|pull|reset|clone)\b|\bgh\s+pr\s+(?:checkout|diff)\b|refs\/pull\//;

export function isCheckoutAction(uses: string | null): boolean {
  if (!uses) return false;
  return CHECKOUT_RE.test(uses.trim());
}

export function looksLikeInstallOrBuild(command: string): boolean {
  return INSTALL_RE.test(command);
}

export function looksLikeManualCheckout(command: string): boolean {
  return MANUAL_CHECKOUT_RE.test(command);
}

export function parseStep(node: Node, index: number, source: SourceText): StepModel {
  const line = source.position(node.range?.[0] ?? 0).line;
  const usesNode = mapGet(node, 'uses');
  const uses = scalarValue(usesNode);
  const runNode = mapGet(node, 'run');
  const runText = scalarValue(runNode);
  const nameNode = scalarValue(mapGet(node, 'name'));

  const withMap = new Map<string, ScalarModel>();
  const withNode = mapGet(node, 'with');
  for (const { key, value } of mapPairs(withNode)) {
    const v = scalarValue(value);
    if (v == null || !value?.range) continue;
    withMap.set(key, { key, value: v, node: value, line: source.position(value.range[0]).line });
  }

  const envMap = new Map<string, ScalarModel>();
  for (const { key, value } of mapPairs(mapGet(node, 'env'))) {
    const v = scalarValue(value);
    if (v == null || !value?.range) continue;
    envMap.set(key, { key, value: v, node: value, line: source.position(value.range[0]).line });
  }

  const ifNode = mapGet(node, 'if');
  const ifValue = scalarValue(ifNode);
  const scriptNode = mapGet(node, 'script');
  const scriptValue = scalarValue(scriptNode);

  return {
    index,
    node,
    line,
    name: nameNode,
    uses,
    usesLine: usesNode?.range ? source.position(usesNode.range[0]).line : null,
    run:
      runNode && runText != null
        ? { text: runText, node: runNode, line: source.position(runNode.range?.[0] ?? 0).line }
        : null,
    with: withMap,
    env: envMap,
    ifExpr:
      ifNode && ifValue != null
        ? { key: 'if', value: ifValue, node: ifNode, line: source.position(ifNode.range?.[0] ?? 0).line }
        : null,
    script:
      scriptNode && scriptValue != null
        ? { key: 'script', value: scriptValue, node: scriptNode, line: source.position(scriptNode.range?.[0] ?? 0).line }
        : null,
  };
}

function parsePermissions(node: Node | undefined, source: SourceText): PermissionsModel {
  const model: PermissionsModel = {
    source: 'default',
    node: node ?? null,
    writeAll: false,
    readAll: false,
    scopes: new Map(),
    writeScopes: [],
    noneScopes: [],
    oidc: false,
    empty: false,
    declared: Boolean(node),
    line: node?.range ? source.position(node.range[0]).line : null,
  };
  if (!node) return model;
  const scalar = scalarValue(node);
  if (scalar != null) {
    const v = scalar.trim();
    if (v === 'write-all') model.writeAll = true;
    else if (v === 'read-all') model.readAll = true;
    else if (v === '{}' || v === '') model.empty = true;
    if (model.writeAll) applyWriteAll(model);
    return model;
  }
  if (isMap(node)) {
    if (node.items.length === 0) model.empty = true;
    for (const { key, value } of mapPairs(node)) {
      const level = (scalarValue(value) ?? '').trim().toLowerCase();
      if (!level) continue;
      model.scopes.set(key, level);
      if (level === 'write') model.writeScopes.push(key);
      if (level === 'none') model.noneScopes.push(key);
      if (key === 'id-token' && level === 'write') model.oidc = true;
    }
  }
  if (model.writeAll) applyWriteAll(model);
  return model;
}

/** Every scope a `write-all` token is granted (the full documented set). */
function applyWriteAll(model: PermissionsModel): void {
  model.writeScopes = [
    'actions',
    'attestations',
    'checks',
    'contents',
    'deployments',
    'discussions',
    'id-token',
    'issues',
    'models',
    'packages',
    'pages',
    'pull-requests',
    'repository-projects',
    'security-events',
    'statuses',
  ];
  model.oidc = true;
  for (const s of model.writeScopes) model.scopes.set(s, 'write');
}

function parseRunsOn(node: Node | undefined): string[] {
  if (!node) return [];
  const scalar = scalarValue(node);
  if (scalar != null) return [scalar.trim()];
  if (isSeq(node)) {
    return seqItems(node)
      .map((i) => scalarValue(i))
      .filter((v): v is string => v != null)
      .map((v) => v.trim());
  }
  if (isMap(node)) {
    const labels = seqItems(mapGet(node, 'labels'))
      .map((i) => scalarValue(i))
      .filter((v): v is string => v != null);
    const group = scalarValue(mapGet(node, 'group'));
    return group ? [group, ...labels] : labels;
  }
  return [];
}

function collectSecrets(
  node: Node | null | undefined,
  source: SourceText,
  path: string,
): Array<{ name: string; line: number; path: string }> {
  const text = nodeText(node);
  if (!text) return [];
  const hits: Array<{ name: string; line: number; path: string }> = [];
  for (const m of findExpressions(text)) {
    for (const hit of m.expr.matchAll(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
      const pos = node?.range ? source.position(node.range[0] + m.index) : null;
      hits.push({ name: hit[1], line: pos?.line ?? 0, path });
    }
  }
  return hits;
}

/** Serialize a node subtree so expressions can be scanned across all of it. */
function nodeText(node: Node | null | undefined): string {
  if (!node) return '';
  const parts: string[] = [];
  const walk = (n: unknown): void => {
    if (!n) return;
    if (isScalar(n)) {
      if (n.value != null) parts.push(String(n.value));
      return;
    }
    if (isSeq(n)) {
      for (const item of n.items) walk(item);
      return;
    }
    if (isMap(n)) {
      for (const pair of n.items) {
        walk(pair.key);
        walk(pair.value);
      }
      return;
    }
    if (Array.isArray(n)) for (const item of n) walk(item);
  };
  walk(node);
  return parts.join('\n');
}

function parseStepList(node: Node | undefined, source: SourceText): StepModel[] {
  return seqItems(node).map((item, index) => parseStep(item, index, source));
}

function parseMatrix(jobNode: Node, source: SourceText): Map<string, ScalarModel> {
  const out = new Map<string, ScalarModel>();
  const matrixNode = mapGet(mapGet(jobNode, 'strategy'), 'matrix');
  if (!isMap(matrixNode)) return out;
  for (const { key, value } of mapPairs(matrixNode)) {
    if (key === 'include' || key === 'exclude') continue;
    const text = nodeText(value);
    if (!text || !value?.range) continue;
    out.set(key, { key, value: text, node: value, line: source.position(value.range[0]).line });
  }
  return out;
}

function normalizeTrigger(raw: string): TriggerKey {
  const v = raw.trim();
  if (KNOWN_TRIGGERS.has(v)) return v as TriggerKey;
  return 'other';
}

function parseTriggers(
  onNode: Node | undefined,
  source: SourceText,
): { triggers: TriggerModel[]; warnings: string[] } {
  const warnings: string[] = [];
  if (!onNode) return { triggers: [], warnings };

  const push = (raw: string, node: Node | null): TriggerModel => {
    const key = normalizeTrigger(raw);
    const line = node?.range ? source.position(node.range[0]).line : null;
    const types: string[] = [];
    if (node) {
      const typesNode = mapGet(node, 'types');
      if (isSeq(typesNode)) {
        for (const item of seqItems(typesNode)) {
          const v = scalarValue(item);
          if (v) types.push(v);
        }
      }
    }
    if (key === 'other') warnings.push(`未知触发器 \`${raw}\`，按通用事件处理。`);
    return { key, raw, node, line, types };
  };

  // `on: push`, `on: [push, pull_request]`, `on: { push: {...} }`
  const scalar = scalarValue(onNode);
  if (scalar != null) return { triggers: [push(scalar, onNode)], warnings };

  if (isSeq(onNode)) {
    return {
      triggers: seqItems(onNode).map((item) => push(scalarValue(item) ?? '', item)),
      warnings,
    };
  }

  if (isMap(onNode)) {
    const triggers: TriggerModel[] = [];
    for (const { key, keyNode, value } of mapPairs(onNode)) {
      // `on: { pull_request_target: { types: [opened] } }` – value may be null
      triggers.push(push(key, value && !isNullNode(value) ? value : keyNode));
    }
    if (triggers.length === 0) warnings.push('`on:` 为空，工作流不会触发。');
    return { triggers, warnings };
  }

  warnings.push('无法解析 `on:` 块。');
  return { triggers: [], warnings };
}

function isNullNode(node: Node): boolean {
  return isScalar(node) && node.value == null;
}

export function buildModel(
  doc: { contents: unknown },
  source: SourceText,
  errors: string[],
): WorkflowModel {
  const root = doc.contents as Node | null;
  const warnings: string[] = [];
  if (!root || !isMap(root)) {
    return {
      name: null,
      nameLine: null,
      triggers: [],
      onNode: null,
      permissions: parsePermissions(undefined, source),
      jobs: [],
      env: new Map(),
      secretRefs: [],
      errors: errors.length ? errors : ['文件内容不是 YAML 映射。'],
      warnings,
    };
  }

  const nameNode = mapGet(root, 'name');
  const name = scalarValue(nameNode);

  // `on` may be written with quotes; also accept the YAML 1.1 boolean key `true`.
  let onNode = mapGet(root, 'on');
  let onKeyNode = mapKeyNode(root, 'on');
  if (!onNode) {
    for (const { key, keyNode, value } of mapPairs(root)) {
      if (key === 'true' || key === 'True') {
        onNode = value;
        onKeyNode = keyNode;
        warnings.push('`on:` 被 YAML 1.1 解析成布尔键，请加引号。');
        break;
      }
    }
  }
  void onKeyNode;

  const { triggers, warnings: triggerWarnings } = parseTriggers(onNode, source);
  warnings.push(...triggerWarnings);

  const permissions = parsePermissions(mapGet(root, 'permissions'), source);

  const env = new Map<string, ScalarModel>();
  for (const { key, value } of mapPairs(mapGet(root, 'env'))) {
    const v = scalarValue(value);
    if (v == null || !value?.range) continue;
    env.set(key, { key, value: v, node: value, line: source.position(value.range[0]).line });
  }

  const jobs: JobModel[] = [];
  const jobsNode = mapGet(root, 'jobs');
  if (jobsNode && isMap(jobsNode)) {
    for (const { key: jobId, value: jobNode } of mapPairs(jobsNode)) {
      if (!jobNode?.range) continue;
      const jobLine = source.position(jobNode.range[0]).line;
      const jobPermNode = mapGet(jobNode, 'permissions');
      const jobPermissions = jobPermNode
        ? { ...parsePermissions(jobPermNode, source), source: 'job' as const }
        : { ...permissions, source: permissions.declared ? ('workflow' as const) : ('default' as const) };

      const runsOnNode = mapGet(jobNode, 'runs-on');
      const runsOn = parseRunsOn(runsOnNode);
      const selfHosted = runsOn.some((label) => label.toLowerCase() === 'self-hosted');

      const jobEnv = new Map<string, ScalarModel>();
      for (const { key, value } of mapPairs(mapGet(jobNode, 'env'))) {
        const v = scalarValue(value);
        if (v == null || !value?.range) continue;
        jobEnv.set(key, { key, value: v, node: value, line: source.position(value.range[0]).line });
      }

      const reusableNode = mapGet(jobNode, 'uses');
      const reusable = scalarValue(reusableNode);
      const secretsNode = mapGet(jobNode, 'secrets');
      const secretsInherit = (scalarValue(secretsNode) ?? '').trim() === 'inherit';

      const steps = parseStepList(mapGet(jobNode, 'steps'), source);

      const jobSecretRefs: Array<{ name: string; line: number; path: string }> = [];
      // Steps and job env are the places secrets usually appear.
      for (const step of steps) {
        jobSecretRefs.push(...collectSecrets(step.node, source, `jobs.${jobId}.steps[${step.index}]`));
      }
      jobSecretRefs.push(...collectSecrets(mapGet(jobNode, 'env'), source, `jobs.${jobId}.env`));
      jobSecretRefs.push(...collectSecrets(mapGet(jobNode, 'with'), source, `jobs.${jobId}.with`));

      jobs.push({
        id: jobId,
        node: jobNode,
        line: jobLine,
        name: scalarValue(mapGet(jobNode, 'name')),
        runsOn,
        runsOnNode: runsOnNode ?? null,
        selfHosted,
        permissions: jobPermissions,
        steps,
        env: jobEnv,
        reusableWorkflow: reusable,
        reusableWorkflowLine: reusableNode?.range ? source.position(reusableNode.range[0]).line : null,
        secretsInherit,
        matrix: parseMatrix(jobNode, source),
        secretRefs: dedupeSecretRefs(jobSecretRefs),
      });
    }
    if (!permissions.declared && !jobs.every((j) => j.permissions.source === 'job')) {
      warnings.push('未声明工作流级 `permissions:`，未单独声明的任务会继承仓库默认权限。');
    }
  } else {
    warnings.push('缺少 `jobs:` 块。');
  }

  return {
    name,
    nameLine: nameNode?.range ? source.position(nameNode.range[0]).line : null,
    triggers,
    onNode: onNode ?? null,
    permissions,
    jobs,
    env,
    secretRefs: dedupeSecretRefs(collectSecrets(mapGet(root, 'env'), source, 'env')),
    errors,
    warnings,
  };
}

function dedupeSecretRefs(
  refs: Array<{ name: string; line: number; path: string }>,
): Array<{ name: string; line: number; path: string }> {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = `${r.path}:${r.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function jobTriggerKeys(model: WorkflowModel): TriggerKey[] {
  return model.triggers.map((t) => t.key);
}

export function hasTrigger(model: WorkflowModel, key: TriggerKey): boolean {
  return model.triggers.some((t) => t.key === key);
}

