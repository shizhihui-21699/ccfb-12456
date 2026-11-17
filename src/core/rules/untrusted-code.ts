/**
 * Rules: untrusted code execution (the class of bug that gets release keys
 * stolen).
 *
 * The shape is always the same: a privileged event (`pull_request_target`,
 * `workflow_run`, `issue_comment`, ...) gives the workflow the base repo's
 * secrets and a writable token, and then a step puts a fork's code into the
 * workspace and runs it.
 */

import type { Rule, RuleContext } from './context.ts';
import { anchorOf, jobPath, stepLabel, stepPath } from './context.ts';
import type { JobModel } from '../model.ts';
import { executesDownloadedArtifact, findUntrustedExecution, isPrivilegedEvent, triggersFor } from '../analysis.ts';
import type { UntrustedExecution } from '../analysis.ts';
import { isCheckoutAction } from '../model.ts';

const SUGGESTION = `把「执行外部代码」和「使用权限/密钥」拆成两个工作流：

1. \`pull_request\`（不带 \`_target\`）工作流负责构建与测试，它没有仓库密钥、GITHUB_TOKEN 只读。
2. 构建产物用 \`actions/upload-artifact\` 上传，不要上传含密钥的日志。
3. 需要写权限/发布的工作流用 \`workflow_run\` 触发，但 **只处理产物**，绝不 checkout 对方的 ref，也绝不执行对方仓库里的脚本。`;

function executionEvidence(kind: UntrustedExecution['kind']): string {
  switch (kind) {
    case 'checkout-head':
      return '`actions/checkout` 的 `ref:` 指向 PR head（fork 仓库的提交）。';
    case 'checkout-fork-repo':
      return '`actions/checkout` 的 `repository:`/`ref:` 指向 fork 仓库。';
    case 'manual-checkout':
      return '手工 `git fetch` / `gh pr checkout` 把 PR 的代码拉进了工作目录。';
    case 'workflow-run-head':
      return '`workflow_run` 触发后 checkout 了上游运行的 head SHA（来自 fork）。';
    case 'artifact-from-fork':
      return '下载了 \`workflow_run\` 上游（可能是 fork）产出的 artifact 并执行。';
    default:
      return '';
  }
}

function describeExecStep(exec: UntrustedExecution): string {
  if (!exec.executessCode) return '';
  const target = exec.execStep ?? exec.step;
  return `随后的步骤 \`${stepLabel(target)}\` 会构建/运行工作目录里的代码。`;
}

function untrustedCodeFinding(
  ctx: RuleContext,
  job: JobModel,
  exec: UntrustedExecution,
  eventLabel: string,
): void {
  const secrets = job.secretRefs.map((s) => s.name);
  const writes = job.permissions.writeScopes;
  const severity = exec.executessCode && (secrets.length > 0 || writes.length > 0) ? 'critical' : exec.executessCode ? 'critical' : 'high';

  const assets: string[] = [];
  if (secrets.length) assets.push(`密钥（${secrets.slice(0, 4).join(', ')}${secrets.length > 4 ? '…' : ''}）`);
  if (writes.length) assets.push(`可写 GITHUB_TOKEN（${writes.slice(0, 4).join(', ')}${writes.length > 4 ? '…' : ''}）`);
  if (job.permissions.oidc) assets.push('OIDC 令牌（可换取云厂商凭据）');

  const assetText = assets.length ? `这个任务同时持有${assets.join('、')}。` : '';

  ctx.sink.add({
    rule: {
      id: 'WF001',
      title: `${eventLabel} 下检出并执行外部贡献者的代码`,
      category: 'untrusted-code',
      severity,
      summary: '特权事件 + 检出 fork 代码 = 外部贡献者可以在你的仓库里执行任意命令。',
      references: [
        'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/',
        'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#preventing-pwn-requests',
      ],
    },
    severity,
    anchor: (() => {
      const a = anchorOf(ctx.source, exec.node ?? exec.step.node);
      if (!exec.executessCode || exec.execStep === exec.step) return a;
      // Extend to the step that actually runs the code, so the reader sees the
      // whole `checkout -> build` pair.
      const execAnchor = anchorOf(ctx.source, exec.execStep?.node);
      return { ...a, endLine: Math.max(a.endLine, execAnchor.endLine) };
    })(),
    path: stepPath(job, exec.step),
    evidence: exec.evidence || stepLabel(exec.step),
    message: `${eventLabel} 触发时，工作流运行在**基仓库**上下文里，默认能拿到仓库密钥和写权限的 GITHUB_TOKEN；而 ${executionEvidence(exec.kind)}${describeExecStep(exec)}${assetText}外部贡献者只要修改 fork 里的脚本/依赖，就能在你的 CI 里读到这些凭据。`,
    advice: `不要把外部代码带进特权任务。${SUGGESTION}`,
    patch: `# 安全拆分示意
---
# 1) 无特权：只在 fork 代码上跑测试
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>        # 默认就是 PR head，且没有密钥
        with: { persist-credentials: false }
      - run: npm ci && npm test
      - uses: actions/upload-artifact@<sha>
        with: { name: dist, path: dist/ }
---
# 2) 特权：只消费产物，不 checkout fork
on:
  workflow_run:
    workflows: [test]
    types: [completed]
permissions:
  contents: read
  pull-requests: write
jobs:
  comment:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@<sha>
        with: { run-id: '\${{ github.event.workflow_run.id }}', github-token: '\${{ github.token }}' }
      # 只读取产物里的文本/数字，绝不 \`source\`、\`sh\` 或执行产物里的脚本`,
  });
}

/** WF001: pull_request_target / issue_comment / etc. executing fork code. */
export const untrustedCheckoutRule: Rule = {
  meta: {
    id: 'WF001',
    title: '特权事件下检出并执行外部贡献者的代码',
    category: 'untrusted-code',
    severity: 'critical',
    summary: 'pull_request_target / workflow_run / issue_comment 等事件带密钥，不能检出 fork 代码。',
    references: ['https://securitylab.github.com/research/github-actions-preventing-pwn-requests/'],
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    if (!isPrivilegedEvent(triggers)) return;

    const event = ctx.model.triggers.find((t) =>
      ['pull_request_target', 'workflow_run', 'issue_comment', 'issues', 'discussion', 'discussion_comment'].includes(t.key),
    );
    const eventLabel = event ? `\`${event.raw}\`` : '特权事件';

    for (const job of ctx.model.jobs) {
      if (!job.steps.length) continue;
      const exec = findUntrustedExecution(ctx.model, job);
      if (!exec) continue;
      // Artifact handling is WF002's job; reporting both would double-count the
      // same root cause.
      if (exec.kind === 'artifact-from-fork') continue;
      untrustedCodeFinding(ctx, job, exec, eventLabel);
    }
  },
};

/**
 * WF002: `workflow_run` jobs that consume a fork-built artifact. Reported
 * separately so the advice can be artifact-specific even when the job is
 * download-only.
 */
export const workflowRunArtifactRule: Rule = {
  meta: {
    id: 'WF002',
    title: 'workflow_run 直接执行上游 artifact',
    category: 'untrusted-code',
    severity: 'critical',
    summary: '上游运行的产物可能由 fork 代码生成，只能当作不可信数据读取。',
    references: ['https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run'],
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    if (!triggers.includes('workflow_run')) return;

    for (const job of ctx.model.jobs) {
      const download = job.steps.find((s) => {
        const uses = (s.uses ?? '').toLowerCase();
        const runId = s.with.get('run-id')?.value ?? '';
        return (uses.includes('download-artifact') || (s.run && /gh\s+run\s+download/.test(s.run.text))) && /workflow_run\.id/.test(runId + (s.run?.text ?? ''));
      });
      if (!download) continue;

      const idx = job.steps.indexOf(download);
      const downloadPath = (download.with.get('path')?.value ?? '.').trim();
      const execStep = job.steps.slice(idx + 1).find((s) => executesDownloadedArtifact(s, downloadPath));
      if (!execStep) continue;
      // checkout-based execution is already reported by WF001
      if (job.steps.some((s) => isCheckoutAction(s.uses))) continue;

      const a = anchorOf(ctx.source, download.node);
      ctx.sink.add({
        rule: this.meta,
        severity: 'critical',
        anchor: a,
        path: stepPath(job, download),
        evidence: download.with.get('run-id')?.value ?? download.run?.text ?? stepLabel(download),
        message: `\`workflow_run\` 的上游可能是来自 fork 的 PR 构建，产物内容由外部贡献者控制；步骤 \`${stepLabel(execStep)}\` 把它当作可执行输入使用。攻击者可以在产物里塞一个可执行文件或脚本，在你的特权任务里执行。`,
        advice: `产物只能当**数据**读：用 \`pull_request_target\` 之外的只读任务解析，或把需要执行的逻辑放在工作流仓库自己的脚本里，并校验产物哈希/签名。绝不要 \`chmod +x\`、\`source\`、\`sh\` 或 \`./\` 执行下载来的文件。`,
        patch: `# 只解析产物里的数据，执行逻辑来自你审核过的本仓库脚本
- run: |
    node scripts/read-report.mjs dist/report.json
    # 绝不要：chmod +x dist/x && ./dist/x`,
        references: this.meta.references,
      });
    }
  },
};


/**
 * WF003: `pull_request` runs the fork's merge commit, but GitHub downgrades
 * GITHUB_TOKEN to read-only for fork PRs -- so a declared write scope is not by
 * itself exploitable there. What *is* exploitable is anything the downgrade does
 * not cover: repository secrets and OIDC tokens. Report only those.
 */
export const forkPrPrivilegeRule: Rule = {
  meta: {
    id: 'WF003',
    title: 'pull_request 上暴露了不随降级失效的凭据',
    category: 'untrusted-code',
    severity: 'high',
    summary: 'fork PR 会把 GITHUB_TOKEN 降为只读，但密钥与 OIDC 令牌不会。',
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    if (!triggers.includes('pull_request') || triggers.includes('pull_request_target')) return;

    for (const job of ctx.model.jobs) {
      const secrets = job.secretRefs;
      const oidc = job.permissions.oidc;
      if (!secrets.length && !oidc) continue;
      // `write-all` is reported by WF020 with the same fix; do not stack.
      if (job.permissions.writeAll) continue;

      const forks = job.steps.some((s) => isCheckoutAction(s.uses));
      const granted = [
        ...secrets.map((s) => `\`secrets.${s.name}\``),
        ...(oidc ? ['`id-token: write`（OIDC）'] : []),
      ].join('、');

      ctx.sink.add({
        rule: this.meta,
        severity: forks ? 'critical' : 'high',
        anchor: anchorOf(ctx.source, job.permissions.node ?? job.node),
        path: `${jobPath(job)}.${secrets.length ? 'steps' : 'permissions'}`,
        evidence: granted,
        message: `\`pull_request\` 事件跑的是 fork 的合并提交${forks ? '，该任务会检出并运行它' : ''}，而这个任务能拿到${granted}。GitHub 会把 fork PR 上的 \`GITHUB_TOKEN\` 降为只读，但**仓库密钥与 OIDC 令牌不受这个降级影响**，外部贡献者可以直接使用。`,
        advice: `\`pull_request\` 任务不要引用 \`secrets.*\`，也不要开 \`id-token: write\`。需要凭据的工作改成 \`workflow_run\` 触发并只消费产物，或改用 \`pull_request_target\` 但绝不 checkout fork 代码。`,
      });
    }
  },
};

export const untrustedCodeRules: Rule[] = [untrustedCheckoutRule, workflowRunArtifactRule, forkPrPrivilegeRule];
