/**
 * Rules: GITHUB_TOKEN permissions.
 *
 * Defaults depend on repository settings, so the audit cannot just look at
 * `permissions:` — it has to reason about what *would* be granted when the
 * block is absent, and about which job actually needs what.
 */

import type { Rule } from './context.ts';
import { anchorOf, jobPath } from './context.ts';
import type { JobModel } from '../model.ts';
import { findUntrustedExecution, triggersFor, isPrivilegedEvent } from '../analysis.ts';

const HIGH_VALUE_SCOPES = new Set([
  'contents',
  'actions',
  'packages',
  'id-token',
  'pull-requests',
  'issues',
  'security-events',
  'deployments',
]);

export const writeAllRule: Rule = {
  meta: {
    id: 'WF020',
    title: 'permissions 写成 write-all',
    category: 'permissions',
    severity: 'high',
    summary: '`write-all` 让 GITHUB_TOKEN 在所有作用域可写，等于把仓库交出去。',
    references: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token'],
  },
  run(ctx) {
    if (ctx.model.permissions.writeAll) {
      ctx.sink.add({
        rule: this.meta,
        severity: 'critical',
        anchor: anchorOf(ctx.source, ctx.model.permissions.node),
        path: 'permissions',
        evidence: 'permissions: write-all',
        message: '`write-all` 给 GITHUB_TOKEN 授予 contents、packages、actions 等全部写权限。任何一处脚本注入或未固定的第三方动作都能借此推送代码、发布包或篡改工作流。',
        advice: '改成按需声明，例如 `permissions: { contents: read }`；需要写评论就只加 `pull-requests: write`。',
        patch: 'permissions:\n  contents: read',
      });
    }

    for (const job of ctx.model.jobs) {
      if (job.permissions.source !== 'job' || !job.permissions.writeAll) continue;
      ctx.sink.add({
        rule: this.meta,
        severity: 'critical',
        anchor: anchorOf(ctx.source, job.permissions.node),
        path: `${jobPath(job)}.permissions`,
        evidence: 'permissions: write-all',
        message: `任务 \`${job.id}\` 的 GITHUB_TOKEN 全部作用域可写。这个任务里的任何注入点都能改写仓库。`,
        advice: '按任务实际需要声明作用域；不要用 `write-all` 图省事。',
        patch: 'permissions:\n  contents: read',
      });
    }
  },
};

export const missingPermissionsRule: Rule = {
  meta: {
    id: 'WF021',
    title: '未声明 permissions，继承仓库默认值',
    category: 'permissions',
    severity: 'medium',
    summary: '没有 `permissions:` 时，令牌权限由仓库/组织设置决定，可能是读写全部。',
  },
  run(ctx) {
    if (ctx.model.permissions.declared) return;
    // A workflow with no jobs is not worth flagging twice.
    if (!ctx.model.jobs.length) return;
    // If every job sets its own permissions, the workflow-level default never
    // applies.
    if (ctx.model.jobs.every((j) => j.permissions.source === 'job')) return;

    const triggers = triggersFor(ctx.model);
    const privileged = isPrivilegedEvent(triggers);
    const exec = ctx.model.jobs.some((j) => findUntrustedExecution(ctx.model, j));
    const forkPr = triggers.includes('pull_request');
    const severity = privileged && exec ? 'critical' : privileged ? 'high' : forkPr ? 'medium' : 'low';

    ctx.sink.add({
      rule: this.meta,
      severity,
      anchor: anchorOf(ctx.source, ctx.model.onNode ?? ctx.model.jobs[0].node),
      path: 'permissions',
      evidence: '（缺少 permissions 块）',
      message: `工作流没有声明 \`permissions:\`，令牌权限完全取决于仓库的默认设置。老仓库的默认值往往是「读写」，新仓库是「只读」；审计无法从这里判断实际权限，因此按最坏情况处理。${privileged ? '这个工作流又使用特权事件，一旦默认值是读写，风险会被放大。' : ''}`,
      advice: '每个工作流都显式写 `permissions:`，从 `contents: read` 起步，按需增加。',
      patch: 'permissions:\n  contents: read',
    });
  },
};

export const overbroadPermissionsRule: Rule = {
  meta: {
    id: 'WF022',
    title: '任务权限超出实际需要',
    category: 'permissions',
    severity: 'medium',
    summary: '只读构建却拿到 `contents: write` / `id-token: write`，一旦被利用就是提权。',
  },
  run(ctx) {
    // A workflow-level block applies to every job; report it once, on the first
    // job that inherits it, instead of repeating the same line per job.
    const reportedWorkflowScopes = new Set<string>();

    for (const job of ctx.model.jobs) {
      // `write-all` already says everything this rule would say.
      if (job.permissions.writeAll) continue;
      // A reusable-workflow call has no steps of its own; what the *called*
      // workflow needs is not visible here, so do not guess.
      if (job.reusableWorkflow) continue;
      // The Copilot agent setup job needs `contents: write` by design: the agent
      // commits through it. Not a finding.
      if (job.id === 'copilot-setup-steps' || job.id === 'copilot' || /copilot/i.test(job.name ?? '')) continue;
      const writeScopes = job.permissions.writeScopes.filter((s) => HIGH_VALUE_SCOPES.has(s));
      // `id-token: write` is reported separately by WF030.
      const meaningful = writeScopes.filter((s) => s !== 'id-token');
      if (!meaningful.length) continue;

      // Only speak when the job's steps are a closed set we understand. One
      // opaque third-party action is enough to make "it does not need this
      // scope" a guess, and a wrong guess here trains people to ignore the tool.
      const need = jobNeedsWrite(job);
      if (need.opaque) continue;
      let unexplained = meaningful.filter((s) => !need.scopes.has(s));
      if (job.permissions.source !== 'job') {
        unexplained = unexplained.filter((s) => !reportedWorkflowScopes.has(s));
        for (const s of unexplained) reportedWorkflowScopes.add(s);
      }
      if (!unexplained.length) continue;

      const exec = findUntrustedExecution(ctx.model, job);
      const privileged = isPrivilegedEvent(triggersFor(ctx.model));
      const severity: 'high' | 'medium' = privileged && exec?.executessCode ? 'high' : 'medium';

      ctx.sink.add({
        rule: this.meta,
        severity,
        anchor: anchorOf(ctx.source, job.permissions.node),
        path: `${jobPath(job)}.permissions`,
        evidence: unexplained.map((s) => `${s}: write`).join(', '),
        message: `任务 \`${job.id}\` 被授予 ${unexplained.map((s) => '`' + s + ': write`').join('、')}，但从步骤看它并不需要这些写权限${exec ? '；而这个任务还会执行外部代码' : ''}。多余的作用域会把「只读执行」升级成「可写仓库」。`,
        advice: `把这些作用域改回 \`read\` 或 \`none\`。若确实需要写，把写操作拆到单独的任务里，只在该任务声明写权限。`,
        patch: unexplained.map((s) => `  ${s}: read`).join('\n'),
      });
    }
  },
};

/**
 * Actions whose permission needs are known, or which cannot write. Anything not
 * in this list makes the job "opaque": we stop guessing rather than accuse.
 */
const READ_ONLY_ACTIONS =
  /^(?:actions\/(?:checkout|setup-\w+|cache(?:\/restore|\/save)?|upload-artifact|download-artifact)|docker\/(?:setup-buildx-action|setup-qemu-action)|pnpm\/action-setup|pnpm\/setup|oven-sh\/setup-bun|denoland\/setup-deno|ruby\/setup-ruby|golangci\/golangci-lint-action)/i;

const KNOWN_WRITE_ACTIONS =
  /^(?:actions\/github-script|peter-evans\/create-pull-request|peter-evans\/create-or-update-comment|softprops\/action-gh-release|actions\/create-release|actions\/upload-release-asset|peaceiris\/actions-gh-pages|codecov\/codecov-action|docker\/build-push-action|github\/codeql-action|pypa\/gh-action-pypi-publish)/i;

export interface JobPermissionNeed {
  scopes: Set<string>;
  /** A step we cannot reason about; suppress over-scope findings for the job. */
  opaque: boolean;
}

/**
 * Scopes a job plausibly needs, inferred from its steps.
 *
 * The failure mode to avoid is a confident "you do not need this" aimed at an
 * action whose implementation we cannot see. So: recognised read-only actions
 * and shell commands give us evidence, and anything else flips `opaque`.
 */
function jobNeedsWrite(job: JobModel): JobPermissionNeed {
  const scopes = new Set<string>();
  let opaque = false;

  const text = job.steps
    .map((s) => [s.uses ?? '', s.run?.text ?? '', ...[...s.with.values()].map((v) => v.value)].join('\n'))
    .join('\n');

  for (const step of job.steps) {
    const uses = (step.uses ?? '').trim();
    if (!uses) continue;
    if (uses.startsWith('./') || uses.startsWith('$/') || uses.startsWith('docker://')) {
      // Local actions and containers: their needs live elsewhere.
      opaque = true;
      continue;
    }
    if (READ_ONLY_ACTIONS.test(uses)) continue;
    if (KNOWN_WRITE_ACTIONS.test(uses)) {
      scopes.add('contents');
      scopes.add('pull-requests');
      if (/codeql|sarif|codecov|security/i.test(uses)) scopes.add('security-events');
      if (/gh-pages/.test(uses)) scopes.add('pages');
      if (/pypi|npm|publish|push-action/.test(uses)) scopes.add('packages');
      continue;
    }
    // Any other third-party action: assume it may need whatever is declared.
    opaque = true;
  }

  if (opaque) return { scopes, opaque };

  // Shell evidence, applied only once every action is understood.
  const shell = job.steps.map((s) => s.run?.text ?? '').join('\n');
  if (/\bgit\s+push\b|\bgh\s+(?:pr|release|issue|repo)\s+(?:create|edit|comment|merge|upload)\b|\bnpm\s+publish\b|\bdocker\s+push\b/i.test(shell)) {
    scopes.add('contents');
    scopes.add('pull-requests');
    if (/\bnpm\s+publish\b|\bdocker\s+push\b/.test(shell)) scopes.add('packages');
  }
  if (/\bactions\/(?:upload|delete)-artifact\b/i.test(text)) scopes.add('actions');
  if (/sarif|codeql/i.test(shell)) scopes.add('security-events');
  // Tools that comment on the PR without being a recognisable action.
  if (/--comment|commentWith|createComment|sticky-pull-request|addLabels/i.test(shell)) {
    scopes.add('pull-requests');
    scopes.add('issues');
  }

  return { scopes, opaque };
}

/**
 * WF030: `id-token: write` on a workflow that also runs untrusted code lets an
 * attacker mint cloud credentials, which is often worse than the token itself.
 */
export const oidcOnUntrustedRule: Rule = {
  meta: {
    id: 'WF030',
    title: '外部代码可达 id-token: write（OIDC 提权）',
    category: 'secrets',
    severity: 'critical',
    summary: '`id-token: write` 可换取云厂商的短期凭据，不能与不可信执行并存。',
    references: ['https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect'],
  },
  run(ctx) {
    for (const job of ctx.model.jobs) {
      if (!job.permissions.oidc) continue;
      const exec = findUntrustedExecution(ctx.model, job);
      const privileged = isPrivilegedEvent(triggersFor(ctx.model));
      if (!exec && !privileged) continue;

      // Cloud credentials are only reachable when the job actually exchanges
      // the token; otherwise the finding is weaker but still worth stating.
      const exchanges = job.steps.some((s) =>
        /aws-actions|azure\/login|google-github-actions|hashicorp\/vault-action|configure-aws-credentials/i.test(s.uses ?? ''),
      );
      const severity: 'critical' | 'high' | 'medium' = exec?.executessCode
        ? 'critical'
        : exec
          ? 'high'
          : exchanges
            ? 'high'
            : 'medium';

      ctx.sink.add({
        rule: this.meta,
        severity,
        anchor: anchorOf(ctx.source, job.permissions.node),
        path: `${jobPath(job)}.permissions`,
        evidence: 'id-token: write',
        message: `任务 \`${job.id}\` 允许申请 OIDC 令牌（\`id-token: write\`）${exec ? '，同时会执行外部代码' : ''}${exchanges ? '，并且使用了云厂商登录动作' : ''}。攻击者可以用它换取云环境的短期凭据，影响面往往超出仓库本身。`,
        advice: `只在真正需要向云厂商换取凭据的发布任务里开启 \`id-token: write\`，并让该任务不执行任何外部代码；对 OIDC 的 \`sub\` 声明做环境（environment）限制。`,
      });
    }
  },
};

export const permissionRules: Rule[] = [
  writeAllRule,
  missingPermissionsRule,
  overbroadPermissionsRule,
  oidcOnUntrustedRule,
];

