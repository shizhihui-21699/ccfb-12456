/**
 * Rules: secret handling and runner trust.
 */

import type { Rule } from './context.ts';
import { anchorOf, jobPath, stepPath } from './context.ts';
import { findUntrustedExecution, isPrivilegedEvent, triggersFor } from '../analysis.ts';
import { findSecrets } from '../expressions.ts';
import { isCheckoutAction } from '../model.ts';

/**
 * WF050: a job that runs untrusted code and also references secrets. WF001
 * covers the general case; this rule catches the narrower variants (secret in
 * `env:`, `secrets: inherit` on a reusable workflow, secrets passed to a
 * third-party action).
 */
export const secretExposureRule: Rule = {
  meta: {
    id: 'WF050',
    title: '密钥与不可信执行处于同一任务',
    category: 'secrets',
    severity: 'critical',
    summary: '一旦任务里执行了外部代码，其中出现的任何 `secrets.*` 都可被读走。',
    references: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-secrets'],
  },
  run(ctx) {
    for (const job of ctx.model.jobs) {
      const exec = findUntrustedExecution(ctx.model, job);
      // Merely downloading a fork's artifact is not exposure; the artifact has
      // to actually be run (that is WF002's finding).
      if (!exec?.executessCode) continue;
      if (job.secretRefs.length === 0 && !job.secretsInherit) continue;

      const names = [...new Set(job.secretRefs.map((r) => r.name))];
      const first = job.secretRefs[0];
      const anchor = first?.line
        ? { line: first.line, column: 1, endLine: first.line }
        : anchorOf(ctx.source, job.permissions.node ?? job.node);

      const evidence = job.secretsInherit
        ? 'secrets: inherit'
        : names.map((n) => `secrets.${n}`).join(', ');

      // Prefer the expression position when we can find it.
      const runTexts: Array<{ text: string; node: typeof job.node }> = [];
      for (const st of job.steps) {
        if (st.run) runTexts.push({ text: st.run.text, node: st.run.node });
        if (st.script) runTexts.push({ text: st.script.value, node: st.script.node });
      }
      const exprNode = runTexts.find((r) => findSecrets(r.text).length > 0);
      const pos = exprNode
        ? (() => {
            const hit = findSecrets(exprNode.text)[0];
            const idx = exprNode.text.indexOf(`secrets.${hit}`);
            return { line: ctx.source.position((exprNode.node.range?.[0] ?? 0) + Math.max(0, idx)).line };
          })()
        : null;

      ctx.sink.add({
        rule: this.meta,
        severity: 'critical',
        anchor: pos ? { line: pos.line, column: 1, endLine: pos.line } : anchor,
        path: first?.path ?? `${jobPath(job)}.secrets`,
        evidence,
        message: `任务 \`${job.id}\` 既执行外部代码，又能访问${job.secretsInherit ? '调用方继承的全部密钥（`secrets: inherit`）' : `密钥 ${names.map((n) => '`' + n + '`').join('、')}`}。任务级密钥对整个任务的所有步骤可见，外部代码只要出现在任意一步，就能把它拿走。`,
        advice: `把密钥移到不执行外部代码的独立任务；确需在同一流程里使用时，用 \`workflow_run\` + 产物传递，并把写操作放在只有它才拿密钥的任务里。`,
      });
    }
  },
};

/**
 * WF051: secrets in `pull_request` workflows from forks. GitHub refuses to
 * supply repository secrets to fork PRs, so the job silently fails — but
 * environment secrets and `pull_request_target` are not covered by that guard.
 */
export const forkPrSecretRule: Rule = {
  meta: {
    id: 'WF051',
    title: 'pull_request 中引用密钥，fork 贡献者会静默失败或拿到环境密钥',
    category: 'secrets',
    severity: 'medium',
    summary: 'fork PR 拿不到仓库密钥；若用的是 environment 密钥或用到了 target 事件则可能泄露。',
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    const isForkPr = triggers.includes('pull_request') && !triggers.includes('pull_request_target');
    const isTarget = triggers.includes('pull_request_target');
    if (!isForkPr && !isTarget) return;

    for (const job of ctx.model.jobs) {
      if (job.secretRefs.length === 0) continue;
      const exec = findUntrustedExecution(ctx.model, job);
      if (isTarget) continue; // covered by WF001/WF050 with sharper advice
      if (exec) continue;
      const names = [...new Set(job.secretRefs.map((r) => r.name))];
      ctx.sink.add({
        rule: this.meta,
        severity: 'medium',
        anchor: anchorOf(ctx.source, job.permissions.node ?? job.node),
        path: `${jobPath(job)}.env`,
        evidence: names.map((n) => `secrets.${n}`).join(', '),
        message: `\`pull_request\` 工作流引用了密钥。来自 fork 的 PR 不会拿到仓库级密钥，任务会失败或静默跳过；如果这些是 environment 密钥，fork 代码即可直接读取。`,
        advice: `需要密钥的步骤不要放在 \`pull_request\` 上；改成 \`pull_request_target\` 但**不 checkout fork 代码**，或改用 \`workflow_run\` 在可信上下文里处理产物。`,
      });
    }
  },
};

/** WF052: a token written into a log or an artifact. */
export const secretEchoRule: Rule = {
  meta: {
    id: 'WF052',
    title: '将密钥回显到日志或写入产物',
    category: 'secrets',
    severity: 'high',
    summary: '日志与产物可能被外部读取；`echo ${{ secrets.X }}` 会让密钥永久留在运行记录里。',
  },
  run(ctx) {
    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        if (!step.run) continue;
        const text = step.run.text;
        if (!/secrets\./.test(text)) continue;
        const echoes = /(?:^|\n)\s*(?:echo|printf|cat\s*<<|set\s+-x|tee\b)/.test(text);
        const uploads = job.steps.some((s) => /upload-artifact/.test(s.uses ?? ''));
        if (!echoes && !uploads) continue;
        const name = findSecrets(text)[0];
        if (!name) continue;
        const a = anchorOf(ctx.source, step.run.node);
        ctx.sink.add({
          rule: this.meta,
          severity: 'high',
          anchor: a,
          path: `${stepPath(job, step)}.run`,
          evidence: `secrets.${name}`,
          message: `脚本里出现 \`secrets.${name}\`，且会${echoes ? '输出到日志' : ''}${echoes && uploads ? '并' : ''}${uploads ? '被打包进 artifact' : ''}。运行日志对拥有仓库读权限的人（包括部分外部协作者）可见，artifact 也可能被下载。`,
          advice: `不要打印密钥；需要调试时输出长度/哈希前缀。确需传给下游时用 artifact 之外的受控渠道，并设置 artifact 保留期。`,
        });
      }
    }
  },
};

/** WF060: self-hosted runners must never run untrusted code. */
export const selfHostedRule: Rule = {
  meta: {
    id: 'WF060',
    title: '自托管 runner 上执行外部代码',
    category: 'runner',
    severity: 'critical',
    summary: '自托管 runner 通常保留状态、内网访问和长期凭据；fork 代码在其上等于入侵。',
    references: ['https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security'],
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    const untrustedEvents =
      triggers.includes('pull_request') ||
      isPrivilegedEvent(triggers);
    if (!untrustedEvents) return;

    for (const job of ctx.model.jobs) {
      if (!job.selfHosted) continue;
      const exec = findUntrustedExecution(ctx.model, job);
      const checksOut = job.steps.some((s) => isCheckoutAction(s.uses));
      if (!exec && !checksOut) continue;

      ctx.sink.add({
        rule: this.meta,
        severity: 'critical',
        anchor: anchorOf(ctx.source, job.runsOnNode ?? job.node),
        path: `${jobPath(job)}.runs-on`,
        evidence: `runs-on: ${job.runsOn.join(', ')}`,
        message: `任务 \`${job.id}\` 在自托管 runner 上运行，并且处理来自外部的事件（${triggers.join(', ')}）。自托管 runner 往往能访问内网、宿主机的 Docker socket 和本地缓存的凭据，外部贡献者在此执行代码即可横向移动。`,
        advice: `外部事件一律使用 \`ubuntu-latest\` 等 GitHub 托管 runner。必须在自托管机器上运行时，只让受保护分支/受信任事件触发，并让 runner 用一次性、无凭据的隔离环境（如临时的 VM/容器）。`,
      });
    }
  },
};

/** WF061: `pull_request_target` with `persist-credentials` left on. */
export const persistCredentialsRule: Rule = {
  meta: {
    id: 'WF061',
    title: 'checkout 保留凭据令牌',
    category: 'hygiene',
    severity: 'medium',
    summary: '`persist-credentials: true`（默认）会把令牌写进 `.git/config`，后续脚本可读取。',
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    if (!isPrivilegedEvent(triggers) && !triggers.includes('pull_request')) return;
    for (const job of ctx.model.jobs) {
      // On a plain `pull_request` the token is read-only for forks, so a token
      // sitting in `.git/config` is not worth a finding unless the job can write.
      if (!isPrivilegedEvent(triggers) && job.permissions.writeScopes.length === 0) continue;
      for (const step of job.steps) {
        if (!isCheckoutAction(step.uses)) continue;
        const persist = step.with.get('persist-credentials');
        const value = persist?.value.trim().toLowerCase();
        if (value === 'false') continue;
        const exec = findUntrustedExecution(ctx.model, job);
        if (!exec && !isPrivilegedEvent(triggers)) continue;
        // A read-only token in `.git/config` is not itself a privilege boundary;
        // it matters when the same job can write or runs untrusted code.
        const writable = job.permissions.writeScopes.length > 0;
        if (!exec && !writable) continue;
        ctx.sink.add({
          rule: this.meta,
          severity: exec ? 'high' : 'medium',
          anchor: anchorOf(ctx.source, step.node),
          path: `${stepPath(job, step)}.with`,
          evidence: persist ? `persist-credentials: ${persist.value}` : '（未设置 persist-credentials）',
          message: `checkout 默认把 \`GITHUB_TOKEN\` 写进工作目录的 \`.git/config\`${exec ? '，而同一任务随后的步骤会执行外部代码' : ''}。任何能读取该文件的脚本都可以拿到令牌。`,
          advice: '给所有 checkout 加上 `with: { persist-credentials: false }`；需要推送时再显式传入只读/专用的令牌。',
          patch: 'with:\n  persist-credentials: false',
        });
      }
    }
  },
};

export const secretRules: Rule[] = [secretExposureRule, forkPrSecretRule, secretEchoRule];
export const runnerRules: Rule[] = [selfHostedRule, persistCredentialsRule];
