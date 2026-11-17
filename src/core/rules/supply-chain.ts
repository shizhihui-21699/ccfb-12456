/**
 * Rules: third-party action supply chain.
 *
 * Two hazards get conflated in review comments: "uses `@v4`" is convenient but
 * mutable, and `uses: some-user/repo@v1` from an unknown publisher is code
 * execution straight into the job. Both are reported here so the fix reads
 * naturally (pin to a commit SHA belonging to a publisher you chose).
 */

import type { Rule } from './context.ts';
import { anchorOf, jobPath, stepPath } from './context.ts';
import { findUntrustedExecution, isPrivilegedEvent, triggersFor } from '../analysis.ts';

/** Official publishers whose actions are usually safe to consume. */
const FIRST_PARTY = new Set(['actions', 'github']);

/** Actions that are expected to be referenced by tag (workflow repo itself). */
const LOCAL_ACTION_RE = /^(?:\.\/|\$\/|docker:\/\/)/;

const FULL_SHA_RE = /^[0-9a-f]{40}$/i;
const SHORT_SHA_RE = /^[0-9a-f]{7,39}$/i;
const TAG_RE = /^(?:v?\d+(?:\.\d+){0,2}|main|master|latest|HEAD|stable|release|next|dev)$/i;

function splitUses(uses: string): { owner: string; repo: string; ref: string; subpath: string } | null {
  const trimmed = uses.trim();
  if (!trimmed || LOCAL_ACTION_RE.test(trimmed)) return null;
  const at = trimmed.lastIndexOf('@');
  if (at <= 0) return { owner: '', repo: trimmed, ref: '', subpath: '' };
  const left = trimmed.slice(0, at);
  const ref = trimmed.slice(at + 1);
  const parts = left.split('/');
  if (parts.length < 2) return { owner: '', repo: left, ref, subpath: '' };
  return {
    owner: parts[0],
    repo: parts[1],
    ref,
    subpath: parts.slice(2).join('/'),
  };
}

function classifyRef(ref: string): 'sha' | 'tag' | 'branch' | 'missing' | 'short-sha' {
  if (!ref) return 'missing';
  if (FULL_SHA_RE.test(ref)) return 'sha';
  if (TAG_RE.test(ref) || /^v\d+(?:\.\d+){0,2}$/i.test(ref)) return 'tag';
  if (SHORT_SHA_RE.test(ref)) return 'short-sha';
  return 'branch';
}

export const unpinnedActionRule: Rule = {
  meta: {
    id: 'WF040',
    title: '第三方动作未固定到提交哈希',
    category: 'supply-chain',
    severity: 'medium',
    summary: '`@v4` / `@main` 这类引用可变：上游改标签或被接管后，你的流水线会执行新代码。',
    references: [
      'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions',
      'https://blog.gitguardian.com/github-actions-security-cheat-sheet/',
    ],
  },
  run(ctx) {
    const triggers = triggersFor(ctx.model);
    const privileged = isPrivilegedEvent(triggers);
    const jobsExec = ctx.model.jobs.some((j) => findUntrustedExecution(ctx.model, j));

    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        if (!step.uses) continue;
        const parsed = splitUses(step.uses);
        if (!parsed) continue;
        const kind = classifyRef(parsed.ref);
        if (kind === 'sha') continue;
        if (kind === 'missing') {
          ctx.sink.add({
            rule: this.meta,
            severity: 'high',
            anchor: anchorOf(ctx.source, step.node),
            path: `${stepPath(job, step)}.uses`,
            evidence: step.uses,
            message: `\`uses:\` 没有写版本。GitHub 会拒绝，但若被改成默认分支引用，行为完全不可控。`,
            advice: '固定到完整 40 位提交哈希，并在同行的注释里记录对应版本，便于 Dependabot 升级。',
          });
          continue;
        }

        const official = FIRST_PARTY.has(parsed.owner.toLowerCase());
        const severity =
          !official && privileged && jobsExec ? 'high' : !official && privileged ? 'high' : official ? 'low' : 'medium';

        const reason =
          kind === 'tag'
            ? `\`@${parsed.ref}\` 是可移动标签：发布者（或任何能接管该仓库的人）可以把它指向新提交，下次运行就会执行未审计的代码。`
            : kind === 'short-sha'
              ? `\`@${parsed.ref}\` 是短哈希，GitHub 仍会解析到某个提交，但缩写可能撞车，且不便于验证。`
              : `\`@${parsed.ref}\` 看起来是一个分支，分支会移动，等价于让发布者随时修改你的流水线。`;

        const trust =
          official
            ? '这是 GitHub 官方动作，风险相对低，但仍建议固定哈希以防上游被攻破。'
            : `\`${parsed.owner}\` 不是 GitHub 官方发布者；把它固定到该仓库某个具体提交，并确认这个提交是你审计过的版本。`;

        ctx.sink.add({
          rule: this.meta,
          severity,
          anchor: anchorOf(ctx.source, step.node),
          path: `${stepPath(job, step)}.uses`,
          evidence: step.uses,
          message: `${reason}${trust}`,
          advice: `改成完整提交哈希：\`uses: ${parsed.owner}/${parsed.repo}@<40位SHA> # ${parsed.ref}\`。用 \`gh api repos/${parsed.owner}/${parsed.repo}/commits/${parsed.ref} --jq .sha\` 获取哈希；把 Dependabot 的 \`github-actions\` 生态打开，让它替你更新。`,
          patch: `uses: ${parsed.owner}/${parsed.repo}@0000000000000000000000000000000000000000 # ${parsed.ref}`,
        });
      }
    }

    // Reusable workflows are supply chain too (`jobs.<id>.uses`).
    for (const job of ctx.model.jobs) {
      if (!job.reusableWorkflow) continue;
      const trimmed = job.reusableWorkflow.trim();
      if (LOCAL_ACTION_RE.test(trimmed)) continue;
      const at = trimmed.lastIndexOf('@');
      const ref = at > 0 ? trimmed.slice(at + 1) : '';
      if (FULL_SHA_RE.test(ref)) continue;
      const owner = trimmed.split('/')[0]?.toLowerCase() ?? '';
      const official = FIRST_PARTY.has(owner);
      ctx.sink.add({
        rule: this.meta,
        severity: official ? 'low' : 'high',
        anchor: anchorOf(ctx.source, job.node),
        path: `${jobPath(job)}.uses`,
        evidence: job.reusableWorkflow,
        message: `可复用工作流 \`${trimmed}\` 的引用 \`${ref || '（无版本）'}\` 不是完整提交哈希。可复用工作流会拿到本仓库的 \`secrets: inherit\`（若启用），引用可变等于把密钥交给会移动的目标。`,
        advice: '固定到完整提交哈希；跨仓库复用前确认对方仓库的权限模型。',
      });
    }
  },
};

/**
 * WF041: an action under a well-known name but a lookalike owner (typosquat /
 * takeover). Cheap to check; catches `actons/checkout` and stale forks.
 */
export const lookalikeActionRule: Rule = {
  meta: {
    id: 'WF041',
    title: '可疑的动作来源（近似官方名称）',
    category: 'supply-chain',
    severity: 'high',
    summary: '与官方名称只差一个字母的发布者，常见于抢注与拼写错误攻击。',
  },
  run(ctx) {
    const OFFICIAL = new Set([
      'actions/checkout',
      'actions/setup-node',
      'actions/setup-python',
      'actions/setup-java',
      'actions/cache',
      'actions/upload-artifact',
      'actions/download-artifact',
      'actions/github-script',
      'actions/create-release',
      'actions/upload-release-asset',
      'docker/build-push-action',
      'docker/login-action',
      'docker/setup-buildx-action',
      'github/codeql-action',
    ]);
    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        const parsed = step.uses ? splitUses(step.uses) : null;
        if (!parsed || !parsed.owner) continue;
        const full = `${parsed.owner}/${parsed.repo}`.toLowerCase();
        if (OFFICIAL.has(full)) continue;
        // distance-1 neighbours of an official name, same repo part
        for (const official of OFFICIAL) {
          const [oOwner, oRepo] = official.split('/');
          if (parsed.repo.toLowerCase() !== oRepo) continue;
          if (parsed.owner.toLowerCase() === oOwner) continue;
          if (levenshtein(parsed.owner.toLowerCase(), oOwner) <= 1) {
            ctx.sink.add({
              rule: this.meta,
              severity: 'high',
              anchor: anchorOf(ctx.source, step.node),
              path: `${stepPath(job, step)}.uses`,
              evidence: step.uses ?? '',
              message: `\`${full}\` 与官方 \`${official}\` 只差一个字符，很像抢注/拼写错误。如果这是误写，你实际执行的是陌生人的代码。`,
              advice: `确认发布者；如是笔误改为 \`${official}\`，否则视同不可信第三方，固定哈希并审计。`,
            });
          }
        }
      }
    }
  },
};

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = new Array<number>(n + 1).fill(0).map((_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

/** WF042: unpinned docker image references inside a `uses: docker://` step. */
export const unpinnedDockerRule: Rule = {
  meta: {
    id: 'WF042',
    title: 'docker:// 动作未固定镜像摘要',
    category: 'supply-chain',
    severity: 'medium',
    summary: '`docker://image:tag` 会在运行时拉取可变标签。',
  },
  run(ctx) {
    for (const job of ctx.model.jobs) {
      for (const step of job.steps) {
        if (!step.uses || !step.uses.trim().startsWith('docker://')) continue;
        const ref = step.uses.trim().slice('docker://'.length);
        if (/@sha256:[0-9a-f]{64}/i.test(ref)) continue;
        ctx.sink.add({
          rule: this.meta,
          severity: 'medium',
          anchor: anchorOf(ctx.source, step.node),
          path: `${stepPath(job, step)}.uses`,
          evidence: step.uses,
          message: `镜像 \`${ref}\` 没有用 \`@sha256:\` 摘要固定，标签会被重新指向。`,
          advice: '改用 `docker://image@sha256:<digest>`，并在注释里记录标签。',
        });
      }
    }
  },
};

export const supplyChainRules: Rule[] = [unpinnedActionRule, lookalikeActionRule, unpinnedDockerRule];
