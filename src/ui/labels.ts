/**
 * Shared constants and tiny helpers used by the UI.
 */

import type { Severity } from '../core/types.ts';

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export const CATEGORY_LABEL: Record<string, string> = {
  'untrusted-code': '不可信代码执行',
  'script-injection': '脚本注入',
  permissions: '权限过大',
  'supply-chain': '供应链',
  secrets: '密钥暴露',
  runner: '运行器',
  hygiene: '加固建议',
};

export const EXAMPLES: Array<{ key: string; label: string; path: string; blurb: string }> = [
  {
    key: 'prTargetExample',
    label: 'pull_request_target 检出 fork 代码',
    path: 'examples/workflows/pr-target-pwn.yml',
    blurb: '外部贡献者分支上的 npm ci 会执行，而任务持有写权限。',
  },
  {
    key: 'injectionExample',
    label: 'PR 标题被拼进脚本',
    path: 'examples/workflows/title-injection.yml',
    blurb: '标题里的 `"; curl …` 会变成命令。',
  },
  {
    key: 'workflowRunExample',
    label: 'workflow_run 产物投毒',
    path: 'examples/workflows/workflow-run-artifact.yml',
    blurb: '下载上游产物后 chmod +x 执行。',
  },
  {
    key: 'ciExample',
    label: '一份干净的 pull_request 流水线',
    path: 'examples/workflows/pull-request-ci.yml',
    blurb: '只读令牌 + 哈希固定动作。',
  },
];
