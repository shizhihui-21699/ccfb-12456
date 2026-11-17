/**
 * Engine tests. Run with `npm test` (node --test, native TS).
 *
 * The fixtures double as documentation: `tests/fixtures/vulnerable/*` are the
 * patterns the console must catch, `tests/fixtures/safe/*` are the patterns it
 * must not flag.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { auditWorkflowText } from '../src/core/audit.ts';
import { findExpressions } from '../src/core/expressions.ts';
import { parseWorkflowText, mapGet, mapKeyNode, scalarValue } from '../src/core/yaml.ts';
import { buildModel } from '../src/core/model.ts';

const FIXTURES = join(process.cwd(), 'tests', 'fixtures');

/**
 * Resolve a fixture. The four files that also ship as UI examples live only in
 * examples/workflows, so the shipped demos and the tests cannot drift apart.
 */
function fixturePath(kind: string, name: string): string {
  const inFixtures = join(FIXTURES, kind, name);
  if (existsSync(inFixtures)) return inFixtures;
  return join(process.cwd(), 'examples', 'workflows', name);
}

function fixture(kind: string, name: string): string {
  return readFileSync(fixturePath(kind, name), 'utf8');
}

function auditFixture(kind: 'vulnerable' | 'safe' | 'edge', name: string) {
  return auditWorkflowText(`${kind}/${name}`, readFileSync(fixturePath(kind, name), 'utf8'));
}

function ruleIds(report: ReturnType<typeof auditWorkflowText>): string[] {
  return report.findings.map((f) => f.ruleId);
}

function findingsOf(report: ReturnType<typeof auditWorkflowText>, ruleId: string) {
  return report.findings.filter((f) => f.ruleId === ruleId);
}

/* ---------------------------------------------------------------- parser --- */

test('findExpressions handles nested braces, quotes and multiple matches', () => {
  const found = findExpressions(
    'echo ${{ github.event.pull_request.title }} and ${{ format("{0}", github.head_ref) }}',
  );
  assert.equal(found.length, 2);
  assert.equal(found[0].expr, 'github.event.pull_request.title');
  assert.equal(found[1].expr, 'format("{0}", github.head_ref)');
  assert.equal(found[0].index, 5);
});

test('findExpressions ignores an unterminated expression', () => {
  assert.deepEqual(findExpressions('echo ${{ github.event.foo'), []);
});

test('parser keeps source positions for keys and values', () => {
  const text = fixture('vulnerable', 'pr-target-pwn.yml');
  const { doc, source, errors } = parseWorkflowText('x', text);
  assert.deepEqual(errors, []);
  const root = doc.contents as never;
  // The value node starts at the first job key; the key node is `jobs:` itself.
  const jobsKey = mapKeyNode(root, 'jobs');
  assert.ok(jobsKey);
  const line = source.position(jobsKey.range![0]).line;
  assert.equal(source.lineText(line), 'jobs:');
  const jobs = mapGet(root, 'jobs');
  assert.ok(jobs);
  assert.equal(source.position(jobs.range![0]).line, 7);
});

test('quoted and YAML-1.1 "on" keys are both recognised', () => {
  const quoted = auditFixture('edge', 'quoted-on.yml');
  assert.ok(quoted.triggers.includes('pull_request_target'));

  const { doc, source } = parseWorkflowText('x', 'on: [push]\njobs: {}\n');
  const model = buildModel(doc, source, []);
  assert.deepEqual(model.triggers.map((t) => t.key), ['push']);
  assert.equal(scalarValue(mapGet(doc.contents as never, 'on')), null);
});

test('malformed YAML reports an error instead of findings', () => {
  const report = auditFixture('edge', 'malformed.yml');
  assert.ok(report.errors.length > 0);
  assert.equal(report.findings.length, 0);
});

/* ------------------------------------------------------- untrusted code --- */

test('pull_request_target + checkout of the PR head + npm ci is critical', () => {
  const report = auditFixture('vulnerable', 'pr-target-pwn.yml');
  const wf001 = findingsOf(report, 'WF001');
  assert.equal(wf001.length, 1);
  assert.equal(wf001[0].severity, 'critical');
  // The anchor should be the `ref:` line, not the top of the file.
  assert.equal(wf001[0].line, 15);
  assert.match(wf001[0].evidence, /pull_request\.head\.sha/);
});

test('secrets reached by an untrusted-code job are reported separately', () => {
  const report = auditFixture('vulnerable', 'pr-target-pwn.yml');
  const wf050 = findingsOf(report, 'WF050');
  assert.equal(wf050.length, 1);
  assert.equal(wf050[0].severity, 'critical');
  assert.match(wf050[0].evidence, /GITHUB_TOKEN/);
});

test('workflow_run + artifact execution is reported as artifact poisoning', () => {
  const report = auditFixture('vulnerable', 'workflow-run-artifact.yml');
  const wf002 = findingsOf(report, 'WF002');
  assert.equal(wf002.length, 1);
  assert.equal(wf002[0].severity, 'critical');
  // WF001 must not double-report the same root cause.
  assert.equal(findingsOf(report, 'WF001').length, 0);
});

test('issue_comment commands that fetch a PR ref are flagged', () => {
  const report = auditFixture('vulnerable', 'issue-command.yml');
  assert.ok(ruleIds(report).includes('WF001'));
  assert.equal(findingsOf(report, 'WF001')[0].severity, 'critical');
});

test('plain pull_request with fork checkout is not a privileged-execution finding', () => {
  const report = auditFixture('safe', 'pull-request-ci.yml');
  assert.equal(findingsOf(report, 'WF001').length, 0);
  assert.equal(report.findings.length, 0);
});

test('pull_request with only a write scope is not escalated (token is downgraded for forks)', () => {
  const text = `
name: x
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF003').length, 0);
});

test('pull_request with repository secrets and fork checkout is critical', () => {
  const text = `
name: x
on: pull_request
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
        env:
          TOKEN: \${{ secrets.DEPLOY_TOKEN }}
`;
  const report = auditWorkflowText('inline.yml', text);
  const wf003 = findingsOf(report, 'WF003');
  assert.equal(wf003.length, 1);
  assert.equal(wf003[0].severity, 'critical');
  assert.match(wf003[0].evidence, /DEPLOY_TOKEN/);
});

/* ------------------------------------------------------------- injection --- */

test('PR title interpolated into run: is critical on a privileged event', () => {
  const report = auditFixture('vulnerable', 'title-injection.yml');
  const hits = findingsOf(report, 'WF010');
  // echo step, grep step, github-script step
  assert.equal(hits.length, 3);
  for (const hit of hits) assert.equal(hit.severity, 'critical');
});

test('injection positions point at the expression, not the step', () => {
  const report = auditFixture('vulnerable', 'title-injection.yml');
  const first = findingsOf(report, 'WF010')[0];
  assert.equal(first.line, 16);
  assert.ok(first.column > 1);
  const source = fixture('vulnerable', 'title-injection.yml').split('\n');
  assert.match(source[first.line - 1], /\$\{\{ github\.event\.pull_request\.title \}\}/);
});

test('env-passed title is not a finding', () => {
  const report = auditFixture('safe', 'pr-target-artifact.yml');
  assert.equal(findingsOf(report, 'WF010').length, 0);
  assert.equal(report.findings.length, 0);
});

test('matrix values derived from the event payload are treated as untrusted', () => {
  const report = auditFixture('vulnerable', 'matrix-injection.yml');
  const hits = findingsOf(report, 'WF010');
  const matrixHit = hits.find((h) => h.evidence.includes('matrix.target'));
  assert.ok(matrixHit, 'matrix.target should be flagged');
  assert.match(matrixHit!.message, /matrix\.target/);
});

test('trusted contexts such as github.actor are not flagged', () => {
  const text = `
name: x
on: pull_request_target
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "actor is \${{ github.actor }} on \${{ github.event_name }}"
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF010').length, 0);
});

/* ----------------------------------------------------------- permissions --- */

test('write-all is critical at workflow and job level', () => {
  const text = `
name: x
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
`;
  const report = auditWorkflowText('inline.yml', text);
  const wf020 = findingsOf(report, 'WF020');
  assert.equal(wf020.length, 2);
  for (const f of wf020) assert.equal(f.severity, 'critical');
});

test('missing permissions block is reported once per workflow', () => {
  const report = auditFixture('edge', 'no-permissions.yml');
  const wf021 = findingsOf(report, 'WF021');
  assert.equal(wf021.length, 1);
});

test('explicit empty permissions is not reported as missing', () => {
  const report = auditFixture('edge', 'empty-permissions.yml');
  assert.equal(findingsOf(report, 'WF021').length, 0);
  assert.equal(report.findings.length, 0);
});

test('id-token: write next to a cloud login action is escalated', () => {
  const report = auditFixture('vulnerable', 'matrix-injection.yml');
  const wf030 = findingsOf(report, 'WF030');
  assert.equal(wf030.length, 1);
  assert.ok(['high', 'critical'].includes(wf030[0].severity));
});

test('a read-only build job with contents: read is not flagged for permissions', () => {
  const report = auditFixture('safe', 'pull-request-ci.yml');
  assert.equal(findingsOf(report, 'WF022').length, 0);
});

test('permissions handed to an unknown action are assumed necessary', () => {
  const text = `
name: x
on: pull_request
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: some-org/reporter@0000000000000000000000000000000000000000
        with:
          token: \${{ secrets.GITHUB_TOKEN }}
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF022').length, 0);
});

test('reusable workflow jobs are not judged on permissions they do not use', () => {
  const text = `
name: x
on: push
permissions: { contents: read }
jobs:
  call:
    permissions:
      contents: read
      pull-requests: write
    uses: org/repo/.github/workflows/x.yml@0000000000000000000000000000000000000000
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF022').length, 0);
});

test('repository-local $/ actions are not treated as unpinned third parties', () => {
  const text = `
name: x
on: push
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: \$/.github/actions/helper
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF040').length, 0);
});

/* ---------------------------------------------------------- supply chain --- */

test('tag-pinned actions are reported, SHA-pinned ones are not', () => {
  const tagged = auditFixture('vulnerable', 'self-hosted.yml');
  const pinned = auditFixture('safe', 'pull-request-ci.yml');
  assert.ok(findingsOf(tagged, 'WF040').length >= 1);
  assert.equal(findingsOf(pinned, 'WF040').length, 0);
});

test('third-party actions rank above official ones', () => {
  const report = auditFixture('vulnerable', 'self-hosted.yml');
  const thirdParty = findingsOf(report, 'WF040').find((f) => f.evidence.startsWith('some-random-user/'));
  const official = findingsOf(report, 'WF040').find((f) => f.evidence.startsWith('actions/'));
  assert.ok(thirdParty && official);
  assert.equal(thirdParty!.severity, 'medium');
  assert.equal(official!.severity, 'low');
});

test('typosquatted official action names are flagged', () => {
  const text = `
name: x
on: push
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actons/checkout@v4
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF041').length, 1);
});

test('local actions and docker:// refs are handled', () => {
  const text = `
name: x
on: push
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF040').length, 0);
  // docker tag without digest
  assert.equal(findingsOf(report, 'WF042').length, 1);
});

/* ---------------------------------------------------------------- runner --- */

test('self-hosted runner with untrusted events is critical', () => {
  const report = auditFixture('vulnerable', 'self-hosted.yml');
  const wf060 = findingsOf(report, 'WF060');
  assert.equal(wf060.length, 1);
  assert.equal(wf060[0].severity, 'critical');
});

/* ------------------------------------------------------- report / scoring --- */

test('safe fixtures produce zero findings', () => {
  for (const name of ['pr-target-artifact.yml', 'pull-request-ci.yml', 'publish-on-release.yml']) {
    const report = auditFixture('safe', name);
    assert.deepEqual(
      report.findings.map((f) => `${f.ruleId}@${f.line}`),
      [],
      `${name} should be clean`,
    );
    assert.equal(report.grade, 'A');
  }
});

test('every finding has a usable advice string and a valid position', () => {
  for (const name of [
    'pr-target-pwn.yml',
    'title-injection.yml',
    'workflow-run-artifact.yml',
    'self-hosted.yml',
    'issue-command.yml',
    'matrix-injection.yml',
  ]) {
    const path = fixturePath('vulnerable', name);
    const text = readFileSync(path, 'utf8');
    const report = auditWorkflowText(path, text);
    const lineCount = text.split('\n').length;
    for (const f of report.findings) {
      assert.ok(f.advice.length > 20, `${f.ruleId} needs advice`);
      assert.ok(f.message.length > 20, `${f.ruleId} needs a message`);
      assert.ok(f.line >= 1 && f.line <= lineCount + 1, `${f.ruleId} line ${f.line} out of range`);
      assert.ok(f.column >= 1);
      assert.ok(f.path.length > 0);
    }
  }
});

test('findings are sorted most severe first', () => {
  const report = auditFixture('vulnerable', 'self-hosted.yml');
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  for (let i = 1; i < report.findings.length; i++) {
    assert.ok(
      order[report.findings[i - 1].severity] <= order[report.findings[i].severity],
      'severity order violated',
    );
  }
});

test('a critical finding can never grade A', () => {
  const report = auditFixture('vulnerable', 'pr-target-pwn.yml');
  assert.notEqual(report.grade, 'A');
  assert.ok(report.score < 40);
});

test('polymorphic content is treated as data, not YAML', () => {
  // A title crafted to look like YAML must not change the audit result.
  const text = `
name: x
on: pull_request_target
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ok"
`;
  const evil = text.replace('echo "ok"', 'echo "${{ github.event.pull_request.title }}"');
  const report = auditWorkflowText('inline.yml', evil);
  const hits = findingsOf(report, 'WF010');
  assert.equal(hits.length, 1);
  // Line 9 is the `run:` line of the generated document.
  assert.equal(hits[0].line, 9);
  const lines = evil.split('\n');
  assert.match(lines[hits[0].line - 1], /\$\{\{ github\.event\.pull_request\.title \}\}/);
});

/* ------------------------------------------------ additional real-world --- */

test('pull_request_target checkout without a ref stays on the base branch (no WF001)', () => {
  const text = `
name: x
on: pull_request_target
permissions:
  contents: read
  pull-requests: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          persist-credentials: false
      - run: echo "analysing metadata only"
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF001').length, 0);
});

test('workflow_run checkout of the upstream head is flagged even without npm ci', () => {
  const text = `
name: x
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF001').length, 1);
  assert.equal(findingsOf(report, 'WF001')[0].severity, 'high');
});

test('secrets: inherit on a reusable workflow is reported when untrusted code runs', () => {
  const text = `
name: x
on: pull_request_target
permissions: { contents: read }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci
  deploy:
    needs: build
    uses: org/repo/.github/workflows/deploy.yml@v1
    secrets: inherit
`;
  const report = auditWorkflowText('inline.yml', text);
  // The reusable job itself does not run fork code, but the pinned-ref job does.
  const ids = ruleIds(report);
  assert.ok(ids.includes('WF001'));
  assert.ok(ids.includes('WF040'), 'reusable workflow must be pinned too');
});

test('read-all is treated as read-only, not write-all', () => {
  const text = `
name: x
on: push
permissions: read-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF020').length, 0);
  assert.equal(findingsOf(report, 'WF022').length, 0);
});

test('random binary and deeply nested input never throws', () => {
  const samples = [
    'ÿþ\u0000\u0001 not yaml at all',
    'a: &a [*a]\n',
    '"on": {pull_request_target: null}\njobs: {}\n',
    'jobs:\n  a:\n    steps:\n      - run: |\n          ' + 'x'.repeat(5000) + '\n',
    'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo "${{ github.event.pull_request.title }}"\n',
  ];
  for (const text of samples) {
    assert.doesNotThrow(() => auditWorkflowText('fuzz.yml', text));
  }
});

test('case: an on: block with a null value (push:) is parsed', () => {
  const text = 'on:\n  push:\njobs: {}\n';
  const report = auditWorkflowText('inline.yml', text);
  assert.deepEqual(report.rawTriggers, ['push']);
});

/* ------------------------------------------------- calibration regressions --- */
/* These come from auditing real public repositories: each one was a false
   positive that would have made the console untrustworthy. */

test('workflow_call-only inputs are a low-severity hardening note, one per input', () => {
  const text = `
name: bench
on:
  workflow_call:
    inputs:
      benchmark:
        type: string
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: pnpm run bench apps/\${{ inputs.benchmark }}.html
      - run: echo \${{ inputs.benchmark }}
      - run: tar -czf out/\${{ inputs.benchmark }}.tgz out
`;
  const report = auditWorkflowText('inline.yml', text);
  const wf012 = findingsOf(report, 'WF012');
  assert.equal(wf012.length, 1, 'one finding per input name');
  assert.equal(wf012[0].severity, 'low');
});

test('workflow_dispatch inputs stay medium', () => {
  const text = `
name: x
on:
  workflow_dispatch:
    inputs:
      target:
        type: string
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh \${{ inputs.target }}
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF012')[0].severity, 'medium');
});

test('an unrecognised third-party action suppresses over-scope guesses', () => {
  const text = `
name: x
on: workflow_run
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: some-unknown/reporter@f4edc62a47169384c3f950a48f58000ce81cd07c
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF022').length, 0);
});

test('a read-only token with persist-credentials is not reported', () => {
  const text = `
name: x
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
      - run: echo done
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF061').length, 0);
});

test('missing workflow permissions on a dispatch-only workflow is low', () => {
  const text = `
name: x
on: workflow_dispatch
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`;
  const report = auditWorkflowText('inline.yml', text);
  assert.equal(findingsOf(report, 'WF021')[0].severity, 'low');
});

test('artifact used as data is fine; executed from the artifact directory is not', () => {
  const base = (tail: string, path = 'results') => `
name: x
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  actions: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@6f51ac03b546ed0e0d6c0a2b8a8efc2b1e9d5a6e
        with:
          run-id: \${{ github.event.workflow_run.id }}
          path: ${path}
${tail}
`;
  const data = auditWorkflowText(
    'data.yml',
    base(`      - run: |
          node scripts/render-report.mjs results/report.json`),
  );
  assert.equal(findingsOf(data, 'WF002').length, 0, 'parsing artifact JSON is data handling');

  const code = auditWorkflowText(
    'code.yml',
    base(`      - run: |
          chmod +x results/release.sh
          ./results/release.sh`),
  );
  assert.equal(findingsOf(code, 'WF002').length, 1);
});

test('unpacking a fork artifact over the workspace root then npm ci is execution', () => {
  const text = `
name: x
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@6f51ac03b546ed0e0d6c0a2b8a8efc2b1e9d5a6e
        with:
          run-id: \${{ github.event.workflow_run.id }}
      - run: npm ci
`;
  const report = auditWorkflowText('x.yml', text);
  assert.equal(findingsOf(report, 'WF002').length, 1);
});
