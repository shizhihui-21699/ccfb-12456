/**
 * Render-level tests for the UI.
 *
 * The app is rendered to a string (no DOM needed) against a fixture, so the
 * tests can assert that findings actually reach the screen: rule title,
 * severity label, line reference and the fix text. A regression that silences
 * the panel will fail here even if the engine tests pass.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { render } from 'preact-render-to-string';

import { App } from '../src/ui/App.tsx';
import { SourceView } from '../src/ui/components/SourceView.tsx';
import { toMarkdown } from '../src/ui/report-markdown.ts';
import { auditFiles } from '../src/core/audit.ts';

const FIXTURES = join(process.cwd(), 'tests', 'fixtures');

function fixture(kind: string, name: string): string {
  const inFixtures = join(FIXTURES, kind, name);
  const path = existsSync(inFixtures) ? inFixtures : join(process.cwd(), 'examples', 'workflows', name);
  return readFileSync(path, 'utf8');
}

function html(): string {
  return render(
    <App
      initialFiles={[
        { path: 'pr-target.yml', text: fixture('vulnerable', 'pr-target-pwn.yml') },
        { path: 'ci.yml', text: fixture('safe', 'pull-request-ci.yml') },
      ]}
    />,
  );
}

test('the shell renders the report header and totals', () => {
  const out = html();
  assert.match(out, /工作流安全审计/);
  assert.match(out, /外部拉取请求攻击面检查/);
  // 2 files, and the vulnerable one has findings
  assert.match(out, /共 \d+ 处问题/);
});

test('findings are listed with their rule title and severity label', () => {
  const out = html();
  assert.match(out, /pull_request_target/);
  assert.match(out, /严重/);
  assert.match(out, /WF001/);
});

test('the clean file is shown as clean in the file rail', () => {
  const out = html();
  assert.match(out, /pr-target\.yml/);
  assert.match(out, /ci\.yml/);
  assert.match(out, /无问题/);
});

test('the detail panel carries the advice text', () => {
  const out = html();
  assert.match(out, /怎么改/);
  assert.match(out, /workflow_run/);
  assert.match(out, /参考改法/);
});

test('source view marks finding lines and numbers them', () => {
  const text = fixture('vulnerable', 'pr-target-pwn.yml');
  const report = auditFiles([{ path: 'x.yml', text }]).files[0];
  const out = render(
    <SourceView path="x.yml" text={text} highlightLines={[15, 15]} findings={report.findings} />,
  );
  assert.match(out, /class="[^"]*hl/);
  assert.match(out, /gutter-mark/);
  assert.match(out, />15</);
});

test('markdown export contains every finding with its advice', () => {
  const report = auditFiles([
    { path: 'a.yml', text: fixture('vulnerable', 'pr-target-pwn.yml') },
    { path: 'b.yml', text: fixture('safe', 'pull-request-ci.yml') },
  ]);
  const md = toMarkdown(report);
  assert.match(md, /^# GitHub Actions 工作流安全审计/m);
  assert.match(md, /WF001/);
  assert.match(md, /建议：/);
  assert.match(md, /未发现已知风险写法/);
  // every finding's rule id appears
  for (const file of report.files) {
    for (const f of file.findings) assert.ok(md.includes(f.ruleId));
  }
});

test('rendering does not leak raw HTML from an attacker-controlled title', () => {
  const evil =
    'name: x\non: pull_request_target\npermissions: { contents: read }\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n';
  const out = render(<App initialFiles={[{ path: 'evil.yml', text: evil.replace('echo "$', 'echo \'<img src=x onerror=alert(1)>\' "$') }]} />);
  assert.ok(!out.includes('<img src=x'), 'raw markup from the workflow must be escaped');
});
