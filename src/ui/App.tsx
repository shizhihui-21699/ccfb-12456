/**
 * The console's single-page UI.
 *
 * Layout: file rail on the left, findings in the middle, selected finding's
 * source excerpt on the right. Collapses to one column under 900px.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { AuditReport, Severity, WorkflowReport } from '../core/types.ts';
import { auditFiles, compareFindings } from '../core/audit.ts';
import { SEVERITY_LABEL, SEVERITY_RANK, CATEGORY_LABEL, EXAMPLES } from './labels.ts';
import { FindingDetail } from './components/FindingDetail.tsx';
import { toMarkdown } from './report-markdown.ts';
import { RichText } from './components/RichText.tsx';
import { readDroppedFiles } from './drop-reader.ts';
import { SourceView } from './components/SourceView.tsx';
import { Summary } from './components/Summary.tsx';

import prTargetExample from '../../examples/workflows/pr-target-pwn.yml';
import injectionExample from '../../examples/workflows/title-injection.yml';
import workflowRunExample from '../../examples/workflows/workflow-run-artifact.yml';
import ciExample from '../../examples/workflows/pull-request-ci.yml';

const EXAMPLE_TEXT: Record<string, { path: string; text: string }> = {
  prTargetExample: { path: '.github/workflows/pr-preview.yml', text: prTargetExample },
  injectionExample: { path: '.github/workflows/triage.yml', text: injectionExample },
  workflowRunExample: { path: '.github/workflows/publish.yml', text: workflowRunExample },
  ciExample: { path: '.github/workflows/ci.yml', text: ciExample },
};

export interface LoadedFile {
  path: string;
  text: string;
  /** set when the user dropped a whole folder */
  group?: string;
}

const STORAGE_KEY = 'workflow-audit-console:v1';

export function App({ initialFiles = [] }: { initialFiles?: LoadedFile[] } = {}) {
  const [files, setFiles] = useState<LoadedFile[]>(initialFiles);
  const [activeFile, setActiveFile] = useState<string | null>(initialFiles[0]?.path ?? null);
  const [activeFinding, setActiveFinding] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [query, setQuery] = useState('');
  const [view, setView] = useState<'findings' | 'source' | 'overview'>('findings');
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  /* restore the last session, so a reload does not lose the audit */
  useEffect(() => {
    if (initialFiles.length) return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw) as { files?: LoadedFile[]; activeFile?: string };
      if (saved.files?.length) {
        setFiles(saved.files);
        setActiveFile(saved.activeFile ?? saved.files[0].path);
      }
    } catch {
      /* private mode / quota: start empty */
    }
  }, [initialFiles.length]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ files, activeFile }));
    } catch {
      /* ignore */
    }
  }, [files, activeFile]);

  const report: AuditReport = useMemo(() => {
    const result = auditFiles(files, {}, new Date());
    return result;
  }, [files]);

  const activeReport = useMemo(
    () => report.files.find((f) => f.file === activeFile) ?? report.files[0],
    [report, activeFile],
  );

  const visibleFindings = useMemo(() => {
    if (!activeReport) return [];
    const q = query.trim().toLowerCase();
    return activeReport.findings.filter((f) => {
      if (severityFilter.size && !severityFilter.has(f.severity)) return false;
      if (!q) return true;
      return (
        f.ruleId.toLowerCase().includes(q) ||
        f.ruleTitle.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q) ||
        f.path.toLowerCase().includes(q) ||
        CATEGORY_LABEL[f.category]?.includes(q)
      );
    });
  }, [activeReport, severityFilter, query]);

  const selected = useMemo(() => {
    if (!activeReport) return null;
    return activeReport.findings.find((f) => f.id === activeFinding) ?? visibleFindings[0] ?? null;
  }, [activeReport, activeFinding, visibleFindings]);

  const loadFiles = useCallback((incoming: LoadedFile[]) => {
    if (!incoming.length) return;
    setFiles((prev) => {
      const next = [...prev.filter((f) => !incoming.some((i) => i.path === f.path)), ...incoming];
      return next;
    });
    setActiveFile(incoming[0].path);
    setActiveFinding(null);
    setNotice(`已载入 ${incoming.length} 个文件`);
  }, []);

  const onImport = useCallback(
    async (list: FileList | null) => {
      if (!list?.length) return;
      setBusy('读取文件…');
      try {
        const incoming: LoadedFile[] = [];
        for (const file of Array.from(list)) {
          if (file.size > 512 * 1024) {
            setNotice(`${file.name} 超过 512KB，已跳过`);
            continue;
          }
          if (!/\.ya?ml$/i.test(file.name)) {
            setNotice(`${file.name} 不是 YAML，已跳过`);
            continue;
          }
          const text = await file.text();
          // A directory picker gives a full relative path; keep the tail so the
          // rail shows `.github/workflows/ci.yml` rather than one long path.
          const relative = file.webkitRelativePath || '';
          const path = relative ? trimToWorkflows(relative) : file.name;
          incoming.push({ path, text, group: relative ? relative.split('/').slice(0, -1).join('/') : undefined });
        }
        loadFiles(incoming);
      } catch (err) {
        setNotice(`读取失败：${(err as Error).message}`);
      } finally {
        setBusy(null);
      }
    },
    [loadFiles],
  );

  const onDrop = useCallback(
    async (event: DragEvent) => {
      event.preventDefault();
      if (!event.dataTransfer) return;
      setBusy('读取拖入的文件…');
      try {
        const dropped = await readDroppedFiles(event.dataTransfer);
        if (!dropped.length) {
          setNotice('没有找到 .yml / .yaml 文件');
          return;
        }
        loadFiles(dropped.map((d) => ({ ...d, path: trimToWorkflows(d.path) })));
      } catch (err) {
        setNotice(`读取失败：${(err as Error).message}`);
      } finally {
        setBusy(null);
      }
    },
    [loadFiles],
  );

  const addExample = useCallback((key: string) => {
    const example = EXAMPLE_TEXT[key];
    if (!example) return;
    loadFiles([{ path: example.path, text: example.text }]);
  }, [loadFiles]);

  const clearAll = useCallback(() => {
    setFiles([]);
    setActiveFile(null);
    setActiveFinding(null);
    setNotice(null);
  }, []);

  const exportJson = useCallback(() => {
    const payload = JSON.stringify(report, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'workflow-audit.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, [report]);

  const exportMarkdown = useCallback(() => {
    const md = toMarkdown(report);
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'workflow-audit.md';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, [report]);

  const toggleSeverity = (severity: Severity) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  };

  const hasFiles = files.length > 0;

  return (
    <div class="app" onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
      <header class="topbar">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 3 6v6c0 5 3.8 9.2 9 10 5.2-.8 9-5 9-10V6L12 2Z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>
          </span>
          <div>
            <h1>工作流安全审计台</h1>
            <p class="tagline">GitHub Actions 外部拉取请求攻击面检查</p>
          </div>
        </div>
        <div class="topbar-actions">
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".yml,.yaml,text/yaml"
            hidden
            onChange={(e) => void onImport((e.target as HTMLInputElement).files)}
          />
          <button class="btn btn-primary" onClick={() => inputRef.current?.click()}>
            <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" fill="none"/></svg>
            导入工作流
          </button>
          {hasFiles && (
            <>
              <button class="btn" onClick={exportMarkdown} title="导出 Markdown 报告">导出 MD</button>
              <button class="btn" onClick={exportJson} title="导出 JSON 报告">JSON</button>
              <button class="btn btn-quiet" onClick={clearAll}>清空</button>
            </>
          )}
        </div>
      </header>

      {!hasFiles ? (
        <EmptyState
          onPick={() => inputRef.current?.click()}
          onImport={onImport}
          onDropFiles={loadFiles}
          onEmpty={() => setNotice('没有找到 .yml / .yaml 文件')}
          onExample={addExample}
          onPaste={(text) => loadFiles([{ path: 'pasted.yml', text }])}
          busy={busy}
          notice={notice}
        />
      ) : (
        <main class="workspace">
          <aside class="rail">
            <Summary report={report} />
            <nav class="file-list" aria-label="工作流文件">
              {report.files.map((file) => (
                <FileRow
                  key={file.file}
                  file={file}
                  active={file.file === activeReport?.file}
                  onSelect={() => {
                    setActiveFile(file.file);
                    setActiveFinding(null);
                  }}
                />
              ))}
            </nav>
            <p class="rail-foot">
              {files.length} 个文件 · 共 {report.totals.findings} 处问题
            </p>
          </aside>

          <section class="main">
            <div class="toolbar">
              <div class="tabs" role="tablist">
                <button class={view === 'findings' ? 'tab active' : 'tab'} onClick={() => setView('findings')}>
                  问题 <span class="count">{activeReport?.findings.length ?? 0}</span>
                </button>
                <button class={view === 'source' ? 'tab active' : 'tab'} onClick={() => setView('source')}>
                  源码
                </button>
                <button class={view === 'overview' ? 'tab active' : 'tab'} onClick={() => setView('overview')}>
                  文件概览
                </button>
              </div>
              <div class="filters">
                {(Object.keys(SEVERITY_LABEL) as Severity[]).map((sev) => (
                  <button
                    key={sev}
                    class={`chip sev-${sev} ${severityFilter.has(sev) ? 'on' : ''}`}
                    aria-pressed={severityFilter.has(sev)}
                    onClick={() => toggleSeverity(sev)}
                  >
                    {SEVERITY_LABEL[sev]}
                    <span class="chip-n">{countSeverity(activeReport, sev)}</span>
                  </button>
                ))}
                <input
                  class="search"
                  placeholder="搜索规则、路径、证据…"
                  value={query}
                  onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
                />
              </div>
            </div>

            {activeReport && (
              <div class="panels">
                {view === 'findings' && (
                  <div class="findings-pane">
                    {visibleFindings.length === 0 ? (
                      <NoFindings file={activeReport} filtered={activeReport.findings.length > 0} />
                    ) : (
                      <ul class="finding-list">
                        {visibleFindings.map((f) => (
                          <li key={f.id}>
                            <button
                              class={`finding-row ${f.id === selected?.id ? 'selected' : ''}`}
                              onClick={() => setActiveFinding(f.id)}
                            >
                              <span class={`sev-bar sev-${f.severity}`} aria-hidden="true" />
                              <span class="finding-main">
                                <span class="finding-title"><RichText text={f.ruleTitle} /></span>
                                <span class="finding-sub">
                                  <code>{f.path}</code>
                                  <span class="dot">·</span>
                                  L{f.line}
                                </span>
                              </span>
                              <span class={`sev-pill sev-${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

                {view === 'findings' && selected && (
                  <div class="detail-pane">
                    <FindingDetail finding={selected} onShowSource={() => setView('source')} />
                    {activeReport.file && (
                      <SourceView
                        path={activeReport.file}
                        text={files.find((f) => f.path === activeReport.file)?.text ?? ''}
                        highlightLines={[selected.line, selected.endLine]}
                        compact
                      />
                    )}
                  </div>
                )}

                {view === 'source' && (
                  <div class="source-pane">
                    <SourceView
                      path={activeReport.file}
                      text={files.find((f) => f.path === activeReport.file)?.text ?? ''}
                      highlightLines={
                        selected && selected.file === activeReport.file ? [selected.line, selected.endLine] : []
                      }
                      findings={activeReport.findings}
                      onSelectFinding={(id: string) => setActiveFinding(id)}
                    />
                  </div>
                )}

                {view === 'overview' && (
                  <div class="overview-pane">
                    <FileOverview file={activeReport} />
                  </div>
                )}
              </div>
            )}
          </section>
        </main>
      )}
    </div>
  );
}

function countSeverity(report: WorkflowReport | undefined, severity: Severity): number {
  return report ? report.findings.filter((f) => f.severity === severity).length : 0;
}

function FileRow({ file, active, onSelect }: { file: WorkflowReport; active: boolean; onSelect: () => void }) {
  const worst = [...file.findings].sort(compareFindings)[0];
  return (
    <button class={`file-row ${active ? 'active' : ''}`} onClick={onSelect}>
      <span class="file-name" title={file.file}>
        {shortPath(file.file)}
      </span>
      <span class="file-meta">
        {file.errors.length > 0 ? (
          <span class="badge badge-error">解析失败</span>
        ) : worst ? (
          <span class={`mini-sev sev-${worst.severity}`}>{SEVERITY_LABEL[worst.severity]}</span>
        ) : (
          <span class="mini-sev sev-clean">无问题</span>
        )}
        <span class="grader">{file.grade}</span>
      </span>
    </button>
  );
}

/** Keep the part from `.github/` onward when a whole repo was dropped. */
function trimToWorkflows(path: string): string {
  const marker = path.indexOf('.github/');
  return marker >= 0 ? path.slice(marker) : path.split('/').filter(Boolean).slice(-2).join('/');
}

function shortPath(path: string): string {
  const parts = path.split('/');
  return parts.length > 1 ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}` : path;
}

function NoFindings({ file, filtered }: { file: WorkflowReport; filtered: boolean }) {
  if (file.errors.length) {
    return (
      <div class="empty-note error">
        <h3>YAML 解析失败</h3>
        <p>没有执行审计。请检查语法后重新导入。</p>
        <pre>{file.errors.join('\n')}</pre>
      </div>
    );
  }
  return (
    <div class="empty-note ok">
      <div class="ok-mark" aria-hidden="true">✓</div>
      <h3>{filtered ? '当前筛选条件下没有问题' : '没有发现已知风险写法'}</h3>
      <p>
        {filtered
          ? '清空搜索或取消严重度筛选看看全部结果。'
          : '按本工具的规则集，这份工作流在外部拉取请求触发路径上没有命中的风险。仍建议人工复核业务逻辑。'}
      </p>
      {file.warnings.length > 0 && (
        <ul class="warnings">
          {file.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FileOverview({ file }: { file: WorkflowReport }) {
  return (
    <div class="overview">
      <section class="card">
        <h2>{file.name}</h2>
        <dl class="kv">
          <dt>评级</dt>
          <dd>
            <span class={`grade grade-${file.grade}`}>{file.grade}</span> <span class="muted">得分 {file.score}/100</span>
          </dd>
          <dt>触发事件</dt>
          <dd>
            {file.rawTriggers.length ? (
              <span class="tag-row">
                {file.rawTriggers.map((t) => (
                  <code class="tag" key={t}>{t}</code>
                ))}
              </span>
            ) : (
              <span class="muted">（未解析到）</span>
            )}
          </dd>
          <dt>任务</dt>
          <dd>{file.jobs.length} 个</dd>
        </dl>
      </section>

      {file.warnings.length > 0 && (
        <section class="card">
          <h3>解析提示</h3>
          <ul class="warnings">
            {file.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </section>
      )}

      <section class="card">
        <h3>任务权限</h3>
        {file.jobs.length === 0 ? (
          <p class="muted">无任务。</p>
        ) : (
          <table class="job-table">
            <thead>
              <tr>
                <th>任务</th>
                <th>运行器</th>
                <th>写权限</th>
              </tr>
            </thead>
            <tbody>
              {file.jobs.map((job) => (
                <tr key={job.id}>
                  <td>
                    <code>{job.id}</code>
                    {job.name && <span class="muted"> {job.name}</span>}
                  </td>
                  <td>{job.runsOn.join(', ') || <span class="muted">—</span>}</td>
                  <td>
                    {job.writePermissions.length ? (
                      <span class="tag-row">
                        {job.writePermissions.map((p) => (
                          <code class="tag tag-warn" key={p}>{p}</code>
                        ))}
                      </span>
                    ) : (
                      <span class="muted">只读</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section class="card">
        <h3>规则命中分布</h3>
        {file.findings.length === 0 ? (
          <p class="muted">没有命中任何规则。</p>
        ) : (
          <RuleBreakdown file={file} />
        )}
      </section>
    </div>
  );
}

function RuleBreakdown({ file }: { file: WorkflowReport }) {
  const groups = new Map<string, { title: string; severity: Severity; count: number }>();
  for (const f of file.findings) {
    const entry = groups.get(f.ruleId);
    if (entry) entry.count += 1;
    else groups.set(f.ruleId, { title: f.ruleTitle, severity: f.severity, count: 1 });
  }
  return (
    <ul class="rule-list">
      {[...groups.entries()]
        .sort((a, b) => SEVERITY_RANK[a[1].severity] - SEVERITY_RANK[b[1].severity] || b[1].count - a[1].count)
        .map(([ruleId, info]) => (
          <li key={ruleId}>
            <span class={`sev-pill sev-${info.severity}`}>{SEVERITY_LABEL[info.severity]}</span>
            <code class="rule-id">{ruleId}</code>
            <span class="rule-title"><RichText text={info.title} /></span>
            <span class="rule-count">{info.count} 处</span>
          </li>
        ))}
    </ul>
  );
}

function EmptyState({
  onPick,
  onImport,
  onDropFiles,
  onExample,
  onPaste,
  onEmpty,
  busy,
  notice,
}: {
  onPick: () => void;
  onImport: (files: FileList | null) => Promise<void>;
  onDropFiles: (files: LoadedFile[]) => void;
  onExample: (key: string) => void;
  onPaste: (text: string) => void;
  onEmpty: () => void;
  busy: string | null;
  notice: string | null;
}) {
  const [paste, setPaste] = useState('');
  const [dragging, setDragging] = useState(false);
  const folderRef = useRef<HTMLInputElement>(null);

  return (
    <main class="empty">
      <div
        class={`drop-zone ${dragging ? 'drag' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={async (e) => {
          e.preventDefault();
          setDragging(false);
          if (!e.dataTransfer) return;
          try {
            const dropped = await readDroppedFiles(e.dataTransfer);
            if (!dropped.length) {
              onEmpty();
              return;
            }
            onDropFiles(dropped.map((d) => ({ ...d, path: trimToWorkflows(d.path) })));
          } catch {
            onEmpty();
          }
        }}
      >
        <div class="drop-inner">
          <div class="drop-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="40" height="40"><path d="M12 3v12m0-12 4 4m-4-4-4 4" stroke="currentColor" stroke-width="1.8" fill="none"/><path d="M4 15v3a3 3 0 0 0 3 3h10a3 3 0 0 0 3-3v-3" stroke="currentColor" stroke-width="1.8" fill="none"/></svg>
          </div>
          <h2>把工作流文件拖进来</h2>
          <p class="muted">
            支持单个或多个 <code>.yml</code> / <code>.yaml</code>，也可以选整个 <code>.github/workflows</code> 目录。文件只在浏览器里解析，不会上传。
          </p>
          <div class="drop-actions">
            <button class="btn btn-primary" onClick={onPick}>选择文件</button>
            <input
              ref={folderRef}
              type="file"
              hidden
              /* @ts-expect-error non-standard but supported in Chrome/Edge */
              webkitdirectory="true"
              directory=""
              multiple
              onChange={(e) => void onImport((e.target as HTMLInputElement).files)}
            />
            <button class="btn" onClick={() => folderRef.current?.click()}>选择目录</button>
          </div>
          {busy && <p class="muted">{busy}</p>}
          {notice && <p class="notice">{notice}</p>}
        </div>
      </div>

      <div class="empty-grid">
        <section class="card">
          <h3>用现成的样例试试</h3>
          <p class="muted">每份都对应一类真实出现过的写法。</p>
          <ul class="example-list">
            {EXAMPLES.map((ex) => (
              <li key={ex.key}>
                <button class="example" onClick={() => onExample(ex.key)}>
                  <span class="example-label">{ex.label}</span>
                  <span class="example-blurb">{ex.blurb}</span>
                  <code>{ex.path.replace('examples/workflows/', '')}</code>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section class="card">
          <h3>或者粘贴 YAML</h3>
          <textarea
            class="paste"
            placeholder={`name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}`}
            value={paste}
            onInput={(e) => setPaste((e.target as HTMLTextAreaElement).value)}
          />
          <button
            class="btn"
            disabled={!paste.trim()}
            onClick={() => {
              if (!paste.trim()) return;
              onPaste(paste);
              setPaste('');
            }}
          >
            审计这段 YAML
          </button>
        </section>
      </div>
    </main>
  );
}
