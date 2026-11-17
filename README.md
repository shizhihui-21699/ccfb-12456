# 工作流安全审计台

导入 GitHub Actions 工作流，找出**外部拉取请求触发时能拿走发布密钥**的那类写法。

这件事的真实版本是：仓库里工作流越堆越多，其中一个用 `pull_request_target` 触发、又 checkout 了贡献者分支的代码，于是贡献者在 fork 里改一行 `postinstall`，就在有写权限和密钥的任务里执行了任意命令。这类问题靠逐份看 YAML 很难发现，因为每一步单独看都合理——错的是组合。

## 快速开始

```bash
npm install
npm run build          # 打包到 dist/
npm start              # http://localhost:4173
```

浏览器里把 `.github/workflows` 拖进去（或选目录、粘贴 YAML）。**文件只在浏览器里解析，不上传**。

命令行审计（适合放进 CI）：

```bash
node src/cli.ts                                   # 默认审计 ./.github/workflows
node src/cli.ts path/to/workflows --fail-on high  # 有高危则退出码 1
node src/cli.ts .github/workflows --markdown report.md --json report.json
```

开发：

```bash
npm run dev        # esbuild watch
npm test           # 55 项：引擎 + UI 渲染 + 报告导出
npm run typecheck
```

## 它检查什么

每条问题都带**位置（文件:行:列）、证据原文、为什么危险、具体改法**，关键项还给一段可直接替换的 YAML。

| 规则 | 严重度 | 检查内容 |
| --- | --- | --- |
| **WF001** | 严重 | 特权事件（`pull_request_target` / `workflow_run` / `issue_comment` 等）下检出并执行 fork 代码。锚点是那个 `ref:`，并指出哪一步会真正跑起来 |
| **WF002** | 严重 | `workflow_run` 下载上游 artifact 后 `chmod +x` / `source` / `./` 执行——产物投毒 |
| **WF003** | 高/严重 | `pull_request` 任务暴露了**不随 fork 降级失效**的凭据：仓库密钥、OIDC 令牌 |
| **WF010** | 严重/高 | `${{ github.event.pull_request.title }}`、分支名、issue 正文等被直接拼进 `run:` / `script:` / 部分 `with:` 参数 |
| **WF011** | 高 | 用外部文本做 `if`/`case` 的准入判断（WF010 已报同一步时不重复） |
| **WF012** | 中 | `workflow_dispatch` / `workflow_call` 的 `inputs.*` 拼进脚本 |
| **WF020** | 严重 | `permissions: write-all` |
| **WF021** | 中/高/严重 | 没写 `permissions:`，权限由仓库默认值决定（按最坏情况定级） |
| **WF022** | 中/高/严重 | 任务权限超出步骤实际需要 |
| **WF030** | 严重 | 能执行外部代码的任务同时开了 `id-token: write`（可换云厂商凭据） |
| **WF040** | 低/中/高 | 第三方动作只写 `@v4` / `@main`，没固定到 40 位提交哈希；可复用工作流同理 |
| **WF041** | 高 | 与官方动作名只差一个字符的发布者（`actons/checkout`） |
| **WF042** | 中 | `docker://image:tag` 没固定摘要 |
| **WF050** | 严重 | 密钥与不可信执行在同一任务（含 `secrets: inherit`） |
| **WF051** | 中 | `pull_request` 里引用密钥（fork 拿不到，环境密钥则可能泄露） |
| **WF052** | 高 | 密钥被 echo 进日志或打进 artifact |
| **WF060** | 严重 | 自托管 runner 上跑外部事件 |
| **WF061** | 中/高 | checkout 保留凭据（`persist-credentials` 默认 true） |

### 判断口径

- **「执行了外部代码」怎么算**：`actions/checkout` 的 `ref`/`repository` 来自事件字段（只排除 base 分支、PR 编号这类安全字段）；手工 `git fetch` / `gh pr checkout`；`workflow_run` 下载并**执行**上游产物。仅仅 `git checkout` 不算——必须有后续构建/运行步骤才算「执行」。
- **产物是「数据」还是「代码」**：下载后只解析 `results/report.json`（用本仓库脚本）不算执行；`chmod +x`、`./`、`source`、`sh artifact/…`，或把产物解到工作区根目录后跑 `npm ci` 才算。
- **fork 降级**：来自 fork 的 PR，GitHub 会把 `GITHUB_TOKEN` 降为只读，所以单写作用域本身不构成提权（报 WF003 只在有密钥/OIDC 时）；同仓库分支 PR 与 `pull_request_target` 不享受这个降级，因此权限仍按最小化建议。
- **矩阵变量会追踪**：`matrix.target: ${{ fromJSON(github.event.pull_request.labels.*.name) }}` 之后，`matrix.target` 在脚本里出现也算注入。
- **`env:` 是安全的**：`env: { T: ${{ ... }} }` + `echo "$T"` 按设计不报——这是官方推荐改法。
- **评分**：严重 40 / 高 15 / 中 5 / 低 1 的加权扣分，按任务数做平方根归一，映射到 A–F。评分只用于排优先级，不做合规结论。

## 架构

```
src/core/            审计引擎（纯函数，无 DOM 依赖）
  yaml.ts            解析 + 源码位置（行列号）
  expressions.ts     ${{ }} 扫描 + 外部可控字段目录
  model.ts           触发器/任务/步骤/权限模型
  analysis.ts        「这个任务跑了外部代码吗」——所有定级的共同输入
  rules/             按类别分文件的规则集
  audit.ts           汇总、去重、评分、报告
src/cli.ts           命令行
src/ui/              Preact 界面（rail / 问题列表 / 详情 / 源码）
scripts/             build（esbuild）、test（esbuild + node:test）、serve（静态服务+CSP）
tests/               引擎测试、UI 渲染测试、fixtures
examples/workflows/  4 份演示工作流（同时被测试引用，防止两边漂移）
```

设计上的两个要点：

1. **规则只看共享分析**。`analysis.ts` 算出「这个任务是否执行外部代码」一次，WF001/WF003/WF010/WF022/WF030/WF050 都基于同一个答案，界面和 CLI 因此不会给出互相矛盾的结论。
2. **去重按根因**。artifact 投毒只报 WF002 不报 WF001；`write-all` 只报 WF020 不叠加 WF003/WF022；工作流级权限只在首个继承它的任务上出现一次。目标是让人从列表顶部往下修，而不是被同一处问题刷屏。

## 测试

55 项，`npm test`：

- **引擎**：每个规则的正例/反例、行列号精度、`env:` 不误报、矩阵污染、类似官方名称、`write-all`/`read-all`、畸形 YAML、深层嵌套与超长输入不抛异常、安全样例零发现。
- **UI**：把 `<App>` 渲染成字符串，断言规则标题、严重度、行号、改法真的出现在页面上；并验证工作流里的 `<img onerror>` 不会被当作 HTML 执行。
- **报告**：Markdown 导出包含每条规则与建议。

这些测试同时是文档：`tests/fixtures/vulnerable/*` 是要抓的写法，`tests/fixtures/safe/*` 是不该误报的写法。

## 已知边界

- 静态分析，不执行工作流。运行时拼出来的字符串（`$VAR` 里再展开）看不到。
- 未内置 GitHub 全部事件字段，未枚举的字段按「可能可控」以低一级严重度提示，宁可多报不漏报。
- `@vX` 固定哈希那条对 `actions/*` 官方动作给「低」，第三方给「中/高」；要全部清零就全部固定到 SHA。
- 评分是启发式，用来排序，不用于对外合规声明。
- 「权限超出实际需要」（WF022）只在任务的动作集合可完整识别时才报；出现无法判断的第三方动作、本地动作或 `docker://` 就跳过，避免误报。
- 已用公开仓库（preact、vite、yaml 的 `.github/workflows`，共 21 个文件）校准：误报从最初的 12 处降到 3 处低危提示，且对 `tests/fixtures/vulnerable/*` 的判定不受影响。
