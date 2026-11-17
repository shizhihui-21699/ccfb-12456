/**
 * Test runner: bundle the test files with esbuild, then hand them to
 * `node --test`.
 *
 * Node can run .ts directly, but not .tsx (the UI tests render Preact) and not
 * text imports (examples import .yml). Bundling first keeps one test command
 * for the whole codebase without pulling in a full test framework.
 */

import { build } from 'esbuild';
import { mkdir, readdir, rm } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = join(import.meta.dirname, '..');
const testsDir = join(root, 'tests');
const outDir = join(root, '.test-dist');

const yamlTextPlugin = {
  name: 'yaml-text',
  setup(pluginBuild: import('esbuild').PluginBuild) {
    pluginBuild.onLoad({ filter: /\.ya?ml$/ }, async (args) => ({
      contents: await import('node:fs/promises').then((fs) => fs.readFile(args.path, 'utf8')),
      loader: 'text',
    }));
  },
};

async function testFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'fixtures') continue;
      out.push(...(await testFiles(full)));
    } else if (/\.test\.(ts|tsx|mts)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

async function main(): Promise<void> {
  const files = await testFiles(testsDir);
  if (!files.length) {
    console.error('no test files found');
    process.exit(1);
  }

  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  await build({
    entryPoints: files,
    outdir: outDir,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: ['node22'],
    sourcemap: 'inline',
    jsx: 'automatic',
    jsxImportSource: 'preact',
    loader: { '.yml': 'text', '.yaml': 'text' },
    plugins: [yamlTextPlugin],
    external: ['preact', 'preact-render-to-string', 'yaml'],
    logLevel: 'warning',
  });

  const bundles = (await readdir(outDir)).filter((f) => f.endsWith('.mjs')).map((f) => join(outDir, f));
  const extra = process.argv.slice(2);
  const result = spawnSync(process.execPath, ['--test', ...extra, ...bundles], {
    stdio: 'inherit',
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  process.exit(result.status ?? 1);
}

void relative;
await main();
