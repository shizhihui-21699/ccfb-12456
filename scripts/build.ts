/**
 * Build: bundle the Preact UI into dist/ (app.js + app.css + index.html).
 *
 * esbuild is used directly rather than through Vite: the app has no dev server
 * needs beyond static files, and a 30-line script keeps the dependency surface
 * small. `--watch` rebuilds on change for `npm run dev`.
 */

import { build, context } from 'esbuild';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const root = join(import.meta.dirname, '..');
const watch = process.argv.includes('--watch');

/** Import .yml/.yaml as text so the examples ship inside the bundle. */
const yamlTextPlugin = {
  name: 'yaml-text',
  setup(pluginBuild: import('esbuild').PluginBuild) {
    pluginBuild.onLoad({ filter: /\.ya?ml$/ }, async (args) => ({
      contents: await readFile(args.path, 'utf8'),
      loader: 'text',
    }));
  },
};

const options: import('esbuild').BuildOptions = {
  entryPoints: [join(root, 'src/ui/main.tsx')],
  outdir: join(root, 'dist'),
  entryNames: 'app',
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: !watch,
  sourcemap: watch,
  jsx: 'automatic',
  jsxImportSource: 'preact',
  loader: { '.yml': 'text', '.yaml': 'text', '.css': 'css' },
  plugins: [yamlTextPlugin],
  logLevel: 'info',
  metafile: true,
};

async function copyHtml(): Promise<void> {
  const source = join(root, 'src/ui/index.html');
  const target = join(root, 'dist/index.html');
  await mkdir(dirname(target), { recursive: true });
  await copyFile(source, target);
}

async function writeBuildInfo(result: import('esbuild').BuildResult): Promise<void> {
  const bytes = Object.values(result.metafile?.outputs ?? {}).reduce((sum, o) => sum + o.bytes, 0);
  await writeFile(
    join(root, 'dist/build-info.json'),
    JSON.stringify({ builtAt: new Date().toISOString(), bytes }, null, 2),
  );
}

async function main(): Promise<void> {
  await mkdir(join(root, 'dist'), { recursive: true });
  await copyHtml();

  if (!existsSync(join(root, 'node_modules'))) {
    console.error('先运行 npm install');
    process.exit(1);
  }

  if (watch) {
    const ctx = await context(options);
    await ctx.watch();
    console.log('watching src/ for changes… (dist/index.html 已就绪，用 npm start 提供服务)');
    return;
  }

  const result = await build(options);
  await writeBuildInfo(result);
  console.log(`built dist/ (${Object.keys(result.metafile?.outputs ?? {}).length} files)`);
}

await main();
