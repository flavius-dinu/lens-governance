// Bundles a test with esbuild and runs it in Node.
//   FIXTURES=<dir> node test/run.mjs           the engine tests
//   FIXTURES=<dir> OUT=<dir> node test/run.mjs render   every view rendered, with Lens's UI packages stubbed
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const which = process.argv[2] === "render" ? "render" : "engines";
const stub = (name) => path.join(here, "stubs", name);
const outfile = path.join(mkdtempSync(path.join(process.env.TMPDIR ?? tmpdir(), "rg-test-")), `${which}.test.cjs`);

const stylesheets = {
  name: "stylesheets",
  setup: (builder) => builder.onResolve({ filter: /\.scss$/ }, () => ({ path: stub("scss.cjs") })),
};

await build({
  entryPoints: [path.join(here, which === "render" ? "render.test.tsx" : "engines.test.ts")],
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node20",
  jsx: "automatic",
  outfile,
  logLevel: "warning",
  plugins: which === "render" ? [stylesheets] : [],
  alias:
    which === "render"
      ? {
          "@k8slens/element-components": stub("elements.cjs"),
          "@k8slens/badge": stub("badge.cjs"),
          "@k8slens/icon": stub("icon.cjs"),
          "@k8slens/input-components": stub("inputs.cjs"),
          "@k8slens/tabs-components": stub("tabs.cjs"),
          "@k8slens/use-inject": stub("use-inject.cjs"),
        }
      : {},
});

try {
  execFileSync(process.execPath, [outfile], { stdio: "inherit", env: { ...process.env, RG_PROJECT: path.dirname(here) } });
} catch {
  process.exit(1);
}
