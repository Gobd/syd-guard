import { mkdir, writeFile } from "node:fs/promises";
import { vanillaExtract } from "./vanillaExtract";
const outdir = "../internal/webui/assets";
await mkdir(outdir, { recursive: true });
const result = await Bun.build({
  entrypoints: ["src/index.tsx"],
  outdir,
  target: "browser",
  minify: true,
  naming: {
    entry: "app.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name].[ext]",
  },
  plugins: [vanillaExtract()],
  define: { "process.env.NODE_ENV": '"production"' },
});
if (!result.success) {
  console.error(result.logs);
  process.exit(1);
}
await writeFile(
  `${outdir}/index.html`,
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Syd Guard approvals</title><link rel="stylesheet" href="/app.css"></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>',
);
