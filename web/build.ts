// Builds the UI into ../internal/ui/dist (embedded into the Go binary).
import { mkdir, rm, writeFile } from "node:fs/promises";
import { vanillaExtract } from "./vanillaExtract";

const outdir = "../internal/ui/dist";
await rm(outdir, { recursive: true, force: true });
await mkdir(`${outdir}/assets`, { recursive: true });
const result = await Bun.build({
  entrypoints: ["src/index.tsx"],
  outdir: `${outdir}/assets`,
  target: "browser",
  minify: true,
  naming: { entry: "app.[ext]", chunk: "[name].[ext]", asset: "[name].[ext]" },
  plugins: [vanillaExtract()],
  define: { "process.env.NODE_ENV": '"production"' },
});
if (!result.success) {
  console.error(result.logs);
  process.exit(1);
}
await writeFile(
  `${outdir}/index.html`,
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>sydguard</title><link rel="stylesheet" href="/assets/app.css"></head><body><div id="root"></div><script type="module" src="/assets/app.js"></script></body></html>\n',
);
