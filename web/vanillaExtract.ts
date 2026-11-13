import type { BunPlugin } from "bun";
import {
  compile,
  cssFileFilter,
  getSourceFromVirtualCssFile,
  processVanillaFile,
  virtualCssFileFilter,
} from "@vanilla-extract/integration";

// Official vanilla-extract compilation/virtual-CSS hooks, adapted to Bun.
export function vanillaExtract(): BunPlugin {
  return {
    name: "vanilla-extract",
    setup(build) {
      const namespace = "sydguard-css";
      build.onResolve({ filter: virtualCssFileFilter }, (args) => ({
        path: args.path,
        namespace,
      }));
      build.onLoad({ filter: /.*/, namespace }, async (args) => ({
        contents: (await getSourceFromVirtualCssFile(args.path)).source,
        loader: "css",
      }));
      build.onLoad({ filter: cssFileFilter }, async (args) => {
        const result = await compile({
          filePath: args.path,
          cwd: process.cwd(),
          identOption: "short",
        });
        // Give the evaluator a working require without mutating Node/Bun loaders.
        const source = `function require(id){return process.getBuiltinModule('module').createRequire(${JSON.stringify(args.path)})(id);}\n${result.source}`;
        return {
          contents: await processVanillaFile({
            source,
            filePath: args.path,
            identOption: "short",
          }),
          loader: "js",
        };
      });
    },
  };
}
