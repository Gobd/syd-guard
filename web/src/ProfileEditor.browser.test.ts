import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chromium } from "@playwright/test";
import { vanillaExtract } from "../vanillaExtract";

const browserTest =
  process.env.SYDGUARD_BROWSER_TEST === "1" ? test : test.skip;

function requestProfileBytes(body: string): string {
  const marker = ',"profile":';
  const offset = body.indexOf(marker);
  if (offset < 0 || !body.endsWith("}"))
    throw new Error("Unexpected save envelope");
  return body.slice(offset + marker.length, -1);
}
function requestProfileDigest(body: string): string {
  return createHash("sha256")
    .update(requestProfileBytes(body), "utf8")
    .digest("hex");
}

browserTest(
  "JSON drafts survive refresh and uncertain saves, and CAS saves only validated intent",
  async () => {
    const build = await Bun.build({
      entrypoints: [`${import.meta.dir}/index.tsx`],
      target: "browser",
      naming: "app.[ext]",
      plugins: [vanillaExtract()],
      define: { "process.env.NODE_ENV": '"production"' },
    });
    if (!build.success) throw new Error(String(build.logs));
    const assets = new Map(
      build.outputs.map((file) => [file.path.split("/").pop(), file]),
    );
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === "/")
          return new Response(
            '<html><head><link rel="stylesheet" href="/app.css"></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>',
            { headers: { "Content-Type": "text/html" } },
          );
        const asset = assets.get(path.slice(1));
        return asset
          ? new Response(asset, {
              headers: {
                "Content-Type": path.endsWith(".js")
                  ? "text/javascript"
                  : "text/css",
              },
            })
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let revision = "a".repeat(64);
    let saves = 0;
    let loads = 0;
    let mode: "conflict" | "uncertain" | "success" = "conflict";
    const profile = {
      version: 1,
      name: "default",
      files: [{ path: "/original", access: ["read"], recursive: false }],
      network: [],
    };
    const metadata = (id: string) => ({
      id,
      name: "default",
      project: id === "one" ? "/one" : "/two",
      path: `/${id}/profile.json`,
      revision,
      capabilities: { edit: true, reload: false },
    });
    let savedBody: unknown;
    try {
      await page.route("**/api/**", async (route) => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (path === "/api/profiles")
          return route.fulfill({ json: [metadata("one"), metadata("two")] });
        if (path === "/api/profiles/one" || path === "/api/profiles/two") {
          const id = path.split("/").pop()!;
          if (request.method() === "PUT") {
            saves++;
            savedBody = request.postDataJSON();
            if (mode === "conflict")
              return route.fulfill({
                status: 409,
                json: { error: "conflict", current_revision: "b".repeat(64) },
              });
            if (mode === "uncertain")
              return route.fulfill({
                status: 503,
                json: { code: "indeterminate", error: "unknown" },
              });
            const body = request.postDataJSON();
            revision = requestProfileDigest(request.postData()!);
            return route.fulfill({
              json: {
                status: "saved",
                applied: false,
                retry_required: false,
                restart_required: false,
                message: "Saved profile",
                profile: { ...metadata(id), profile: body.profile },
              },
            });
          }
          loads++;
          return route.fulfill({ json: { ...metadata(id), profile } });
        }
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      const select = page.getByLabel("Selected project profile");
      await select.selectOption("one");
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      const editor = page.getByLabel("Saved profile JSON");
      const save = page.getByRole("button", {
        name: "Save profile",
        exact: true,
      });
      await editor.fill('{"version":');
      expect(await save.isDisabled()).toBe(true);
      await page.waitForTimeout(2300);
      expect(await editor.inputValue()).toBe('{"version":');
      page.once("dialog", (dialog) => dialog.dismiss());
      await page.getByRole("button", { name: "Form", exact: true }).click();
      expect(await editor.inputValue()).toBe('{"version":');
      page.once("dialog", (dialog) => dialog.dismiss());
      await select.selectOption("two");
      expect(await editor.inputValue()).toBe('{"version":');
      expect(loads).toBe(1);
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: "Form", exact: true }).click();
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      expect(JSON.parse(await editor.inputValue())).toEqual(profile);
      await editor.fill('{"version":');
      revision = "b".repeat(64);
      await page
        .getByText(/Profile metadata is stale/)
        .waitFor({ timeout: 5000 });
      expect(await editor.inputValue()).toBe('{"version":');
      expect(await save.isDisabled()).toBe(true);
      page.once("dialog", (dialog) => dialog.dismiss());
      await page.getByRole("button", { name: "Load current revision" }).click();
      expect(await editor.inputValue()).toBe('{"version":');
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: "Load current revision" }).click();
      expect(loads).toBe(2);
      const draft = {
        ...profile,
        files: [{ path: "/new", access: ["write"], recursive: true }],
        network: [{ host: "example.com", port: 443, transport: "tcp" }],
      };
      await editor.fill(JSON.stringify({ ...draft, name: "other" }));
      expect(await save.isDisabled()).toBe(true);
      await editor.fill(JSON.stringify({ ...draft, deny: [] }));
      expect(await save.isDisabled()).toBe(true);
      await editor.fill(JSON.stringify(draft));
      await page.getByRole("button", { name: "Form", exact: true }).click();
      expect(
        await page
          .getByRole("group", { name: "File rule 1" })
          .getByLabel("Path")
          .inputValue(),
      ).toBe("/new");
      await page.getByRole("button", { name: "Add file rule" }).click();
      await page
        .getByRole("group", { name: "File rule 2" })
        .getByRole("button", { name: "Remove file rule" })
        .click();
      await page.getByRole("button", { name: "Add network rule" }).click();
      await page
        .getByRole("group", { name: "Network rule 2" })
        .getByRole("button", { name: "Remove network rule" })
        .click();
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      await save.click();
      await page.getByText(/Revision conflict/).waitFor();
      expect(await editor.inputValue()).toBe(JSON.stringify(draft));
      expect(await save.isDisabled()).toBe(true);
      await editor.fill('{"invalid":');
      const load = page.getByRole("button", { name: "Load current revision" });
      page.once("dialog", (dialog) => dialog.dismiss());
      await load.click();
      expect(await editor.inputValue()).toBe('{"invalid":');
      expect(loads).toBe(2);
      revision = "b".repeat(64);
      page.once("dialog", (dialog) => dialog.accept());
      await load.click();
      expect(loads).toBe(3);
      mode = "uncertain";
      await editor.fill(JSON.stringify(draft));
      await page.waitForFunction(() =>
        Array.from(document.querySelectorAll("button")).some(
          (button) => button.textContent === "Save profile" && !button.disabled,
        ),
      );
      await save.click();
      await page.getByText(/Save outcome indeterminate/).waitFor();
      expect(await editor.inputValue()).toBe(JSON.stringify(draft));
      expect(await save.isDisabled()).toBe(true);
      expect(saves).toBe(2);
      page.once("dialog", (dialog) => dialog.accept());
      await load.click();
      mode = "success";
      await editor.fill(JSON.stringify(draft));
      await save.click();
      await page.getByText(/Saved profile Applied: no/).waitFor();
      expect(savedBody).toEqual({
        expected_revision: "b".repeat(64),
        profile: draft,
      });
      expect(saves).toBe(3);
      await select.selectOption("two");
      await page.getByText("Project: /two", { exact: true }).waitFor();
      expect(loads).toBe(5);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  20_000,
);

browserTest(
  "raw-only edits are protected and inconsistent save responses require reconciliation",
  async () => {
    const build = await Bun.build({
      entrypoints: [`${import.meta.dir}/index.tsx`],
      target: "browser",
      naming: "app.[ext]",
      plugins: [vanillaExtract()],
      define: { "process.env.NODE_ENV": '"production"' },
    });
    if (!build.success) throw new Error(String(build.logs));
    const assets = new Map(
      build.outputs.map((file) => [file.path.split("/").pop(), file]),
    );
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === "/")
          return new Response(
            '<html><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>',
            { headers: { "Content-Type": "text/html" } },
          );
        const asset = assets.get(path.slice(1));
        return asset
          ? new Response(asset, {
              headers: {
                "Content-Type": path.endsWith(".js")
                  ? "text/javascript"
                  : "text/css",
              },
            })
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const profile = {
      version: 1,
      name: "default",
      files: [{ path: "/original", access: ["read"], recursive: false }],
      network: [],
    };
    const metadata = {
      id: "one",
      name: "default",
      project: "/one",
      path: "/one/profile.json",
      revision: "a".repeat(64),
      capabilities: { edit: true, reload: false },
    };
    let kind = "id";
    let saves = 0;
    let loads = 0;
    let lastSubmittedBytes = "";
    try {
      await page.route("**/api/**", async (route) => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (path === "/api/profiles")
          return route.fulfill({
            json: [
              metadata,
              {
                ...metadata,
                id: "two",
                project: "/two",
                path: "/two/profile.json",
              },
            ],
          });
        if (path === "/api/profiles/one") {
          if (request.method() !== "PUT") {
            loads++;
            return route.fulfill({ json: { ...metadata, profile } });
          }
          saves++;
          const submitted = request.postDataJSON().profile;
          lastSubmittedBytes = requestProfileBytes(request.postData()!);
          const digest = requestProfileDigest(request.postData()!);
          let returned: unknown = {
            ...metadata,
            revision: digest,
            profile: submitted,
          };
          if (kind === "id")
            returned = {
              ...metadata,
              revision: digest,
              id: "other",
              profile: submitted,
            };
          if (kind === "name")
            returned = {
              ...metadata,
              revision: digest,
              name: "other",
              profile: submitted,
            };
          if (kind === "project")
            returned = {
              ...metadata,
              revision: digest,
              project: "/other",
              profile: submitted,
            };
          if (kind === "path")
            returned = {
              ...metadata,
              revision: digest,
              path: "/other",
              profile: submitted,
            };
          if (kind === "revision")
            returned = { ...metadata, revision: "bad", profile: submitted };
          if (kind === "old-revision")
            returned = {
              ...metadata,
              revision: metadata.revision,
              profile: submitted,
            };
          if (kind === "wrong-digest")
            returned = {
              ...metadata,
              revision: "f".repeat(64),
              profile: submitted,
            };
          if (kind === "content")
            returned = { ...metadata, revision: digest, profile };
          if (kind === "shape") returned = null;
          if (kind === "invalid-profile")
            returned = {
              ...metadata,
              revision: digest,
              profile: { ...submitted, files: null },
            };
          if (kind === "capabilities")
            returned = {
              ...metadata,
              revision: digest,
              profile: submitted,
              capabilities: { edit: "yes" },
            };
          if (kind === "reordered")
            returned = {
              ...metadata,
              revision: digest,
              profile: {
                network: submitted.network,
                files: submitted.files.map(
                  (rule: {
                    path: string;
                    access: string[];
                    recursive: boolean;
                  }) => ({
                    recursive: rule.recursive,
                    access: rule.access,
                    path: rule.path,
                  }),
                ),
                name: submitted.name,
                version: submitted.version,
              },
            };
          return route.fulfill({
            json: {
              status: "saved",
              applied: kind === "applied",
              retry_required: false,
              restart_required: false,
              message: "Saved profile",
              profile: returned,
            },
          });
        }
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      const select = page.getByLabel("Selected project profile");
      await select.selectOption("one");
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      const editor = page.getByLabel("Saved profile JSON");
      const save = page.getByRole("button", {
        name: "Save profile",
        exact: true,
      });
      const load = page.getByRole("button", { name: "Load current revision" });
      const rawOnly = JSON.stringify(
        { network: [], files: profile.files, name: "default", version: 1 },
        null,
        4,
      );
      await editor.fill(rawOnly);
      expect(await save.isDisabled()).toBe(true);
      const fractional = JSON.stringify({
        ...profile,
        network: [{ host: "example.com", port: 443, transport: "tcp" }],
      }).replace('"port":443', '"port":443.00000000000000001');
      await editor.fill(fractional);
      expect(await save.isDisabled()).toBe(true);
      await editor.fill(
        JSON.stringify(profile).replace(
          '"version":1',
          '"version":1.00000000000000001',
        ),
      );
      expect(await save.isDisabled()).toBe(true);
      await editor.fill(rawOnly);
      expect(
        await page.evaluate(
          () =>
            !window.dispatchEvent(
              new Event("beforeunload", { cancelable: true }),
            ),
        ),
      ).toBe(true);
      await page.getByRole("button", { name: "Form", exact: true }).click();
      expect(
        await page.evaluate(
          () =>
            !window.dispatchEvent(
              new Event("beforeunload", { cancelable: true }),
            ),
        ),
      ).toBe(true);
      page.once("dialog", (dialog) => dialog.dismiss());
      await page
        .getByLabel("UI access token (not the controller’s master token)")
        .fill("other-token");
      expect(
        await page
          .getByLabel("UI access token (not the controller’s master token)")
          .inputValue(),
      ).toBe("test-token");
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      expect(await editor.inputValue()).toBe(rawOnly);
      page.once("dialog", (dialog) => dialog.dismiss());
      await load.click();
      expect(await editor.inputValue()).toBe(rawOnly);
      page.once("dialog", (dialog) => dialog.dismiss());
      await select.selectOption("two");
      expect(await editor.inputValue()).toBe(rawOnly);
      await page.getByRole("button", { name: "Form", exact: true }).click();
      await page
        .getByRole("group", { name: "File rule 1" })
        .getByLabel("Path")
        .fill("/form-change");
      page.once("dialog", (dialog) => dialog.dismiss());
      await save.click();
      expect(saves).toBe(0);
      page.once("dialog", (dialog) => dialog.dismiss());
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      expect(
        await page
          .getByRole("group", { name: "File rule 1" })
          .getByLabel("Path")
          .inputValue(),
      ).toBe("/form-change");
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      expect(JSON.parse(await editor.inputValue()).files[0].path).toBe(
        "/form-change",
      );
      page.once("dialog", (dialog) => dialog.accept());
      await load.click();
      expect(loads).toBe(2);
      const draft = {
        ...profile,
        files: [
          { path: "/reviewed/😀é<&\u2028", access: ["read"], recursive: false },
        ],
      };
      const rawDraft = JSON.stringify(draft, null, 4);
      for (const invalid of [
        "id",
        "name",
        "project",
        "path",
        "revision",
        "old-revision",
        "wrong-digest",
        "content",
        "shape",
        "invalid-profile",
        "capabilities",
        "applied",
      ]) {
        kind = invalid;
        await editor.fill(rawDraft);
        await save.click();
        await page.getByText(/Save outcome indeterminate/).waitFor();
        expect(await editor.inputValue()).toBe(rawDraft);
        expect(await save.isDisabled()).toBe(true);
        expect(await page.getByText(/Saved profile Applied/).count()).toBe(0);
        const before = saves;
        page.once("dialog", (dialog) => dialog.dismiss());
        await load.click();
        expect(await editor.inputValue()).toBe(rawDraft);
        expect(saves).toBe(before);
        page.once("dialog", (dialog) => dialog.accept());
        await load.click();
      }
      kind = "reordered";
      await editor.fill(rawDraft);
      await save.click();
      await page.getByText(/Saved profile Applied: no/).waitFor();
      expect(await editor.inputValue()).toBe(rawDraft);
      expect(lastSubmittedBytes).toBe(JSON.stringify(draft));
      expect(lastSubmittedBytes).not.toBe(rawDraft);
      expect(
        await page.evaluate(() =>
          window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
        ),
      ).toBe(true);
      expect(saves).toBe(13);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  30_000,
);

browserTest(
  "digest failure and token changes before digest never submit a save",
  async () => {
    const build = await Bun.build({
      entrypoints: [`${import.meta.dir}/index.tsx`],
      target: "browser",
      naming: "app.[ext]",
      plugins: [vanillaExtract()],
      define: { "process.env.NODE_ENV": '"production"' },
    });
    if (!build.success) throw new Error(String(build.logs));
    const assets = new Map(
      build.outputs.map((file) => [file.path.split("/").pop(), file]),
    );
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === "/")
          return new Response(
            '<html><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>',
            { headers: { "Content-Type": "text/html" } },
          );
        const asset = assets.get(path.slice(1));
        return asset
          ? new Response(asset, {
              headers: {
                "Content-Type": path.endsWith(".js")
                  ? "text/javascript"
                  : "text/css",
              },
            })
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const metadata = {
      id: "one",
      name: "default",
      project: "/one",
      path: "/one/profile.json",
      revision: "a".repeat(64),
      capabilities: { edit: true, reload: false },
    };
    const profile = {
      version: 1,
      name: "default",
      files: [{ path: "/original", access: ["read"], recursive: false }],
      network: [],
    };
    let saves = 0;
    try {
      await page.route("**/api/**", async (route) => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (path === "/api/profiles")
          return route.fulfill({ json: [metadata] });
        if (path === "/api/profiles/one") {
          if (request.method() === "PUT") {
            saves++;
            return route.fulfill({ status: 500 });
          }
          return route.fulfill({ json: { ...metadata, profile } });
        }
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      await page.getByLabel("Selected project profile").selectOption("one");
      await page.getByRole("button", { name: "JSON", exact: true }).click();
      const editor = page.getByLabel("Saved profile JSON");
      const raw = JSON.stringify(
        { ...profile, files: [{ ...profile.files[0], path: "/draft" }] },
        null,
        4,
      );
      await editor.fill(raw);
      const save = page.getByRole("button", {
        name: "Save profile",
        exact: true,
      });
      await page.evaluate(() => {
        const state = window as unknown as {
          originalDigest: SubtleCrypto["digest"];
        };
        state.originalDigest = crypto.subtle.digest.bind(crypto.subtle);
        Object.defineProperty(crypto.subtle, "digest", {
          configurable: true,
          value: () => Promise.reject(new Error("unavailable")),
        });
      });
      await save.click();
      await page
        .getByText(/Profile was not submitted: unable to calculate/)
        .waitFor();
      expect(await editor.inputValue()).toBe(raw);
      expect(await save.isEnabled()).toBe(true);
      expect(saves).toBe(0);
      await page.evaluate(() => {
        const state = window as unknown as {
          originalDigest: SubtleCrypto["digest"];
          digestStarted: boolean;
          releaseDigest: () => void;
        };
        Object.defineProperty(crypto.subtle, "digest", {
          configurable: true,
          value: (...args: Parameters<SubtleCrypto["digest"]>) =>
            new Promise<ArrayBuffer>((resolve, reject) => {
              state.digestStarted = true;
              state.releaseDigest = () => {
                void state.originalDigest(...args).then(resolve, reject);
              };
            }),
        });
      });
      await save.click();
      await page.waitForFunction(
        () =>
          (window as unknown as { digestStarted?: boolean }).digestStarted ===
          true,
      );
      page.once("dialog", (dialog) => dialog.accept());
      await page
        .getByLabel("UI access token (not the controller’s master token)")
        .fill("second-token");
      await page.getByLabel("Selected project profile").waitFor();
      await page.evaluate(() =>
        (window as unknown as { releaseDigest: () => void }).releaseDigest(),
      );
      await page.waitForTimeout(200);
      expect(saves).toBe(0);
      expect(
        await page
          .getByLabel("UI access token (not the controller’s master token)")
          .inputValue(),
      ).toBe("second-token");
    } finally {
      await browser.close();
      server.stop();
    }
  },
  15_000,
);
