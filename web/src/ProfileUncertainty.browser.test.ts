import { expect, test } from "bun:test";
import { chromium } from "@playwright/test";

const browserTest =
  process.env.SYDGUARD_BROWSER_TEST === "1" ? test : test.skip;

browserTest(
  "uncertain profile saves preserve drafts and require an explicit fresh snapshot",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(
              Bun.file(
                `${import.meta.dir}/../../internal/webui/assets/${file}`,
              ),
            )
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    try {
      for (const mode of [
        "indeterminate",
        "lost transport",
        "legacy failure",
      ]) {
        const page = await browser.newPage();
        let saves = 0;
        let loads = 0;
        let reconciled = false;
        const metadata = () => ({
          id: "managed-profile",
          name: "default",
          project: "/project",
          path: "/project/.sydguard/default.json",
          revision: (reconciled ? "b" : "a").repeat(64),
          capabilities: { edit: true, reload: false, saved_decisions: false },
        });
        await page.route("**/api/**", async (route) => {
          const request = route.request();
          const path = new URL(request.url()).pathname;
          if (path === "/api/profiles")
            return route.fulfill({ json: [metadata()] });
          if (path === "/api/profiles/managed-profile") {
            if (request.method() === "PUT") {
              saves++;
              if (mode === "lost transport") return route.abort("failed");
              return route.fulfill({
                status: mode === "indeterminate" ? 503 : 502,
                json: {
                  error: "Save response unavailable",
                  code:
                    mode === "indeterminate" ? "indeterminate" : "unavailable",
                },
              });
            }
            loads++;
            if (loads > 1) reconciled = true;
            return route.fulfill({
              json: {
                ...metadata(),
                profile: {
                  version: 1,
                  name: "default",
                  files: [
                    {
                      path: reconciled ? "/fresh" : "/original",
                      access: ["read"],
                      recursive: false,
                    },
                  ],
                  network: [],
                },
              },
            });
          }
          return route.fulfill({ json: [] });
        });
        await page.goto(`${server.url}#token=test-token`);
        await page
          .getByLabel("Selected project profile")
          .selectOption("managed-profile");
        const field = page
          .getByRole("group", { name: "File rule 1" })
          .getByLabel("Path");
        const save = page.getByRole("button", {
          name: "Save profile",
          exact: true,
        });
        await field.fill("/draft");
        await save.click();
        await page
          .getByText(/Save outcome indeterminate. Your edits are preserved/)
          .waitFor();
        expect(await field.inputValue()).toBe("/draft");
        expect(await save.isDisabled()).toBe(true);
        await field.fill("/draft-still-preserved");
        expect(await save.isDisabled()).toBe(true);
        expect(saves).toBe(1);
        expect(loads).toBe(1);
        const load = page.getByRole("button", {
          name: "Load current revision",
        });
        page.once("dialog", (dialog) => dialog.dismiss());
        await load.click();
        expect(await field.inputValue()).toBe("/draft-still-preserved");
        expect(loads).toBe(1);
        page.once("dialog", (dialog) => dialog.accept());
        await load.click();
        await page
          .getByText(`Revision: ${"b".repeat(64)}`, { exact: true })
          .waitFor();
        expect(await field.inputValue()).toBe("/fresh");
        expect(await save.isDisabled()).toBe(true);
        await field.fill("/reviewed-after-reconciliation");
        await page.waitForFunction(() =>
          Array.from(document.querySelectorAll("button")).some(
            (button) =>
              button.textContent === "Save profile" && !button.disabled,
          ),
        );
        expect(loads).toBe(2);
        expect(saves).toBe(1);
        await page.close();
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  20_000,
);

browserTest(
  "catalog responses slower than polling are not permanently superseded",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(
              Bun.file(
                `${import.meta.dir}/../../internal/webui/assets/${file}`,
              ),
            )
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let active = 0;
    let maximum = 0;
    const metadata = {
      id: "slow-profile",
      name: "default",
      project: "/project",
      path: "/project/.sydguard/default.json",
      revision: "a".repeat(64),
      capabilities: { edit: true, reload: false, saved_decisions: false },
    };
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/profiles") {
          active++;
          maximum = Math.max(maximum, active);
          await new Promise((resolve) => setTimeout(resolve, 2500));
          active--;
          return route.fulfill({ json: [metadata] });
        }
        if (path === "/api/profiles/slow-profile")
          return route.fulfill({
            json: {
              ...metadata,
              profile: {
                version: 1,
                name: "default",
                files: [
                  { path: "/original", access: ["read"], recursive: false },
                ],
                network: [],
              },
            },
          });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      await page
        .getByLabel("Selected project profile")
        .selectOption("slow-profile", { timeout: 6000 });
      await page
        .getByRole("group", { name: "File rule 1" })
        .getByLabel("Path")
        .fill("/reviewed");
      expect(
        await page
          .getByRole("button", { name: "Save profile", exact: true })
          .isEnabled(),
      ).toBe(true);
      expect(maximum).toBe(1);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  12_000,
);

browserTest(
  "a stalled status read cannot freeze later live approvals",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(
              Bun.file(
                `${import.meta.dir}/../../internal/webui/assets/${file}`,
              ),
            )
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let calls = 0;
    let release: (() => void) | undefined;
    const stalled = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/sessions") {
          calls++;
          if (calls === 1) {
            await stalled;
            return route.fulfill({ json: [] });
          }
          return route.fulfill({
            json: [
              {
                id: "live-id",
                name: "agent",
                state: "running",
                project: "/project",
              },
            ],
          });
        }
        if (path === "/api/files/pending")
          return route.fulfill({
            json: [
              {
                id: "file-id",
                session_id: "live-id",
                session_name: "agent",
                capability: "read",
                path: "/requested",
                attempts: 1,
              },
            ],
          });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      await page.waitForFunction(
        () =>
          Array.from(document.querySelectorAll("button")).some(
            (button) =>
              button.textContent === "Allow exact path for run" &&
              !button.disabled,
          ),
        undefined,
        { timeout: 6000 },
      );
      expect(calls).toBeGreaterThanOrEqual(2);
      const allow = page.getByRole("button", {
        name: "Allow exact path for run",
      });
      expect(await allow.isEnabled()).toBe(true);
      release?.();
      await page.waitForTimeout(100);
      expect(await allow.isEnabled()).toBe(true);
      expect(await page.getByText("Project: /project").count()).toBe(1);
    } finally {
      release?.();
      await browser.close();
      server.stop();
    }
  },
  12_000,
);
