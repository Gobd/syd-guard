import { expect, test } from "bun:test";
import { chromium } from "@playwright/test";

const assets =
  process.env.SYDGUARD_BROWSER_ASSETS ??
  `${import.meta.dir}/../../internal/webui/assets`;

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
          ? new Response(Bun.file(`${assets}/${file}`))
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
          ? new Response(Bun.file(`${assets}/${file}`))
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
          await new Promise((resolve) => setTimeout(resolve, 4100));
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
        .selectOption("slow-profile", { timeout: 7000 });
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
  16_000,
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
          ? new Response(Bun.file(`${assets}/${file}`))
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

browserTest(
  "successful snapshots remain usable during slow refreshes and failures fail closed",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let catalogCalls = 0;
    let statusCalls = 0;
    let catalogFailure = false;
    let statusFailure = false;
    let invalidStatus = false;
    let mismatchedSession = false;
    let decisions = 0;
    const metadata = {
      id: "profile-id",
      name: "default",
      project: "/project",
      path: "/project/default.json",
      revision: "a".repeat(64),
      capabilities: { edit: true, reload: true, saved_decisions: true },
    };
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/profiles") {
          catalogCalls++;
          await new Promise((resolve) => setTimeout(resolve, 4100));
          if (catalogFailure) return route.fulfill({ status: 503 });
          return route.fulfill({ json: [metadata] });
        }
        if (path === "/api/profiles/profile-id")
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
        if (path === "/api/sessions") {
          statusCalls++;
          await new Promise((resolve) => setTimeout(resolve, 700));
          if (statusFailure) return route.fulfill({ status: 503 });
          if (invalidStatus)
            return route.fulfill({
              json: [
                {
                  id: "session-id",
                  name: "agent",
                  state: "running",
                  project: "/project",
                  managed_live: {
                    session: "root",
                    project: "project",
                    profile: "default",
                    generation: "1",
                    sequence: "1",
                    saved_revision: "revision",
                    state: "pending",
                    engine_digest: "digest",
                    last_confirmed_at: "2025-01-01T00:00:00Z",
                    pending_sequence: "not-a-number",
                  },
                },
              ],
            });
          return route.fulfill({
            json: [
              {
                id: "session-id",
                name: mismatchedSession ? "other" : "agent",
                state: "running",
                project: "/project",
                profile: {
                  id: "profile-id",
                  name: "default",
                  revision: metadata.revision,
                },
              },
            ],
          });
        }
        if (path === "/api/files/pending")
          return route.fulfill({
            json: [
              {
                id: "file-id",
                session_id: "session-id",
                session_name: "agent",
                capability: "read",
                path: "/requested",
                attempts: 1,
              },
            ],
          });
        if (path.endsWith("/decisions")) decisions++;
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      const select = page.getByLabel("Selected project profile");
      expect(await select.isDisabled()).toBe(true);
      const deny = page.getByRole("button", { name: "Deny for run" });
      await deny.waitFor();
      expect(await deny.isEnabled()).toBe(true);
      expect(await select.isDisabled()).toBe(true);
      await select.selectOption("profile-id", { timeout: 7000 });
      const field = page
        .getByRole("group", { name: "File rule 1" })
        .getByLabel("Path");
      await field.fill("/draft");
      const save = page.getByRole("button", {
        name: "Save profile",
        exact: true,
      });
      const savedDecision = page.getByRole("button", {
        name: "Save to profile (unavailable)",
        exact: true,
      });
      expect(await save.isEnabled()).toBe(true);
      expect(await savedDecision.isDisabled()).toBe(true);
      await page
        .waitForFunction(() => false, undefined, { timeout: 500 })
        .catch(() => {});
      // Sample across a pending 4.1s catalog refresh and a delayed status poll.
      for (let i = 0; i < 25; i++) {
        expect(await deny.isEnabled()).toBe(true);
        expect(await save.isEnabled()).toBe(true);
        expect(await savedDecision.isDisabled()).toBe(true);
        await page.waitForTimeout(100);
      }
      expect(catalogCalls).toBeGreaterThanOrEqual(2);
      expect(statusCalls).toBeGreaterThanOrEqual(3);
      catalogFailure = true;
      await page
        .getByText(/Profile service unavailable or refreshing/)
        .waitFor({ timeout: 7000 });
      expect(await save.isDisabled()).toBe(true);
      expect(await field.inputValue()).toBe("/draft");
      expect(
        await page
          .getByRole("button", { name: /Save to profile/ })
          .isDisabled(),
      ).toBe(true);
      expect(await deny.isEnabled()).toBe(true);
      statusFailure = true;
      await page
        .getByRole("alert")
        .getByText(/displayed data may be stale/)
        .waitFor({ timeout: 5000 });
      expect(await deny.isDisabled()).toBe(true);
      expect(await field.inputValue()).toBe("/draft");
      statusFailure = false;
      mismatchedSession = true;
      await page
        .getByText("Project: Unavailable; refresh before deciding")
        .waitFor({ timeout: 5000 });
      expect(await deny.isDisabled()).toBe(true);
      invalidStatus = true;
      await page
        .getByRole("alert")
        .getByText(/Invalid status response/)
        .waitFor({ timeout: 5000 });
      expect(await deny.isDisabled()).toBe(true);
      expect(await field.inputValue()).toBe("/draft");
      expect(decisions).toBe(0);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  25_000,
);

browserTest(
  "token changes invalidate snapshots and late old-token responses cannot restore them",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let oldCatalog = 0;
    let oldStatus = 0;
    let oldDecisions = 0;
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        const old = route.request().headers().authorization === "Bearer old";
        if (!old) return route.fulfill({ status: 401 });
        if (path === "/api/profiles") {
          oldCatalog++;
          if (oldCatalog > 1) await gate;
          return route.fulfill({
            json: [
              {
                id: "p",
                name: "default",
                project: "/project",
                path: "/p",
                revision: "a",
                capabilities: { edit: true },
              },
            ],
          });
        }
        if (path === "/api/sessions") {
          oldStatus++;
          if (oldStatus > 1) await gate;
          return route.fulfill({
            json: [
              { id: "s", name: "agent", state: "running", project: "/project" },
            ],
          });
        }
        if (path === "/api/files/decisions") {
          oldDecisions++;
          await gate;
          return route.fulfill({
            json: { status: "applied; retry the operation" },
          });
        }
        if (path === "/api/files/pending")
          return route.fulfill({
            json: [
              {
                id: "f",
                session_id: "s",
                session_name: "agent",
                capability: "read",
                path: "/file",
                attempts: 1,
              },
            ],
          });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=old`);
      const deny = page.getByRole("button", { name: "Deny for run" });
      await deny.waitFor();
      expect(await deny.isEnabled()).toBe(true);
      await page
        .waitForFunction(() => false, undefined, { timeout: 2500 })
        .catch(() => {});
      expect(oldCatalog).toBeGreaterThanOrEqual(2);
      expect(oldStatus).toBeGreaterThanOrEqual(2);
      await deny.click();
      expect(oldDecisions).toBe(1);
      await page
        .getByLabel("UI access token (not the controller’s master token)")
        .fill("new");
      await page.getByRole("alert").getByText(/401/).waitFor();
      const oldCatalogAtChange = oldCatalog;
      const oldStatusAtChange = oldStatus;
      release?.();
      await page.waitForTimeout(300);
      expect(oldCatalog).toBe(oldCatalogAtChange);
      expect(oldStatus).toBe(oldStatusAtChange);
      expect(await page.getByRole("status").textContent()).toBe("");
      expect(
        await page.getByText("No tracked foreground sessions.").count(),
      ).toBe(1);
      expect(
        await page.getByRole("button", { name: "Deny for run" }).count(),
      ).toBe(0);
      expect(
        await page.getByLabel("Selected project profile").isDisabled(),
      ).toBe(true);
    } finally {
      release?.();
      await browser.close();
      server.stop();
    }
  },
  12_000,
);

browserTest(
  "stalled background snapshots eventually time out and fail closed",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let catalogCalls = 0;
    let statusCalls = 0;
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/profiles") {
          if (++catalogCalls > 1) await gate;
          return route
            .fulfill({
              json: [
                {
                  id: "p",
                  name: "default",
                  project: "/project",
                  path: "/p",
                  revision: "a",
                  capabilities: { saved_decisions: true },
                },
              ],
            })
            .catch(() => {});
        }
        if (path === "/api/sessions") {
          if (++statusCalls > 1) await gate;
          return route
            .fulfill({
              json: [
                {
                  id: "s",
                  name: "agent",
                  state: "running",
                  project: "/project",
                  profile: { id: "p", name: "default", revision: "a" },
                },
              ],
            })
            .catch(() => {});
        }
        if (path === "/api/files/pending")
          return route.fulfill({
            json: [
              {
                id: "f",
                session_id: "s",
                session_name: "agent",
                capability: "read",
                path: "/file",
                attempts: 1,
              },
            ],
          });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      const deny = page.getByRole("button", { name: "Deny for run" });
      const saved = page.getByRole("button", {
        name: "Save to profile (unavailable)",
        exact: true,
      });
      await saved.waitFor();
      expect(await deny.isEnabled()).toBe(true);
      expect(await saved.isDisabled()).toBe(true);
      await page
        .getByText(/Profile service unavailable or refreshing/)
        .waitFor({ timeout: 16000 });
      await page
        .getByRole("alert")
        .getByText(/displayed data may be stale/)
        .waitFor({ timeout: 3000 });
      expect(await deny.isDisabled()).toBe(true);
      expect(
        await page
          .getByRole("button", { name: /Save to profile/ })
          .isDisabled(),
      ).toBe(true);
      expect(catalogCalls).toBeGreaterThanOrEqual(2);
      expect(statusCalls).toBeGreaterThanOrEqual(2);
    } finally {
      release?.();
      await browser.close();
      server.stop();
    }
  },
  20_000,
);

browserTest(
  "any current-token 401 latches both authorities despite late successful reads",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const metadata = {
      id: "p",
      name: "default",
      project: "/project",
      path: "/p",
      revision: "a",
      capabilities: { edit: true, saved_decisions: true },
    };
    try {
      for (const source of ["catalog", "status", "decision", "profile-save"]) {
        const page = await browser.newPage();
        let trigger = false;
        let releaseOther: (() => void) | undefined;
        let otherStarted: (() => void) | undefined;
        const delayed = new Promise<void>((resolve) => {
          releaseOther = resolve;
        });
        const otherInFlight = new Promise<void>((resolve) => {
          otherStarted = resolve;
        });
        try {
          await page.route("**/api/**", async (route) => {
            const request = route.request();
            const path = new URL(request.url()).pathname;
            const old = request.headers().authorization === "Bearer old";
            if (path === "/api/profiles") {
              if (trigger && old && source === "catalog") {
                await otherInFlight;
                return route.fulfill({ status: 401, json: null });
              }
              if (trigger && old && source === "status") {
                otherStarted?.();
                await delayed;
              }
              return route.fulfill({ json: [metadata] });
            }
            if (path === "/api/sessions") {
              if (trigger && old && source === "status") {
                await otherInFlight;
                return route.fulfill({ status: 401, json: null });
              }
              if (trigger && old && source === "catalog") {
                otherStarted?.();
                await delayed;
              }
              return route.fulfill({
                json: [
                  {
                    id: "s",
                    name: "agent",
                    state: "running",
                    project: "/project",
                    profile: { id: "p", name: "default", revision: "a" },
                  },
                ],
              });
            }
            if (path === "/api/profiles/p") {
              if (
                request.method() === "PUT" &&
                old &&
                source === "profile-save"
              )
                return route.fulfill({ status: 401, json: null });
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
            }
            if (path === "/api/files/pending")
              return route.fulfill({
                json: [
                  {
                    id: "f",
                    session_id: "s",
                    session_name: "agent",
                    capability: "read",
                    path: "/file",
                    attempts: 1,
                  },
                ],
              });
            if (path === "/api/files/decisions" && old && source === "decision")
              return route.fulfill({ status: 401, json: null });
            return route.fulfill({ json: [] });
          });
          await page.goto(`${server.url}#token=old`);
          await page.getByLabel("Selected project profile").selectOption("p");
          const field = page
            .getByRole("group", { name: "File rule 1" })
            .getByLabel("Path");
          await field.fill("/draft");
          const save = page.getByRole("button", {
            name: "Save profile",
            exact: true,
          });
          const deny = page.getByRole("button", { name: "Deny for run" });
          expect(await save.isEnabled()).toBe(true);
          expect(await deny.isEnabled()).toBe(true);
          if (source === "catalog") {
            await page
              .getByRole("button", { name: "JSON", exact: true })
              .click();
            await page.getByLabel("Saved profile JSON").fill('{ "version":');
          }
          trigger = true;
          if (source === "decision") await deny.click();
          if (source === "profile-save") await save.click();
          await page
            .getByRole("alert")
            .getByText(/UI token unauthorized \(401\)/)
            .waitFor({ timeout: 6000 });
          expect(await save.isDisabled()).toBe(true);
          expect(await deny.isDisabled()).toBe(true);
          if (source === "catalog")
            expect(
              await page.getByLabel("Saved profile JSON").inputValue(),
            ).toBe('{ "version":');
          else expect(await field.inputValue()).toBe("/draft");
          releaseOther?.();
          await page.waitForTimeout(source === "catalog" ? 2200 : 250);
          expect(await save.isDisabled()).toBe(true);
          expect(await deny.isDisabled()).toBe(true);
          if (source === "catalog")
            expect(
              await page.getByLabel("Saved profile JSON").inputValue(),
            ).toBe('{ "version":');
          else expect(await field.inputValue()).toBe("/draft");
          if (source === "status") {
            page.once("dialog", (dialog) => dialog.accept());
            await page
              .getByLabel("UI access token (not the controller’s master token)")
              .fill("new");
            await page.waitForFunction(() =>
              Array.from(document.querySelectorAll("button")).some(
                (button) =>
                  button.textContent === "Deny for run" && !button.disabled,
              ),
            );
            expect(
              await page.getByLabel("Selected project profile").isEnabled(),
            ).toBe(true);
          }
        } finally {
          releaseOther?.();
          await page.close();
        }
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  25_000,
);

browserTest(
  "token change keeps a live decision blocked until its outcome and a fresh reconciliation",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    try {
      for (const outcome of [
        "applied",
        "unknown",
        "rejected",
        "null",
        "contradictory",
      ]) {
        const page = await browser.newPage();
        let release: (() => void) | undefined;
        const gate = new Promise<void>((resolve) => {
          release = resolve;
        });
        let pending = true;
        let decisionCalls = 0;
        let pendingReads = 0;
        try {
          await page.route("**/api/**", async (route) => {
            const path = new URL(route.request().url()).pathname;
            if (path === "/api/sessions")
              return route.fulfill({
                json: [
                  {
                    id: "s",
                    name: "agent",
                    state: "running",
                    project: "/project",
                  },
                ],
              });
            if (path === "/api/files/pending") {
              pendingReads++;
              return route.fulfill({
                json: pending
                  ? [
                      {
                        id: "f",
                        session_id: "s",
                        session_name: "agent",
                        capability: "read",
                        path: "/file",
                        attempts: 1,
                      },
                    ]
                  : [],
              });
            }
            if (path === "/api/files/decisions") {
              decisionCalls++;
              expect(route.request().headers().authorization).toBe(
                "Bearer old",
              );
              expect(route.request().postDataJSON().action).toBe("allow");
              await gate;
              return outcome === "applied"
                ? route.fulfill({
                    json: { status: "applied; retry the operation" },
                  })
                : outcome === "rejected"
                  ? route.fulfill({ status: 401, json: null })
                  : outcome === "null"
                    ? route.fulfill({ json: null })
                    : outcome === "contradictory"
                      ? route.fulfill({ json: { status: "denied" } })
                      : route.abort("failed");
            }
            return route.fulfill({ json: [] });
          });
          await page.goto(`${server.url}#token=old`);
          const allow = page.getByRole("button", {
            name: "Allow exact path for run",
          });
          const deny = page.getByRole("button", { name: "Deny for run" });
          await allow.waitFor();
          await allow.click();
          await page
            .getByLabel("UI access token (not the controller’s master token)")
            .fill("new");
          await deny.waitFor();
          expect(await deny.isDisabled()).toBe(true);
          const reconcile = page.getByRole("button", {
            name: "Fetch fresh pending requests to reconcile",
          });
          expect(await reconcile.isDisabled()).toBe(true);
          release?.();
          await page
            .getByText(
              outcome === "applied"
                ? /Approved\. The workload must retry/
                : outcome === "rejected"
                  ? /decision was rejected as unauthorized/
                  : /decision outcome is unknown and may have applied/,
            )
            .waitFor();
          expect(await deny.isDisabled()).toBe(true);
          const before = pendingReads;
          await reconcile.click();
          if (outcome === "rejected") {
            await reconcile.waitFor({ state: "detached" });
            expect(await deny.isEnabled()).toBe(true);
            expect(await page.getByRole("alert").textContent()).toBe("");
            await page
              .getByRole("status")
              .getByText(/rejected as unauthorized.*Fresh pending requests/)
              .waitFor();
          } else {
            await page.getByText(/original request is still pending/).waitFor();
            expect(await deny.isDisabled()).toBe(true);
            pending = false;
            await reconcile.click();
            await reconcile.waitFor({ state: "detached" });
            if (["unknown", "null", "contradictory"].includes(outcome))
              await page
                .getByRole("status")
                .getByText(
                  /outcome remains unknown; absence does not prove failure/,
                )
                .waitFor();
            else
              await page
                .getByRole("status")
                .getByText(/Approved.*Fresh pending requests/)
                .waitFor();
          }
          expect(pendingReads).toBeGreaterThan(before);
          expect(decisionCalls).toBe(1);
        } finally {
          release?.();
          await page.close();
        }
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  20_000,
);

browserTest(
  "profile GET and reload 401s invalidate cached catalog and status",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const metadata = {
      id: "p",
      name: "default",
      project: "/project",
      path: "/p",
      revision: "a",
      capabilities: { edit: true, reload: true, saved_decisions: true },
    };
    try {
      for (const source of ["get", "reload"]) {
        const page = await browser.newPage();
        let trigger = false;
        try {
          await page.route("**/api/**", async (route) => {
            const path = new URL(route.request().url()).pathname;
            if (path === "/api/profiles")
              return route.fulfill({ json: [metadata] });
            if (path === "/api/sessions")
              return route.fulfill({
                json: [
                  {
                    id: "s",
                    name: "agent",
                    state: "running",
                    project: "/project",
                    profile: { id: "p", name: "default", revision: "a" },
                  },
                ],
              });
            if (path === "/api/files/pending")
              return route.fulfill({
                json: [
                  {
                    id: "f",
                    session_id: "s",
                    session_name: "agent",
                    capability: "read",
                    path: "/file",
                    attempts: 1,
                  },
                ],
              });
            if (
              (path === "/api/profiles/p" && trigger && source === "get") ||
              (path === "/api/profiles/p/reload" && source === "reload")
            )
              return route.fulfill({ status: 401, json: null });
            if (path === "/api/profiles/p")
              return route.fulfill({
                json: {
                  ...metadata,
                  profile: {
                    version: 1,
                    name: "default",
                    files: [
                      { path: "/file", access: ["read"], recursive: false },
                    ],
                    network: [],
                  },
                },
              });
            return route.fulfill({ json: [] });
          });
          await page.goto(`${server.url}#token=test-token`);
          const select = page.getByLabel("Selected project profile");
          await select.selectOption("p");
          const deny = page.getByRole("button", { name: "Deny for run" });
          expect(await deny.isEnabled()).toBe(true);
          if (source === "get") {
            trigger = true;
            await page
              .getByRole("button", { name: "Load current revision" })
              .click();
          } else {
            await page.getByLabel("Active session").selectOption("s");
            await page
              .getByRole("button", { name: "Reload profile into session" })
              .click();
          }
          await page
            .getByRole("alert")
            .getByText(/UI token unauthorized \(401\)/)
            .waitFor();
          expect(await select.isDisabled()).toBe(true);
          expect(await deny.isDisabled()).toBe(true);
        } finally {
          await page.close();
        }
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  12_000,
);

browserTest(
  "malformed same-token HTTP 200 decision responses stay unknown and blocked",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    try {
      for (const result of [
        null,
        { status: "denied" },
        { status: "applied; retry the operation", applied: false },
      ]) {
        const page = await browser.newPage();
        let decisions = 0;
        try {
          await page.route("**/api/**", async (route) => {
            const path = new URL(route.request().url()).pathname;
            if (path === "/api/sessions")
              return route.fulfill({
                json: [
                  {
                    id: "s",
                    name: "agent",
                    state: "running",
                    project: "/project",
                  },
                ],
              });
            if (path === "/api/files/pending")
              return route.fulfill({
                json: [
                  {
                    id: "f",
                    session_id: "s",
                    session_name: "agent",
                    capability: "read",
                    path: "/file",
                    attempts: 1,
                  },
                ],
              });
            if (path === "/api/files/decisions") {
              decisions++;
              return route.fulfill({ json: result });
            }
            return route.fulfill({ json: [] });
          });
          await page.goto(`${server.url}#token=test-token`);
          const allow = page.getByRole("button", {
            name: "Allow exact path for run",
          });
          const deny = page.getByRole("button", { name: "Deny for run" });
          await allow.click();
          await page
            .getByText(/decision outcome is unknown and may have applied/)
            .waitFor();
          expect(await deny.isDisabled()).toBe(true);
          expect(
            await page.getByText(/Approved\. The workload must retry/).count(),
          ).toBe(0);
          await page
            .getByRole("button", {
              name: "Fetch fresh pending requests to reconcile",
            })
            .click();
          await page.getByText(/original request is still pending/).waitFor();
          expect(await deny.isDisabled()).toBe(true);
          expect(decisions).toBe(1);
        } finally {
          await page.close();
        }
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  12_000,
);

browserTest(
  "401 response headers latch authorization without waiting for stalled bodies",
  async () => {
    const browser = await chromium.launch({ headless: true });
    const metadata = {
      id: "p",
      name: "default",
      project: "/project",
      path: "/p",
      revision: "a",
      capabilities: { edit: true, saved_decisions: true },
    };
    try {
      for (const source of ["catalog", "status", "old-status"]) {
        let trigger = false;
        let started: (() => void) | undefined;
        let release: (() => void) | undefined;
        const oldStarted = new Promise<void>((resolve) => {
          started = resolve;
        });
        const oldGate = new Promise<void>((resolve) => {
          release = resolve;
        });
        const streams: ReadableStreamDefaultController<Uint8Array>[] = [];
        const unauthorized = () =>
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                streams.push(controller);
                controller.enqueue(new TextEncoder().encode("{"));
              },
            }),
            { status: 401, headers: { "content-type": "application/json" } },
          );
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          async fetch(request) {
            const path = new URL(request.url).pathname;
            const old = request.headers.get("authorization") === "Bearer old";
            if (path === "/api/profiles") {
              if (trigger && old && source === "catalog") return unauthorized();
              return Response.json([metadata]);
            }
            if (path === "/api/sessions") {
              if (trigger && old && source === "status") return unauthorized();
              if (trigger && old && source === "old-status") {
                started?.();
                await oldGate;
                return unauthorized();
              }
              return Response.json([
                {
                  id: "s",
                  name: "agent",
                  state: "running",
                  project: "/project",
                  profile: { id: "p", name: "default", revision: "a" },
                },
              ]);
            }
            if (path === "/api/files/pending")
              return Response.json([
                {
                  id: "f",
                  session_id: "s",
                  session_name: "agent",
                  capability: "read",
                  path: "/file",
                  attempts: 1,
                },
              ]);
            if (path === "/api/network/pending") return Response.json([]);
            if (path === "/api/profiles/p")
              return Response.json({
                ...metadata,
                profile: {
                  version: 1,
                  name: "default",
                  files: [
                    { path: "/file", access: ["read"], recursive: false },
                  ],
                  network: [],
                },
              });
            const file = path === "/" ? "index.html" : path.slice(1);
            return ["index.html", "app.js", "app.css"].includes(file)
              ? new Response(Bun.file(`${assets}/${file}`))
              : new Response("not found", { status: 404 });
          },
        });
        const page = await browser.newPage();
        try {
          await page.goto(`${server.url}#token=old`);
          await page.getByLabel("Selected project profile").selectOption("p");
          const deny = page.getByRole("button", { name: "Deny for run" });
          const field = page
            .getByRole("group", { name: "File rule 1" })
            .getByLabel("Path");
          expect(await deny.isEnabled()).toBe(true);
          trigger = true;
          if (source === "old-status") {
            await oldStarted;
            await page
              .getByLabel("UI access token (not the controller’s master token)")
              .fill("new");
            release?.();
            await deny.waitFor();
            await page.waitForTimeout(500);
            expect(streams.length).toBeGreaterThan(0);
            expect(await deny.isEnabled()).toBe(true);
            expect(
              await page.getByLabel("Selected project profile").isEnabled(),
            ).toBe(true);
            expect(await page.getByRole("alert").textContent()).toBe("");
          } else {
            await field.fill("/draft");
            await page
              .getByRole("alert")
              .getByText(/UI token unauthorized \(401\)/)
              .waitFor({ timeout: 6000 });
            expect(streams.length).toBeGreaterThan(0);
            expect(await deny.isDisabled()).toBe(true);
            expect(
              await page
                .getByRole("button", { name: "Save profile", exact: true })
                .isDisabled(),
            ).toBe(true);
            expect(await field.inputValue()).toBe("/draft");
          }
        } finally {
          release?.();
          for (const stream of streams) {
            try {
              stream.close();
            } catch {
              // The browser may already have canceled the response body.
            }
          }
          await page.close();
          server.stop(true);
        }
      }
    } finally {
      await browser.close();
    }
  },
  20_000,
);

browserTest(
  "managed uint64 fields reject malformed status without losing drafts",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const file =
          new URL(request.url).pathname === "/"
            ? "index.html"
            : new URL(request.url).pathname.slice(1);
        return ["index.html", "app.js", "app.css"].includes(file)
          ? new Response(Bun.file(`${assets}/${file}`))
          : new Response("not found", { status: 404 });
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const max = "18446744073709551615";
    const live: Record<string, unknown> = {
      session: "root",
      project: "project",
      profile: "default",
      generation: max,
      sequence: max,
      pending_sequence: max,
      predecessor_sequence: max,
      saved_revision: "revision",
      state: "pending",
      engine_digest: "digest",
      last_confirmed_at: "2025-01-01T00:00:00Z",
    };
    const metadata = {
      id: "profile-id",
      name: "default",
      project: "/project",
      path: "/project/default.json",
      revision: "a".repeat(64),
      capabilities: { edit: true, reload: true, saved_decisions: false },
    };
    let completed = 0;
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/sessions") {
          const snapshot = { ...live };
          await route.fulfill({
            json: [
              {
                id: "session-id",
                name: "agent",
                state: "running",
                project: "/project",
                managed_live: snapshot,
              },
            ],
          });
          completed++;
          return;
        }
        if (path === "/api/profiles")
          return route.fulfill({ json: [metadata] });
        if (path === "/api/profiles/profile-id")
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
        .getByText(
          /Generation: 18446744073709551615.*Sequence: 18446744073709551615.*Pending sequence: 18446744073709551615.*Predecessor sequence: 18446744073709551615/,
        )
        .waitFor();
      await page
        .getByLabel("Selected project profile")
        .selectOption("profile-id");
      const field = page
        .getByRole("group", { name: "File rule 1" })
        .getByLabel("Path");
      await field.fill("/draft-preserved");
      const invalid: unknown[] = [
        "18446744073709551616",
        "-1",
        "+1",
        "01",
        "1.0",
        "not-a-number",
        1,
      ];
      for (const key of [
        "generation",
        "sequence",
        "pending_sequence",
        "predecessor_sequence",
      ]) {
        for (const value of invalid) {
          live[key] = value;
          const previous = completed;
          const deadline = Date.now() + 5000;
          while (completed <= previous && Date.now() < deadline)
            await page.waitForTimeout(20);
          expect(completed).toBeGreaterThan(previous);
          await page.waitForTimeout(50);
          await page
            .getByRole("alert")
            .getByText(/Invalid status response/)
            .waitFor({ timeout: 2000 });
          expect(await field.inputValue()).toBe("/draft-preserved");
        }
        live[key] = max;
      }
    } finally {
      await browser.close();
      server.stop();
    }
  },
  80_000,
);
