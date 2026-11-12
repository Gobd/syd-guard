import { expect, test } from "bun:test";
import { chromium } from "@playwright/test";

const browserTest =
  process.env.SYDGUARD_BROWSER_TEST === "1" ? test : test.skip;

browserTest(
  "pending approval identifies the exact active session and safely renders targets",
  async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        const path = new URL(request.url).pathname;
        const file = path === "/" ? "index.html" : path.slice(1);
        if (!["index.html", "app.js", "app.css"].includes(file))
          return new Response("not found", { status: 404 });
        return new Response(
          Bun.file(`${import.meta.dir}/../../internal/webui/assets/${file}`),
        );
      },
    });
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    let active = true;
    let failed = false;
    let decisions = 0;
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        expect(route.request().headers().authorization).toBe(
          "Bearer test-token",
        );
        if (path === "/api/sessions" && failed) {
          await route.fulfill({ status: 502 });
        } else if (path === "/api/sessions") {
          await route.fulfill({
            json: active
              ? [
                  {
                    id: "opaque-a",
                    name: "agent",
                    state: "running",
                    project: "/project-a",
                    command: ["agent-cli"],
                    pid: 123,
                  },
                ]
              : [],
          });
        } else if (path === "/api/files/pending") {
          await route.fulfill({
            json: [
              {
                id: "request-a",
                session_id: "opaque-a",
                session_name: "agent",
                capability: "read",
                path: "<img src=x onerror=alert(1)>",
                attempts: 1,
              },
            ],
          });
        } else if (path === "/api/network/pending") {
          await route.fulfill({ json: [] });
        } else if (path === "/api/files/decisions") {
          decisions++;
          await route.fulfill({ json: { status: "applied" } });
        } else {
          await route.fulfill({ status: 404 });
        }
      });
      await page.goto(`${server.url}#token=test-token`);
      await page.getByText("Session ID: opaque-a", { exact: true }).waitFor();
      expect(await page.getByText("Project: /project-a").count()).toBe(1);
      expect(await page.getByText("<img src=x onerror=alert(1)>").count()).toBe(
        1,
      );
      expect(await page.locator("img").count()).toBe(0);
      expect(
        await page.getByText("Command: agent-cli · PID: 123").count(),
      ).toBe(1);
      expect(
        await page.getByText("Profile: not supplied by launcher").count(),
      ).toBe(1);
      expect(new URL(page.url()).hash).toBe("");
      const allow = page.getByRole("button", {
        name: "Allow exact path for run",
      });
      expect(await allow.isEnabled()).toBe(true);
      failed = true;
      await page
        .getByRole("alert")
        .getByText(/\/api\/sessions.*502/)
        .waitFor({ timeout: 5000 });
      expect(await allow.isDisabled()).toBe(true);
      failed = false;
      active = false;
      await page
        .getByText("Project: Unavailable; refresh before deciding")
        .waitFor({ timeout: 5000 });
      expect(await allow.isDisabled()).toBe(true);
      expect(decisions).toBe(0);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  15_000,
);

browserTest(
  "profile editor loads, validates, preserves conflicts, saves and reloads against a mock contract",
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
    const a = "a".repeat(64),
      b = "b".repeat(64),
      c = "c".repeat(64);
    const id = "opaque:profile";
    const capabilities = { edit: true, reload: true, saved_decisions: true };
    const metadata = {
      id,
      name: "default",
      project: "/project",
      path: "<img src=x onerror=alert(1)>",
      revision: a,
      capabilities,
    };
    let record = {
      ...metadata,
      profile: {
        version: 1,
        name: "default",
        files: [{ path: "/safe", access: ["read"], recursive: false }],
        network: [],
      },
    };
    let sessionRevision = a;
    let conflict = true;
    let sessionActive = true;
    let failedSessions = false;
    let reloadApplied = false;
    let supportsSaved = true;
    const saves: unknown[] = [],
      reloads: unknown[] = [],
      decisions: unknown[] = [];
    try {
      await page.route("**/api/**", async (route) => {
        const req = route.request();
        const path = new URL(req.url()).pathname;
        expect(req.headers().authorization).toBe("Bearer test-token");
        if (path === "/api/sessions") {
          if (failedSessions) return route.fulfill({ status: 502 });
          return route.fulfill({
            json: sessionActive
              ? [
                  {
                    id: "session-1",
                    name: "agent",
                    state: "running",
                    project: "/project",
                    profile: { id, name: "default", revision: sessionRevision },
                  },
                ]
              : [],
          });
        }
        if (path === "/api/files/pending")
          return route.fulfill({
            json: [
              {
                id: "f",
                session_id: "session-1",
                session_name: "agent",
                capability: "read",
                path: "/safe",
                attempts: 1,
              },
            ],
          });
        if (path === "/api/network/pending")
          return route.fulfill({
            json: [
              {
                id: "n",
                session_id: "session-1",
                session_name: "agent",
                target: { host: "example.com", port: 443, transport: "tcp" },
                attempts: 1,
              },
            ],
          });
        if (path === "/api/profiles")
          return route.fulfill({
            json: [
              {
                ...record,
                profile: undefined,
                capabilities: {
                  ...capabilities,
                  saved_decisions: supportsSaved,
                },
              },
            ],
          });
        if (
          path === `/api/profiles/${encodeURIComponent(id)}` &&
          req.method() === "GET"
        )
          return route.fulfill({ json: record });
        if (
          path === `/api/profiles/${encodeURIComponent(id)}` &&
          req.method() === "PUT"
        ) {
          const body = req.postDataJSON();
          saves.push(body);
          if (conflict) {
            record = { ...record, revision: b };
            conflict = false;
            return route.fulfill({
              status: 409,
              json: {
                error: "changed",
                code: "revision_conflict",
                current_revision: b,
              },
            });
          }
          record = { ...record, revision: c, profile: body.profile };
          return route.fulfill({
            json: {
              status: "saved",
              profile: record,
              applied: false,
              retry_required: false,
              restart_required: false,
              message: "Saved; reload or use on next launch",
            },
          });
        }
        if (path === `/api/profiles/${encodeURIComponent(id)}/reload`) {
          reloads.push(req.postDataJSON());
          return route.fulfill({
            json: {
              status: reloadApplied ? "applied" : "restart_required",
              profile: record,
              applied: reloadApplied,
              retry_required: reloadApplied,
              restart_required: !reloadApplied,
              message: reloadApplied ? "Reloaded" : "Restart required",
            },
          });
        }
        if (path.endsWith("/decisions")) {
          decisions.push(req.postDataJSON());
          return route.fulfill({
            json: {
              status: "saved",
              applied: false,
              retry_required: false,
              restart_required: true,
              message: "Saved; restart required",
            },
          });
        }
        return route.fulfill({ status: 404 });
      });
      await page.goto(`${server.url}#token=test-token`);
      await page.getByLabel("Selected project profile").selectOption(id);
      await page.getByText("Profile ID: opaque:profile").waitFor();
      expect(
        await page
          .getByText("Profile path: <img src=x onerror=alert(1)>")
          .count(),
      ).toBe(1);
      expect(await page.locator("img").count()).toBe(0);
      const file = page.getByRole("group", { name: "File rule 1" });
      const save = page.getByRole("button", {
        name: "Save profile",
        exact: true,
      });
      await file.getByLabel("Path").fill("../invalid");
      expect(await save.isDisabled()).toBe(true);
      await file.getByLabel("Path").fill("/edited");
      await page.getByRole("button", { name: "Add network rule" }).click();
      const networkRule = page.getByRole("group", { name: "Network rule 1" });
      await networkRule.getByLabel("Host").fill("*.example.com");
      await networkRule.getByLabel("Port", { exact: true }).fill("70000");
      expect(await save.isDisabled()).toBe(true);
      await networkRule.getByLabel("Host").fill("example.com");
      await networkRule.getByLabel("Port", { exact: true }).fill("443");
      expect(await save.isEnabled()).toBe(true);
      await save.click();
      await page
        .getByText(/Revision conflict. Your edits are preserved/)
        .waitFor();
      expect(await file.getByLabel("Path").inputValue()).toBe("/edited");
      expect(await save.isDisabled()).toBe(true);
      expect(saves).toHaveLength(1);
      expect(
        (saves[0] as { expected_revision: string }).expected_revision,
      ).toBe(a);
      page.once("dialog", (dialog) => dialog.dismiss());
      await page.getByRole("button", { name: "Load current revision" }).click();
      expect(await file.getByLabel("Path").inputValue()).toBe("/edited");
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: "Load current revision" }).click();
      await page.getByText(`Revision: ${b}`, { exact: true }).waitFor();
      await file.getByLabel("Path").fill("/edited-again");
      await save.click();
      await page
        .getByText(/Saved; reload or use on next launch Applied: no/)
        .waitFor();
      expect(
        (saves[1] as { expected_revision: string }).expected_revision,
      ).toBe(b);
      // The active session was at a different revision; it must not be targeted.
      expect(
        await page.getByLabel("Active session").locator("option").count(),
      ).toBe(1);
      sessionRevision = b;
      await page.waitForTimeout(2400);
      await page.getByLabel("Active session").selectOption("session-1");
      await page
        .getByRole("button", { name: "Reload profile into session" })
        .click();
      await page
        .getByText(
          /Restart required Applied: no; retry required: no; restart required: yes/,
        )
        .waitFor();
      expect(reloads).toEqual([
        { session_id: "session-1", expected_revision: c },
      ]);
      reloadApplied = true;
      await page
        .getByRole("button", { name: "Reload profile into session" })
        .click();
      await page
        .getByText(
          /Reloaded Applied: yes; retry required: yes; restart required: no/,
        )
        .waitFor();
      expect(reloads).toHaveLength(2);
      // Matching revision is required for saved decisions, even after successful save.
      expect(
        await page
          .getByRole("button", { name: "Save to profile (unavailable)" })
          .count(),
      ).toBe(2);
      sessionRevision = c;
      supportsSaved = false;
      await page.waitForTimeout(2400);
      expect(
        await page
          .getByRole("button", { name: "Save to profile (unavailable)" })
          .count(),
      ).toBe(2);
      supportsSaved = true;
      await page.waitForTimeout(2400);
      const savedButtons = page.getByRole("button", {
        name: "Save to profile",
        exact: true,
      });
      expect(await savedButtons.count()).toBe(2);
      await savedButtons.nth(0).click();
      await page.getByText(/Saved; restart required Applied: no/).waitFor();
      expect(decisions[0]).toEqual({
        id: "f",
        action: "allow",
        scope: "saved",
        profile_id: id,
        expected_revision: c,
        access: ["read"],
        recursive: false,
      });
      await savedButtons.nth(1).click();
      expect(decisions[1]).toEqual({
        id: "n",
        action: "allow",
        scope: "saved",
        profile_id: id,
        expected_revision: c,
      });
      failedSessions = true;
      await page
        .getByRole("alert")
        .getByText(/\/api\/sessions.*502/)
        .waitFor({ timeout: 5000 });
      expect(
        await page
          .getByRole("button", { name: "Allow exact path for run" })
          .isDisabled(),
      ).toBe(true);
      expect(
        await page
          .getByRole("button", { name: "Save to profile (unavailable)" })
          .count(),
      ).toBe(2);
      failedSessions = false;
      sessionActive = false;
      await page
        .getByText("Project: Unavailable; refresh before deciding")
        .first()
        .waitFor({ timeout: 5000 });
      expect(decisions).toHaveLength(2);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  30000,
);

browserTest(
  "untrusted discovered candidate is visibly read-only",
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
    const candidate = {
      id: "candidate-id",
      name: "default",
      project: "/project",
      path: "/project/.sydguard/default.json",
      revision: "a".repeat(64),
      authority: "untrusted-candidate",
      description: "Discovered candidate; not applied to this session",
      capabilities: { edit: false, reload: false, saved_decisions: false },
    };
    try {
      await page.route("**/api/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/api/profiles")
          return route.fulfill({ json: [candidate] });
        if (path === "/api/profiles/candidate-id")
          return route.fulfill({
            json: {
              ...candidate,
              profile: { version: 1, name: "default", files: [], network: [] },
            },
          });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${server.url}#token=test-token`);
      await page.locator("#profile-select").selectOption("candidate-id");
      await page
        .getByText(/Untrusted candidate.*not applied to this session/)
        .waitFor();
      expect(
        await page.getByRole("button", { name: "Save profile" }).isDisabled(),
      ).toBe(true);
      expect(
        await page
          .getByRole("button", { name: "Reload profile into session" })
          .isDisabled(),
      ).toBe(true);
    } finally {
      await browser.close();
      server.stop();
    }
  },
  15_000,
);
