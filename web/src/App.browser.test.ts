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
