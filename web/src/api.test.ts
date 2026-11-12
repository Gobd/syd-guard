import { expect, test } from "bun:test";
import { networkLabel, requestSession } from "./api";
test("approval identity includes hostname, actual port and transport", () => {
  expect(
    networkLabel({
      id: "x",
      session_id: "s",
      session_name: "work",
      target: { host: "api.example.com", port: 8443, transport: "tcp" },
      attempts: 1,
    }),
  ).toBe("api.example.com:8443 / TCP");
});

test("request identity requires an active exact session ID and name", () => {
  const sessions = [
    { id: "opaque-a", name: "agent", state: "running", project: "/project-a" },
  ];
  expect(
    requestSession(sessions, { session_id: "opaque-a", session_name: "agent" })
      ?.project,
  ).toBe("/project-a");
  expect(
    requestSession(sessions, { session_id: "opaque-b", session_name: "agent" }),
  ).toBeUndefined();
  expect(
    requestSession(sessions, { session_id: "opaque-a", session_name: "other" }),
  ).toBeUndefined();
  expect(
    requestSession([{ ...sessions[0], state: "exited" }], {
      session_id: "opaque-a",
      session_name: "agent",
    }),
  ).toBeUndefined();
});

test("saved decisions require exact active profile identity, project and revision", async () => {
  const { matchingProfile, fileAccess } = await import("./api");
  const revision = "a".repeat(64);
  const profile = {
    id: "opaque",
    name: "default",
    project: "/p",
    path: "/p/profile",
    revision,
  };
  const session = {
    id: "session",
    name: "agent",
    state: "running",
    project: "/p",
    profile: { id: "opaque", name: "default", revision },
  };
  expect(matchingProfile(session, [profile])).toEqual(profile);
  expect(
    matchingProfile(
      { ...session, profile: { ...session.profile, revision: "b".repeat(64) } },
      [profile],
    ),
  ).toBeUndefined();
  expect(
    matchingProfile(
      { ...session, profile: { ...session.profile, name: "other" } },
      [profile],
    ),
  ).toBeUndefined();
  expect(
    matchingProfile({ ...session, project: "/other" }, [profile]),
  ).toBeUndefined();
  expect(fileAccess("stat")).toBe("read");
  expect(fileAccess("create")).toBe("write");
  expect(fileAccess("rename")).toBe("delete");
  expect(fileAccess("exec")).toBeUndefined();
});

test("HTTP 401 ignores null or stalled bodies and immediately reports authorization failure", async () => {
  const { api, ApiError } = await import("./api");
  const original = globalThis.fetch;
  try {
    for (const body of ["null", new ReadableStream({ start() {} })]) {
      globalThis.fetch = (async () =>
        new Response(body, { status: 401 })) as unknown as typeof fetch;
      const result = await Promise.race([
        api("token", "/api/profiles").then(
          () => "success",
          (error: unknown) => error,
        ),
        new Promise<string>((resolve) =>
          setTimeout(() => resolve("timed out"), 250),
        ),
      ]);
      expect(result).toBeInstanceOf(ApiError);
      expect((result as InstanceType<typeof ApiError>).status).toBe(401);
    }
  } finally {
    globalThis.fetch = original;
  }
});

test("non-401 errors preserve status and typed details for any JSON shape", async () => {
  const { api, ApiError } = await import("./api");
  const original = globalThis.fetch;
  try {
    const cases: [string, string, string | undefined, string | undefined][] = [
      [
        "null",
        "Request to /api/profiles/p failed (503). Refresh if the session or request has ended.",
        undefined,
        undefined,
      ],
      [
        "[]",
        "Request to /api/profiles/p failed (503). Refresh if the session or request has ended.",
        undefined,
        undefined,
      ],
      [
        "{",
        "Request to /api/profiles/p failed (503). Refresh if the session or request has ended.",
        undefined,
        undefined,
      ],
      [
        JSON.stringify({
          error: "uncertain",
          code: "indeterminate",
          current_revision: "abc",
        }),
        "uncertain",
        "indeterminate",
        "abc",
      ],
      [
        JSON.stringify({ error: null, code: 3, current_revision: [] }),
        "Request to /api/profiles/p failed (503). Refresh if the session or request has ended.",
        undefined,
        undefined,
      ],
    ];
    for (const [body, message, code, revision] of cases) {
      globalThis.fetch = (async () =>
        new Response(body, { status: 503 })) as unknown as typeof fetch;
      try {
        await api("token", "/api/profiles/p", {}, "PUT");
        throw new Error("expected failure");
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as InstanceType<typeof ApiError>).status).toBe(503);
        expect((error as Error).message).toBe(message);
        expect((error as InstanceType<typeof ApiError>).code).toBe(code);
        expect((error as InstanceType<typeof ApiError>).currentRevision).toBe(
          revision,
        );
      }
    }
  } finally {
    globalThis.fetch = original;
  }
});

test("decision responses must match the endpoint and outcome contract", async () => {
  const { validDecisionOutcome } = await import("./api");
  const saved = {
    status: "saved",
    message: "saved",
    applied: false,
    retry_required: false,
    restart_required: true,
  };
  const cases: [unknown, "files" | "network", "run" | "saved", boolean][] = [
    [{ status: "applied; retry the operation" }, "files", "run", true],
    [{ status: "applied; retry the request" }, "network", "run", true],
    [null, "files", "run", false],
    [[], "files", "run", false],
    [{}, "files", "run", false],
    [{ status: "applied" }, "files", "run", false],
    [{ status: "denied" }, "files", "run", false],
    [{ status: "applied; retry the request" }, "files", "run", false],
    [
      { status: "applied; retry the operation", applied: false },
      "files",
      "run",
      false,
    ],
    [saved, "files", "saved", true],
    [
      { ...saved, status: "applied", applied: true, restart_required: false },
      "network",
      "saved",
      true,
    ],
    [{ ...saved, status: "restart_required" }, "files", "saved", true],
    [{ ...saved, status: "applied" }, "files", "saved", false],
    [
      { ...saved, status: "restart_required", restart_required: false },
      "files",
      "saved",
      false,
    ],
    [{ ...saved, applied: true }, "files", "saved", false],
    [{ ...saved, retry_required: "unknown" }, "files", "saved", false],
    [null, "network", "saved", false],
  ];
  for (const [value, kind, scope, expected] of cases)
    expect(validDecisionOutcome(value, kind, scope)).toBe(expected);
});
