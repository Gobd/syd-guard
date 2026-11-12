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
