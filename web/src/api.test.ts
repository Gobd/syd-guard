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
