import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import type { Profile } from "./api";
import {
  parseProfileJSON,
  profileDigest,
  validateProfile,
  validSaveOutcome,
} from "./profileValidation";

const profile: Profile = {
  version: 1,
  name: "default",
  files: [{ path: "/project", access: ["read", "write"], recursive: true }],
  network: [{ host: "example.com", port: 443, transport: "tcp" }],
};
const parse = (value: unknown) =>
  parseProfileJSON(JSON.stringify(value), "default");

describe("saved profile JSON validation", () => {
  test("accepts typed intent and rejects unknown input without throwing", () => {
    expect(parse(profile).profile).toEqual(profile);
    for (const value of [
      null,
      [],
      {},
      { ...profile, files: null },
      { ...profile, files: [null] },
      { ...profile, network: [null] },
      { ...profile, version: "1" },
      { ...profile, name: "other" },
      { ...profile, deny: [] },
      { ...profile, files: [{ ...profile.files[0], syd: "raw" }] },
      { ...profile, network: [{ ...profile.network[0], port: "443" }] },
    ]) {
      expect(parse(value).error).toBeTruthy();
      expect(validateProfile(value, "default")).toBeTruthy();
    }
  });
  test("rejects malformed, duplicate, oversized and excessive rules", () => {
    expect(parseProfileJSON("{", "default").error).toContain("Malformed");
    expect(
      parseProfileJSON(
        '{"version":1,"version":1,"name":"default","files":[],"network":[]}',
        "default",
      ).error,
    ).toContain("Duplicate");
    expect(
      parseProfileJSON(" ".repeat(1024 * 1024 + 1), "default").error,
    ).toContain("1 MiB");
    expect(
      parse({ ...profile, files: Array(4097).fill(profile.files[0]) }).error,
    ).toContain("4096");
  });
  test("rejects lossy numeric tokens while leaving quoted digits untouched", () => {
    const json = JSON.stringify(profile);
    for (const token of ["1.00000000000000001", "1e0", "1.0", "-1", "1e9999"]) {
      expect(
        parseProfileJSON(
          json.replace('"version":1', `"version":${token}`),
          "default",
        ).error,
      ).toBeTruthy();
    }
    for (const token of [
      "443.00000000000000001",
      "443.0",
      "443e0",
      "-443",
      "99999999999999999999999999999999999",
      "NaN",
    ]) {
      expect(
        parseProfileJSON(
          json.replace('"port":443', `"port":${token}`),
          "default",
        ).error,
      ).toBeTruthy();
    }
    expect(
      parse({
        ...profile,
        files: [{ ...profile.files[0], path: "/443.00000000000000001" }],
      }).profile,
    ).toBeTruthy();
  });
  test("rejects unpaired surrogate strings but accepts valid pairs", () => {
    for (const path of ["/\ud800", "/\udc00", "/\ud800x", "/\ud800\ud800"]) {
      expect(
        parse({ ...profile, files: [{ ...profile.files[0], path }] }).error,
      ).toContain("surrogate");
      expect(
        validateProfile(
          { ...profile, files: [{ ...profile.files[0], path }] },
          "default",
        ),
      ).toBeTruthy();
    }
    expect(
      parse({
        ...profile,
        files: [{ ...profile.files[0], path: "/\ud83d\ude00" }],
      }).profile,
    ).toBeTruthy();
    expect(
      parseProfileJSON(
        '{"version":1,"name":"default","files":[],"network":[],"\\ud800":1}',
        "default",
      ).error,
    ).toContain("surrogate");
  });
  test("binds successful acknowledgments to the exact submitted UTF-8 bytes", async () => {
    const submitted = {
      ...profile,
      files: [{ ...profile.files[0], path: "/😀é<&\u2028" }],
    };
    const json = JSON.stringify(submitted);
    const digest = await profileDigest(json);
    expect(digest).toBe(
      createHash("sha256").update(json, "utf8").digest("hex"),
    );
    expect(digest).not.toBe(
      await profileDigest(JSON.stringify(submitted, null, 4)),
    );
    const record = {
      id: "id",
      name: "default",
      project: "/project",
      path: "/profile",
      revision: "a".repeat(64),
      profile,
    };
    const outcome = {
      status: "saved",
      applied: false,
      retry_required: false,
      restart_required: false,
      message: "saved",
      profile: { ...record, revision: digest, profile: submitted },
    };
    expect(validSaveOutcome(outcome, record, submitted, digest)).toBe(true);
    expect(
      validSaveOutcome(
        {
          ...outcome,
          profile: { ...outcome.profile, revision: record.revision },
        },
        record,
        submitted,
        digest,
      ),
    ).toBe(false);
    expect(
      validSaveOutcome(
        {
          ...outcome,
          profile: { ...outcome.profile, revision: "f".repeat(64) },
        },
        record,
        submitted,
        digest,
      ),
    ).toBe(false);
  });
  test("enforces file and network rule types and values", () => {
    for (const rule of [
      { ...profile.files[0], path: "/./" },
      { ...profile.files[0], path: "/a/../b" },
      { ...profile.files[0], access: ["read", "read"] },
      { ...profile.files[0], access: ["deny"] },
      { ...profile.files[0], recursive: "true" },
    ])
      expect(parse({ ...profile, files: [rule] }).error).toBeTruthy();
    for (const rule of [
      { ...profile.network[0], host: "127.0.0.1" },
      { ...profile.network[0], host: "Example.com" },
      { ...profile.network[0], port: 0 },
      { ...profile.network[0], transport: "syd" },
    ])
      expect(parse({ ...profile, network: [rule] }).error).toBeTruthy();
  });
});
