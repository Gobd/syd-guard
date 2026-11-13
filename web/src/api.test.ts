import { expect, test } from "bun:test";
import { base, describe, short } from "./api";

test("short paths hide the home directory", () => {
  expect(short("/home/brian.guest/.pi/x")).toBe("~/.pi/x");
  expect(short("/Users/brian/Developer/p")).toBe("~/Developer/p");
  expect(base("/Users/b/Developer/p/.sydguard.json")).toBe("p/.sydguard.json");
});

test("describe reports applied and failed sessions honestly", () => {
  const text = describe({
    saved: "/Users/b/p/.sydguard.json",
    sessions: [
      { session: "abcdef123", applied: true },
      { session: "999999999", applied: false, error: "timed out" },
    ],
  });
  expect(text).toContain("saved to ~/p/.sydguard.json");
  expect(text).toContain("✓ applied live to session abcdef");
  expect(text).toContain("✗ NOT applied to session 999999: timed out");
});
