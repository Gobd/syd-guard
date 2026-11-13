import { expect, test } from "bun:test";
import { validUint64 } from "./uint64";

test("canonical uint64 decimal syntax and range", () => {
  for (const value of ["0", "1", "18446744073709551615"])
    expect(validUint64(value)).toBe(true);
  for (const value of [
    "18446744073709551616",
    "-1",
    "+1",
    "00",
    "01",
    "1.0",
    "not-a-number",
    "",
    1,
    null,
  ])
    expect(validUint64(value)).toBe(false);
});
