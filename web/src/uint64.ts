// Compare decimal strings directly to avoid precision loss in JavaScript numbers.
export function validUint64(value: unknown): boolean {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value))
    return false;
  const max = "18446744073709551615";
  return (
    value.length < max.length || (value.length === max.length && value <= max)
  );
}
