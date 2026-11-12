import type { Profile, ProfileOutcome, ProfileRecord } from "./api";

const maxBytes = 1024 * 1024;
const encoder = new TextEncoder();
const bytes = (text: string) => encoder.encode(text).length;
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const fields = (
  value: unknown,
  keys: string[],
): value is Record<string, unknown> =>
  object(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

function wellFormedString(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

// JSON.parse alone loses duplicate keys and numeric token precision.
function checkJSONTokens(text: string): void {
  let pos = 0;
  const whitespace = () => {
    while (/\s/.test(text[pos] ?? "") && pos < text.length) pos++;
  };
  const string = () => {
    const start = pos++;
    while (pos < text.length) {
      if (text[pos] === "\\") pos += 2;
      else if (text[pos++] === '"') {
        const decoded = JSON.parse(text.slice(start, pos)) as string;
        if (!wellFormedString(decoded))
          throw new Error(
            "JSON strings cannot contain unpaired Unicode surrogates.",
          );
        return decoded;
      }
    }
    throw new Error("Malformed JSON.");
  };
  const value = (depth: number): void => {
    if (depth > 64) throw new Error("JSON nesting is too deep.");
    whitespace();
    if (text[pos] === "{") {
      pos++;
      const seen = new Set<string>();
      whitespace();
      while (text[pos] !== "}") {
        const key = string();
        if (seen.has(key)) throw new Error(`Duplicate JSON field: ${key}.`);
        seen.add(key);
        whitespace();
        pos++; // colon (syntax already checked by JSON.parse)
        value(depth + 1);
        whitespace();
        if (text[pos] !== ",") break;
        pos++;
        whitespace();
      }
      pos++;
    } else if (text[pos] === "[") {
      pos++;
      whitespace();
      while (text[pos] !== "]") {
        value(depth + 1);
        whitespace();
        if (text[pos] !== ",") break;
        pos++;
        whitespace();
      }
      pos++;
    } else if (text[pos] === '"') string();
    else {
      const start = pos;
      while (pos < text.length && !/[\s,\]}]/.test(text[pos])) pos++;
      const token = text.slice(start, pos);
      if (
        token !== "true" &&
        token !== "false" &&
        token !== "null" &&
        !/^(?:0|[1-9][0-9]*)$/.test(token)
      )
        throw new Error(
          "Numbers must be unsigned decimal integers without fractions or exponents.",
        );
    }
  };
  value(0);
}

export function validateProfile(
  value: unknown,
  name: string,
): string | undefined {
  if (!fields(value, ["version", "name", "files", "network"]))
    return "Profile must contain only version, name, files and network.";
  if (value.version !== 1) return "Profile version must be 1.";
  if (value.name !== name || !/^[a-zA-Z0-9_-]{1,64}$/.test(name))
    return "Profile name must match the selected profile; JSON cannot rename it.";
  if (!Array.isArray(value.files) || !Array.isArray(value.network))
    return "Files and network must be arrays.";
  if (value.files.length + value.network.length > 4096)
    return "A profile may contain at most 4096 rules.";
  for (const rule of value.files) {
    if (!fields(rule, ["path", "access", "recursive"]))
      return "File rules require only path, access and recursive.";
    if (
      typeof rule.path !== "string" ||
      !rule.path ||
      !wellFormedString(rule.path) ||
      bytes(rule.path) > 4096 ||
      (rule.path.startsWith("/") &&
        rule.path.split("/").every((part) => !part || part === ".")) ||
      [...rule.path].some(
        (ch) =>
          ch.charCodeAt(0) < 32 ||
          (ch.charCodeAt(0) >= 127 && ch.charCodeAt(0) <= 159) ||
          "*?[]{}\\$;!".includes(ch),
      ) ||
      rule.path.split("/").includes("..") ||
      (rule.path.startsWith("~") &&
        rule.path !== "~" &&
        !rule.path.startsWith("~/"))
    )
      return "File rule requires a valid literal path (not the filesystem root).";
    if (
      typeof rule.recursive !== "boolean" ||
      !Array.isArray(rule.access) ||
      !rule.access.length ||
      rule.access.length > 3 ||
      new Set(rule.access).size !== rule.access.length ||
      !rule.access.every(
        (item: unknown) =>
          typeof item === "string" &&
          ["read", "write", "delete"].includes(item),
      )
    )
      return "File rule requires a boolean recursive flag and unique read, write or delete access.";
  }
  for (const rule of value.network) {
    if (!fields(rule, ["host", "port", "transport"]))
      return "Network rules require only host, port and transport.";
    if (
      typeof rule.host !== "string" ||
      rule.host.length > 253 ||
      !rule.host.includes(".") ||
      /^\d+\.\d+\.\d+\.\d+$/.test(rule.host) ||
      !rule.host
        .split(".")
        .every(
          (label) =>
            label.length > 0 &&
            label.length <= 63 &&
            /^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$/.test(label),
        ) ||
      typeof rule.port !== "number" ||
      !Number.isInteger(rule.port) ||
      rule.port < 1 ||
      rule.port > 65535 ||
      (rule.transport !== "tcp" && rule.transport !== "udp")
    )
      return "Network rule requires an exact lowercase host, port 1–65535 and TCP or UDP.";
  }
  if (bytes(JSON.stringify(value)) > maxBytes) return "Profile exceeds 1 MiB.";
  return undefined;
}

// Object-key order is not intent; array order and all typed fields are.
export function sameProfile(a: Profile, b: Profile): boolean {
  const normalized = (profile: Profile) => ({
    version: profile.version,
    name: profile.name,
    files: profile.files.map(({ path, access, recursive }) => ({
      path,
      access,
      recursive,
    })),
    network: profile.network.map(({ host, port, transport }) => ({
      host,
      port,
      transport,
    })),
  });
  return JSON.stringify(normalized(a)) === JSON.stringify(normalized(b));
}

export async function profileDigest(
  serializedProfile: string,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(serializedProfile),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export function validSaveOutcome(
  value: unknown,
  record: ProfileRecord,
  submitted: Profile,
  expectedDigest: string,
): value is ProfileOutcome {
  if (
    !object(value) ||
    value.status !== "saved" ||
    value.applied !== false ||
    typeof value.retry_required !== "boolean" ||
    typeof value.restart_required !== "boolean" ||
    typeof value.message !== "string" ||
    !object(value.profile)
  )
    return false;
  const returned = value.profile;
  if (
    returned.id !== record.id ||
    returned.name !== record.name ||
    returned.project !== record.project ||
    returned.path !== record.path ||
    typeof returned.revision !== "string" ||
    returned.revision !== expectedDigest ||
    validateProfile(returned.profile, record.name)
  )
    return false;
  if (
    (returned.authority !== undefined &&
      typeof returned.authority !== "string") ||
    (returned.description !== undefined &&
      typeof returned.description !== "string")
  )
    return false;
  if (
    returned.capabilities !== undefined &&
    (!object(returned.capabilities) ||
      ["edit", "reload", "saved_decisions"].some(
        (key) =>
          returned.capabilities &&
          (returned.capabilities as Record<string, unknown>)[key] !==
            undefined &&
          typeof (returned.capabilities as Record<string, unknown>)[key] !==
            "boolean",
      ))
  )
    return false;
  return sameProfile(returned.profile as Profile, submitted);
}

export function parseProfileJSON(
  text: string,
  name: string,
): { profile: Profile; error?: never } | { error: string; profile?: never } {
  if (bytes(text) > maxBytes) return { error: "JSON input exceeds 1 MiB." };
  try {
    const value: unknown = JSON.parse(text);
    checkJSONTokens(text);
    const error = validateProfile(value, name);
    if (error) return { error };
    return { profile: value as Profile };
  } catch (error) {
    return {
      error:
        error instanceof SyntaxError
          ? "Malformed JSON. Check the syntax."
          : error instanceof Error
            ? error.message
            : "Malformed JSON.",
    };
  }
}
