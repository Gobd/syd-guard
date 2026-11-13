// API client for the sydguard UI server.

export type Kind = "read" | "write" | "hosts" | "connect" | "ignore";

export interface Card {
  id: string;
  session: string;
  project: string;
  rulesFile: string;
  kind: Kind;
  target: string;
  cmd: string;
  count: number;
  learned: boolean;
  waiting: number;
  options: string[];
  note?: string;
  overlayPath?: string;
}

export interface Connection {
  id: string;
  protocol: string;
  scheme?: string;
  port: string;
  destination: string;
  hostname?: string;
  httpHost?: string;
  sni?: string;
  state: string;
  error?: string;
  started: string;
  ended?: string;
  sent: number;
  received: number;
}

export interface Session {
  id: string;
  project: string;
  rulesFile: string;
  cwd: string;
  cmd: string[];
  learn: boolean;
  pid: number;
  started: string;
  status: "applied" | "updating" | "unknown";
  landlock?: { enabled: boolean; read?: string[]; write?: string[] };
  outsideCeiling?: string[];
  lastError?: string;
  dnsAddr?: string;
  overlays?: string[];
  dynamicOverlays?: string[];
  overlayGuarded?: boolean;
  overlayReadOnly?: string[];
  ports?: { port: number; exposed: boolean; error?: string }[];
  network?: boolean;
  connections?: Connection[];
}

export type Rules = Partial<Record<Kind, string[]>>;

export interface RuleFile {
  path: string;
  rules: Rules;
  pending?: string;
  error?: string;
}

export interface FileView extends RuleFile {
  project: string;
  baseline?: { kind: string; pattern: string; why: string }[];
  sessions: string[];
}

export interface VMState {
  sessions: Session[];
  cards: Card[];
  files: FileView[];
  global: RuleFile;
  namespaces: boolean;
}

export interface VM {
  name: string;
  ok: boolean;
  error?: string;
  state?: VMState;
}

export interface Machine {
  name: string;
  kind: "lima" | "local";
  status: string;
  agents: number;
  version?: string;
}

export interface CommandCard {
  id: string;
  vm: string;
  project: string;
  rulesFile: string;
  agent: string;
  kind: "run" | "propose";
  name?: string;
  scope?: string;
  argv: string[];
  stdin?: string;
  reason?: string;
  note?: string;
}

export interface CommandDecision {
  id: string;
  action: "run" | "deny" | "save";
  scope?: "global" | "project";
  name?: string;
  run?: string[];
  args?: Record<string, string>;
  mode?: "allow" | "ask";
  stdin?: boolean;
  description?: string;
}

export interface State {
  version: string;
  vms: VM[];
  machines: Machine[];
  commands: CommandCard[];
  ownsGlobal: boolean;
  global?: RuleFile;
}

export interface EditRequest {
  vm: string;
  card?: string;
  scope: "rules" | "global";
  file?: string;
  session?: string;
  path?: string;
  kind?: Kind;
  pattern?: string;
}

interface ApplyResult {
  session: string;
  applied: boolean;
  error?: string;
  note?: string;
}

export interface EditResult {
  saved?: string;
  sessions?: ApplyResult[];
  vms?: Record<string, { sessions?: ApplyResult[]; error?: string }>;
  note?: string;
}

async function call<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(j?.error ?? r.statusText);
  return j as T;
}

export const getState = () => call<State>("/api/state");
export type Op =
  "allow" | "remove" | "dismiss" | "trust" | "forget" | "overlay";
export const edit = (op: Op, req: EditRequest) =>
  call<EditResult>(`/api/${op}`, req);
export const decideCommand = (d: CommandDecision) =>
  call<object>("/api/command", d);
export const vmAction = (name: string, action: "start" | "stop") =>
  call<object>("/api/vm", { name, action });

// Subscribe to "something changed" events; returns an unsubscribe function.
export function onChange(fn: () => void): () => void {
  const es = new EventSource("/api/events");
  es.onmessage = fn;
  return () => es.close();
}

// Plain-language summary of what an edit actually did.
export function describe(res: EditResult): string {
  const lines: string[] = [];
  if (res.saved) lines.push(`saved to ${short(res.saved)}`);
  const add = (list: ApplyResult[] | undefined, vm = "") =>
    list?.forEach((s) =>
      lines.push(
        s.applied
          ? `✓ applied live to ${vm}session ${s.session.slice(0, 6)}${s.note ? ` (${s.note})` : ""}`
          : `✗ NOT applied to ${vm}session ${s.session.slice(0, 6)}: ${s.error}`,
      ),
    );
  add(res.sessions);
  for (const [vm, r] of Object.entries(res.vms ?? {})) {
    if (r.error) lines.push(`✗ ${vm}: ${r.error}`);
    else add(r.sessions, `${vm} `);
  }
  if (res.note) lines.push(`note: ${res.note}`);
  return lines.join("\n");
}

export const short = (p = "") => p.replace(/^\/(home|Users)\/[^/]+/, "~");
export const base = (p = "") => short(p).split("/").slice(-2).join("/");
