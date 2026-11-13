import { useEffect, useState } from "preact/hooks";
import {
  base,
  type Card,
  type CommandCard,
  type Connection,
  decideCommand,
  describe,
  edit,
  type EditRequest,
  type FileView,
  getState,
  type Op,
  type Kind,
  onChange,
  type RuleFile,
  short,
  type State,
  vmAction,
} from "./api";
import * as s from "./styles.css";

const KIND_LABEL: Record<string, string> = {
  read: "read",
  write: "write",
  hosts: "network",
  connect: "connect",
};
const KIND_PILL: Record<string, keyof typeof s.pill> = {
  read: "plain",
  write: "warn",
  hosts: "web",
  connect: "warn",
};

type Act = (op: Op, req: EditRequest) => void;

export function App() {
  const [state, setState] = useState<State | null>(null);
  const [error, setError] = useState("");
  const [toast, setToast] = useState<{ text: string; bad: boolean }>({
    text: "",
    bad: false,
  });

  const refresh = () =>
    getState()
      .then((st) => {
        setState(st);
        setError("");
      })
      .catch((e: Error) => setError(e.message));

  useEffect(() => {
    void refresh();
    const stop = onChange(() => void refresh());
    const poll = setInterval(() => void refresh(), 5000); // fallback if the stream drops
    return () => {
      stop();
      clearInterval(poll);
    };
  }, []);

  const act: Act = (op, req) => {
    edit(op, req)
      .then((res) => setToast({ text: describe(res), bad: false }))
      .catch((e: Error) => setToast({ text: e.message, bad: true }))
      .finally(() => void refresh());
  };

  const cards: [string, Card][] = [];
  const files: [string, FileView][] = [];
  for (const vm of state?.vms ?? []) {
    for (const c of vm.state?.cards ?? []) cards.push([vm.name, c]);
    for (const f of vm.state?.files ?? []) files.push([vm.name, f]);
  }
  const sessionCount =
    state?.vms.reduce((n, v) => n + (v.state?.sessions.length ?? 0), 0) ?? 0;
  // "All projects" rules: owned by this UI's machine, or per VM when it doesn't own them.
  const globals: [string, RuleFile][] = state?.ownsGlobal
    ? state.global
      ? [["", state.global]]
      : []
    : (state?.vms.flatMap((v) =>
        v.state ? [[v.name, v.state.global] as [string, RuleFile]] : [],
      ) ?? []);
  const active = files.filter(([, f]) => f.sessions.length > 0);
  const idle = files.filter(([, f]) => f.sessions.length === 0);
  const pending = cards.filter(([, c]) => !c.learned);
  const learned = cards.filter(([, c]) => c.learned);
  const waiting = pending.length + (state?.commands.length ?? 0);
  document.title = `${waiting ? `(${waiting}) ` : ""}sydguard`;
  const connected = state?.vms.filter((v) => v.ok).map((v) => v.name) ?? [];

  return (
    <>
      <header class={s.header}>
        <h1 class={s.title}>sydguard</h1>
        <span class={s.mute}>
          {error
            ? `disconnected: ${error}`
            : state &&
              `UI ${state.version} · ${connected.length ? `connected: ${connected.join(", ")}` : "no VMs connected"}`}
        </span>
      </header>
      <main class={s.main}>
        <div class={`${s.toast} ${toast.bad ? s.warn : s.ok}`}>
          {toast.text}
        </div>

        <h2 class={s.section}>
          Waiting for you {waiting > 0 && `(${waiting})`}
        </h2>
        {(state?.commands ?? []).map((c) => (
          <CommandView key={c.id} card={c} onDone={refresh} />
        ))}
        {pending.map(([vm, c]) => (
          <CardView key={c.id} vm={vm} card={c} act={act} />
        ))}
        {waiting === 0 && (
          <div class={s.empty}>
            {sessionCount > 0
              ? "Nothing blocked right now."
              : "No agents running. Start one with: sydguard -- claude (or --learn for a first run)."}
          </div>
        )}

        {learned.length > 0 && (
          <>
            <h2 class={s.section}>
              Learning now{" "}
              <span class={s.mute}>
                (saved to the rules file when the learn run exits)
              </span>
            </h2>
            {learned.map(([vm, c]) => (
              <CardView key={c.id} vm={vm} card={c} act={act} />
            ))}
          </>
        )}

        {sessionCount > 0 && (
          <>
            <h2 class={s.section}>Running agents</h2>
            <Sessions state={state} act={act} />
          </>
        )}

        <h2 class={s.section}>Rules</h2>
        {active.map(([vm, f]) => (
          <RulesView
            key={vm + f.path}
            title={projectTitle(f)}
            where={vm}
            vm={vm}
            scope="rules"
            file={f}
            act={act}
            running={f.sessions.length}
          />
        ))}
        {globals.map(([vm, f]) =>
          hasRules(f) ? (
            <RulesView
              key={`global-${vm}`}
              title="All projects"
              vm={vm}
              scope="global"
              file={f}
              act={act}
            />
          ) : (
            <details key={`global-${vm}`}>
              <summary class={s.summary}>All projects (no rules yet)</summary>
              <RulesView
                title="All projects"
                vm={vm}
                scope="global"
                file={f}
                act={act}
              />
            </details>
          ),
        )}
        {idle.length > 0 && (
          <details>
            <summary class={s.summary}>Other projects ({idle.length})</summary>
            {idle.map(([vm, f]) => (
              <RulesView
                key={vm + f.path}
                title={projectTitle(f)}
                where={vm}
                vm={vm}
                scope="rules"
                file={f}
                act={act}
                forget
              />
            ))}
          </details>
        )}

        <h2 class={s.section}>Machines</h2>
        <Machines state={state} onDone={() => void refresh()} />
      </main>
    </>
  );
}

const hasRules = (f: RuleFile) =>
  Object.values(f.rules ?? {}).some((v) =>
    Array.isArray(v) ? v.length > 0 : !!v,
  );

// "myproject" or "myproject · review" for --rules review.
function projectTitle(f: FileView): string {
  const name = short(f.project).split("/").pop() || short(f.path);
  const file = f.path.split("/").pop() ?? "";
  return file === ".sydguard.json"
    ? name
    : `${name} · ${file.replace(/\.json$/, "")}`;
}

function Machines({
  state,
  onDone,
}: {
  state: State | null;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const run = (name: string, action: "start" | "stop") => {
    setBusy(name);
    setError("");
    vmAction(name, action)
      .catch((e: Error) => setError(e.message))
      .finally(() => {
        setBusy("");
        onDone();
      });
  };
  const machines = state?.machines ?? [];
  if (machines.length === 0)
    return <div class={s.empty}>No machines found.</div>;
  return (
    <>
      {error && <div class={s.warn}>{error}</div>}
      {machines.map((m) => (
        <div key={m.name} class={`${s.card} ${s.row}`}>
          <span class={s.pill[m.status === "Running" ? "ok" : "plain"]}>
            {m.status.toLowerCase()}
          </span>
          <strong>{m.name}</strong>
          <span class={s.mute}>
            {m.kind === "lima" ? "Lima VM" : "this machine"}
            {m.status === "Running" &&
              ` · ${m.agents} agent${m.agents === 1 ? "" : "s"} running`}
          </span>
          {m.kind === "lima" && (
            <button
              type="button"
              disabled={
                busy === m.name || (m.status === "Running" && m.agents > 0)
              }
              title={m.agents > 0 ? "stop its agents first" : ""}
              onClick={() =>
                run(m.name, m.status === "Running" ? "stop" : "start")
              }
            >
              {busy === m.name
                ? "…"
                : m.status === "Running"
                  ? "Stop VM"
                  : "Start VM"}
            </button>
          )}
        </div>
      ))}
    </>
  );
}

// A host command the agent asked to run (or proposed).
function CommandView({
  card: c,
  onDone,
}: {
  card: CommandCard;
  onDone: () => void;
}) {
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState(
    c.argv
      .slice(0, 2)
      .join("-")
      .replace(/[^a-z0-9_-]/gi, "")
      .toLowerCase(),
  );
  const [template, setTemplate] = useState(c.argv.join(" "));
  const [scope, setScope] = useState<"project" | "global">("project");
  const [mode, setMode] = useState<"ask" | "allow">("ask");
  const [regexes, setRegexes] = useState<Record<string, string>>({});
  const placeholders = [...template.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map(
    (m) => m[1] ?? "",
  );
  const send = (action: "run" | "deny" | "save") => {
    setError("");
    const args: Record<string, string> = {};
    for (const p of placeholders) args[p] = regexes[p] ?? "[A-Za-z0-9._/-]+";
    decideCommand({
      id: c.id,
      action,
      ...(action === "save"
        ? {
            scope,
            name,
            run: template.split(" ").filter(Boolean),
            args,
            mode,
            stdin: !!c.stdin,
          }
        : {}),
    })
      .then(onDone)
      .catch((e: Error) => setError(e.message));
  };
  return (
    <div class={s.card}>
      <div class={s.row}>
        <span class={s.pill.warn}>
          {c.kind === "run" ? "command" : "new command?"}
        </span>
        <span class={s.target}>{c.argv.join(" ")}</span>
      </div>
      <div class={s.mute}>
        {c.vm} › {short(c.project)}
        {c.kind === "run" &&
          ` · ${c.name} (${c.scope === "global" ? "all projects" : "this project"})`}
        {c.agent && ` · ${c.agent}`} · runs on this machine with your
        credentials (git hooks off)
      </div>
      {c.reason && <div class={s.mute}>why: {c.reason}</div>}
      {c.note && <div class={s.warn}>{c.note}</div>}
      {c.stdin && <pre class={s.pre}>{c.stdin}</pre>}
      {error && <div class={s.warn}>{error}</div>}
      <div class={s.row}>
        <button type="button" class={s.primary} onClick={() => send("run")}>
          {c.kind === "run" ? "Run" : "Run once"}
        </button>
        {c.kind === "propose" && (
          <button type="button" onClick={() => setSaving(!saving)}>
            Save as command…
          </button>
        )}
        <button type="button" onClick={() => send("deny")}>
          Deny
        </button>
      </div>
      {saving && (
        <div class={s.card}>
          <div class={s.mute}>
            Replace words with {"{placeholders}"} the agent may fill in, each
            checked against a regex.
          </div>
          <div class={s.row}>
            <input
              value={name}
              onInput={(e) => setName(e.currentTarget.value)}
              placeholder="name"
            />
            <Toggle
              value={scope}
              onChange={setScope}
              options={[
                ["project", "This project"],
                ["global", "All projects"],
              ]}
            />
            <Toggle
              value={mode}
              onChange={setMode}
              options={[
                ["ask", "Ask each time"],
                ["allow", "Always allow"],
              ]}
            />
          </div>
          <div class={s.row}>
            <input
              class={s.grow}
              value={template}
              onInput={(e) => setTemplate(e.currentTarget.value)}
            />
          </div>
          {placeholders.map((p) => (
            <div key={p} class={s.row}>
              <span class={s.target}>{`{${p}}`} must match</span>
              <input
                class={s.grow}
                value={regexes[p] ?? "[A-Za-z0-9._/-]+"}
                onInput={(e) =>
                  setRegexes({ ...regexes, [p]: e.currentTarget.value })
                }
              />
            </div>
          ))}
          <button type="button" class={s.primary} onClick={() => send("save")}>
            Save and run
          </button>
        </div>
      )}
    </div>
  );
}

// A row of buttons, one selected (instead of a dropdown).
function Toggle<T extends string>(props: {
  value: T;
  onChange: (v: T) => void;
  options: [T, string][];
  title?: string;
}) {
  return (
    <span class={s.segment} title={props.title}>
      {props.options.map(([v, label]) => (
        <button
          type="button"
          key={v}
          class={v === props.value ? s.segmentOn : s.segmentBtn}
          onClick={() => props.onChange(v)}
        >
          {label}
        </button>
      ))}
    </span>
  );
}

function CardView({ vm, card: c, act }: { vm: string; card: Card; act: Act }) {
  const [pattern, setPattern] = useState(c.options[0] ?? "");
  const [kind, setKind] = useState<Kind>(c.kind);
  const [scope, setScope] = useState<"rules" | "global">("rules");
  const req = { vm, card: c.id, scope, file: c.rulesFile };
  const denyPattern =
    c.kind === "hosts"
      ? c.target.replace(/^[a-z]+:\/\//, "").replace(/:\d+$/, "")
      : pattern;
  return (
    <div class={s.card}>
      <div class={s.row}>
        <span class={s.pill[KIND_PILL[c.kind] ?? "plain"]}>
          {KIND_LABEL[c.kind] ?? c.kind}
        </span>
        <span class={s.target}>{short(c.target)}</span>
        {c.count > 1 && <span class={s.mute}>×{c.count}</span>}
        {c.waiting > 0 && (
          <span class={s.warn}>
            ⏸ {c.waiting} request{c.waiting > 1 ? "s" : ""} paused
          </span>
        )}
      </div>
      <div class={s.mute}>
        {vm} › {short(c.project)} › {base(c.rulesFile)}
        {c.cmd && ` · ${c.cmd}`}
      </div>
      {c.note && <div class={s.mute}>{c.note}</div>}
      <div class={s.opts}>
        {c.options.map((o) => (
          <button
            type="button"
            key={o}
            class={o === pattern ? s.optSelected : s.opt}
            onClick={() => setPattern(o)}
          >
            {short(o)}
          </button>
        ))}
      </div>
      <div class={s.row}>
        <input
          class={s.grow}
          value={pattern}
          onInput={(e) => setPattern(e.currentTarget.value)}
        />
        {(c.kind === "read" || c.kind === "write") && (
          <Toggle
            value={kind}
            onChange={setKind}
            options={[
              ["read", "Read"],
              ["write", "Read + write"],
            ]}
          />
        )}
        <Toggle
          value={scope}
          onChange={setScope}
          options={[
            ["rules", "This project"],
            ["global", "All projects"],
          ]}
          title={`this project = ${base(c.rulesFile)}`}
        />
        <button
          type="button"
          class={s.primary}
          onClick={() => act("allow", { ...req, kind, pattern })}
        >
          Allow
        </button>
        <button
          type="button"
          onClick={() => act("dismiss", { vm, scope: "rules", card: c.id })}
        >
          {c.learned ? "Skip" : "Deny"}
        </button>
        <button
          type="button"
          class={s.link}
          title="deny and never ask again"
          onClick={() =>
            act("allow", { ...req, kind: "ignore", pattern: denyPattern })
          }
        >
          deny always
        </button>
      </div>
    </div>
  );
}

function Sessions({ state, act }: { state: State | null; act: Act }) {
  const rows =
    state?.vms.flatMap((vm) =>
      (vm.state?.sessions ?? []).map((x) => [vm.name, x] as const),
    ) ?? [];
  const down = state?.vms.filter((v) => !v.ok) ?? [];
  return (
    <>
      {down.map((v) => (
        <div key={v.name} class={`${s.card} ${s.warn}`}>
          {v.name}: {v.error || "not connected"}
        </div>
      ))}
      {state?.vms.some((v) => v.state && !v.state.namespaces) && (
        <div class={`${s.card} ${s.warn}`}>
          Private DNS and build-folder overlays are off in some VMs (run
          `sydguard setup`).
        </div>
      )}
      {rows.length === 0 && <div class={s.empty}>No agents running.</div>}
      {rows.map(([vm, x]) => (
        <div key={x.id} class={s.card}>
          <div class={s.row}>
            <span
              class={
                s.pill[
                  x.learn
                    ? "warn"
                    : x.status === "applied"
                      ? "ok"
                      : x.status === "unknown"
                        ? "warn"
                        : "plain"
                ]
              }
            >
              {x.learn ? "learning" : x.status}
            </span>
            <span class={s.target}>{x.cmd.join(" ")}</span>
            <span class={s.mute}>
              {vm} › {short(x.cwd)} · rules {base(x.rulesFile)} · pid {x.pid} ·
              since {new Date(x.started).toLocaleTimeString()}
              {x.overlays?.length
                ? ` · VM-local: ${x.overlays.join(", ")}`
                : ""}
            </span>
          </div>
          {(x.ports ?? []).length > 0 && (
            <div class={s.row}>
              <span class={s.mute}>dev servers:</span>
              {(x.ports ?? []).map((p) =>
                p.exposed ? (
                  <a
                    key={p.port}
                    class={s.target}
                    href={`http://localhost:${p.port}/`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    localhost:{p.port}
                  </a>
                ) : (
                  <span key={p.port} class={s.warn} title={p.error}>
                    {p.port} (not exposed: {p.error})
                  </span>
                ),
              )}
            </div>
          )}
          <details open>
            <summary class={s.summary}>
              Approvals for this session’s rules
            </summary>
            <div class={s.mute}>
              Grants are saved to {base(x.rulesFile)} and shared by sessions
              using that file.
            </div>
            {(state?.vms.find((v) => v.name === vm)?.state?.cards ?? [])
              .filter((c) => c.rulesFile === x.rulesFile && !c.learned)
              .map((c) => (
                <CardView key={c.id} vm={vm} card={c} act={act} />
              ))}
          </details>
          {x.landlock?.enabled && (
            <details>
              <summary class={s.summary}>
                Landlock: fixed filesystem ceiling
              </summary>
              <div class={s.mute}>
                Live approvals work only inside these roots. A wider ceiling
                requires a new session. These are maximums, not Syd grants;
                write includes read and read includes execute.
              </div>
              <div>Read: {(x.landlock.read ?? []).join(", ")}</div>
              <div>Read + write: {(x.landlock.write ?? []).join(", ")}</div>
            </details>
          )}
          {x.network && <Connections connections={x.connections ?? []} />}
          {(x.outsideCeiling ?? []).length > 0 && (
            <div class={s.warn}>
              Saved, but outside this session's Landlock ceiling (they apply to
              new sessions with a wider ceiling):{" "}
              {(x.outsideCeiling ?? []).map(short).join(", ")}
            </div>
          )}
          {x.lastError && (
            <div class={s.warn}>
              last update failed: {x.lastError} — policy state unknown; restart
              this agent
            </div>
          )}
        </div>
      ))}
    </>
  );
}

function Connections({ connections }: { connections: Connection[] }) {
  const [filter, setFilter] = useState<"all" | "active">("all");
  const [search, setSearch] = useState("");
  const rows = connections.filter(
    (c) =>
      (filter === "all" || !c.ended) &&
      [
        c.hostname,
        c.httpHost,
        c.sni,
        c.destination,
        c.protocol,
        c.scheme,
        c.port,
      ].some((v) => v?.toLowerCase().includes(search.toLowerCase())),
  );
  const active = connections.filter((c) => !c.ended).length;
  return (
    <details>
      <summary class={s.summary}>
        Connections ({active} active · {connections.length} recent)
      </summary>
      <div class={s.row}>
        <Toggle
          value={filter}
          onChange={setFilter}
          options={[
            ["all", "Recent"],
            ["active", "Active"],
          ]}
        />
        <input
          class={s.grow}
          placeholder="Filter hostname, IP, protocol…"
          value={search}
          onInput={(e) => setSearch(e.currentTarget.value)}
        />
      </div>
      <div class={s.mute}>
        Latest 256 flows per session · metadata only, no decrypted HTTPS ·
        history resets on daemon restart.
      </div>
      {rows.length === 0 && <div class={s.empty}>No matching connections.</div>}
      {rows.map((c) => (
        <div key={c.id} class={s.card}>
          <div class={s.row}>
            <span class={s.pill[c.error ? "warn" : c.ended ? "plain" : "ok"]}>
              {c.scheme || c.protocol} · port {c.port} · {c.state}
            </span>
            <span class={s.target}>{c.hostname || c.destination}</span>
            <span class={s.mute}>
              {c.destination} · ↑ {c.sent.toLocaleString()} B · ↓{" "}
              {c.received.toLocaleString()} B ·{" "}
              {new Date(c.started).toLocaleTimeString()}
            </span>
          </div>
          {(c.httpHost || c.sni) && (
            <div class={s.mute}>
              {c.httpHost && `HTTP Host: ${c.httpHost}`}
              {c.httpHost && c.sni && " · "}
              {c.sni && `TLS SNI: ${c.sni}`}
            </div>
          )}
          {c.error && <div class={s.warn}>{c.error}</div>}
        </div>
      ))}
    </details>
  );
}

const BLOCKS: [Kind, string, string][] = [
  ["read", "Read", "~/.cache/go-build/**"],
  ["write", "Read + write", "~/.npm/**"],
  [
    "hosts",
    "Network & DNS (by host name)",
    "https://github.com, tcp://db:5432, udp://service:9000",
  ],
  ["connect", "Raw connect (advanced)", "1.2.3.4!22"],
  ["ignore", "Always deny", "host or path"],
];

function RulesView(props: {
  title: string;
  where?: string;
  forget?: boolean;
  vm: string;
  scope: "rules" | "global";
  file: RuleFile | FileView;
  act: Act;
  running?: number;
}) {
  const { title, where, forget, vm, scope, file: f, act, running } = props;
  const baseline = "baseline" in f ? f.baseline : undefined;
  return (
    <div class={s.card}>
      <div class={s.row}>
        <strong>{title}</strong>
        {running ? <span class={s.pill.ok}>{running} running</span> : null}
        <span class={s.mute}>
          {where ? `${where} · ` : ""}
          {short(f.path)}
        </span>
        {forget && (
          <button
            type="button"
            class={s.link}
            title="remove from this list (the file stays)"
            onClick={() => act("forget", { vm, scope, file: f.path })}
          >
            forget
          </button>
        )}
      </div>
      {f.error && (
        <div class={s.warn}>⚠ {f.error} — using the last trusted rules</div>
      )}
      {f.pending && (
        <div>
          <div class={s.warn}>
            ⚠ changed outside sydguard — not in use until you trust it:
          </div>
          <pre class={s.pre}>{f.pending}</pre>
          <button
            type="button"
            onClick={() => act("trust", { vm, scope, file: f.path })}
          >
            Trust these rules
          </button>
        </div>
      )}
      <div class={s.rulesGrid}>
        {BLOCKS.map(([kind, label, placeholder]) => (
          <RuleBlock
            key={kind}
            {...{ kind, label, placeholder, vm, scope, act }}
            file={f}
          />
        ))}
      </div>
      {baseline && (
        <details>
          <summary class={s.summary}>always allowed (built in)</summary>
          <ul class={`${s.ruleList} ${s.mute}`}>
            {baseline.map((b) => (
              <li key={b.kind + b.pattern}>
                {b.kind} {short(b.pattern)} — {b.why}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function RuleBlock(props: {
  kind: Kind;
  label: string;
  placeholder: string;
  vm: string;
  scope: "rules" | "global";
  file: RuleFile;
  act: Act;
}) {
  const { kind, label, placeholder, vm, scope, file, act } = props;
  const [value, setValue] = useState("");
  const add = () => {
    if (!value) return;
    act("allow", { vm, scope, file: file.path, kind, pattern: value });
    setValue("");
  };
  return (
    <div>
      <h4 class={s.ruleHead}>{label}</h4>
      <ul class={s.ruleList}>
        {(file.rules[kind] ?? []).map((p) => (
          <li key={p} class={s.ruleItem}>
            <span>{short(p)}</span>
            <button
              type="button"
              class={s.link}
              title="remove"
              onClick={() =>
                act("remove", { vm, scope, file: file.path, kind, pattern: p })
              }
            >
              ✕
            </button>
          </li>
        ))}
      </ul>
      <div class={s.addRow}>
        <input
          class={s.addInput}
          placeholder={placeholder}
          value={value}
          onInput={(e) => setValue(e.currentTarget.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button type="button" onClick={add}>
          +
        </button>
      </div>
    </div>
  );
}
