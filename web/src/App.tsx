import { useEffect, useState } from "preact/hooks";
import {
  base,
  type Card,
  describe,
  edit,
  type EditRequest,
  type FileView,
  getState,
  type Kind,
  onChange,
  type RuleFile,
  short,
  type State,
} from "./api";
import * as s from "./styles.css";

const KIND_LABEL: Record<string, string> = {
  read: "read",
  write: "write",
  hosts: "web",
  connect: "connect",
};
const KIND_PILL: Record<string, keyof typeof s.pill> = {
  read: "plain",
  write: "warn",
  hosts: "web",
  connect: "warn",
};

type Act = (
  op: "allow" | "remove" | "dismiss" | "trust",
  req: EditRequest,
) => void;

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
  const pending = cards.filter(([, c]) => !c.learned);
  const learned = cards.filter(([, c]) => c.learned);
  document.title = `${pending.length ? `(${pending.length}) ` : ""}sydguard`;
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
          Waiting for you {pending.length > 0 && `(${pending.length})`}
        </h2>
        {pending.length ? (
          pending.map(([vm, c]) => (
            <CardView key={c.id} vm={vm} card={c} act={act} />
          ))
        ) : (
          <div class={s.empty}>Nothing blocked right now.</div>
        )}

        <h2 class={s.section}>
          Learning now{" "}
          <span class={s.mute}>
            (saved to the rules file when the learn run exits)
          </span>
        </h2>
        {learned.length ? (
          learned.map(([vm, c]) => (
            <CardView key={c.id} vm={vm} card={c} act={act} />
          ))
        ) : (
          <div class={s.empty}>
            Run sydguard --learn -- &lt;agent&gt; to record rules automatically.
          </div>
        )}

        <h2 class={s.section}>Running agents</h2>
        <Sessions state={state} />

        <h2 class={s.section}>Rules</h2>
        {state?.ownsGlobal && state.global && (
          <RulesView
            title="All projects (every VM)"
            vm=""
            scope="global"
            file={state.global}
            act={act}
          />
        )}
        {state?.vms.map(
          (vm) =>
            !state.ownsGlobal &&
            vm.state && (
              <RulesView
                key={vm.name}
                title="All projects"
                vm={vm.name}
                scope="global"
                file={vm.state.global}
                act={act}
              />
            ),
        )}
        {files.map(([vm, f]) => (
          <RulesView
            key={vm + f.path}
            title={`${vm} › ${short(f.project) || "rules"}`}
            vm={vm}
            scope="rules"
            file={f}
            act={act}
            running={f.sessions.length}
          />
        ))}
      </main>
    </>
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
          <select
            value={kind}
            onChange={(e) => setKind(e.currentTarget.value as Kind)}
          >
            <option value="read">read</option>
            <option value="write">read+write</option>
          </select>
        )}
        <select
          value={scope}
          onChange={(e) =>
            setScope(e.currentTarget.value as "rules" | "global")
          }
        >
          <option value="rules">this rules file ({base(c.rulesFile)})</option>
          <option value="global">all projects</option>
        </select>
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

function Sessions({ state }: { state: State | null }) {
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

const BLOCKS: [Kind, string, string][] = [
  ["read", "Read", "~/.cache/go-build/**"],
  ["write", "Read + write", "~/.npm/**"],
  [
    "hosts",
    "Web & DNS (by host name)",
    "https://github.com, *.npmjs.org, tcp://db:5432",
  ],
  ["connect", "Raw connect (advanced)", "1.2.3.4!22"],
  ["ignore", "Always deny", "host or path"],
];

function RulesView(props: {
  title: string;
  vm: string;
  scope: "rules" | "global";
  file: RuleFile | FileView;
  act: Act;
  running?: number;
}) {
  const { title, vm, scope, file: f, act, running } = props;
  const baseline = "baseline" in f ? f.baseline : undefined;
  return (
    <div class={s.card}>
      <div class={s.row}>
        <strong>{title}</strong>
        <span class={s.mute}>{short(f.path)}</span>
        {running ? <span class={s.pill.ok}>{running} running</span> : null}
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
