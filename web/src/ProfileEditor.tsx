import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  profileApi,
  type Access,
  type Profile,
  type ProfileMetadata,
  type ProfileOutcome,
  type ProfileRecord,
  type Session,
} from "./api";
import * as styles from "./theme.css";

const groups: Access[] = ["read", "write", "delete"];
function validProfile(profile: Profile): boolean {
  return (
    profile.version === 1 &&
    profile.files.every(
      (rule) =>
        rule.path.length > 0 &&
        rule.path.length <= 4096 &&
        ![...rule.path].some(
          (ch) =>
            ch.charCodeAt(0) < 32 ||
            (ch.charCodeAt(0) >= 127 && ch.charCodeAt(0) <= 159) ||
            "*?[]{}\\$;!".includes(ch),
        ) &&
        !rule.path.split("/").includes("..") &&
        (!rule.path.startsWith("~") ||
          rule.path === "~" ||
          rule.path.startsWith("~/")) &&
        rule.access.length > 0 &&
        new Set(rule.access).size === rule.access.length &&
        rule.access.every((access) => groups.includes(access)),
    ) &&
    profile.network.every(
      (rule) =>
        rule.host.length > 0 &&
        rule.host.length <= 253 &&
        rule.host.includes(".") &&
        !/^\d+\.\d+\.\d+\.\d+$/.test(rule.host) &&
        rule.host
          .split(".")
          .every(
            (label) =>
              label.length > 0 &&
              label.length <= 63 &&
              /^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$/.test(label),
          ) &&
        Number.isInteger(rule.port) &&
        rule.port >= 1 &&
        rule.port <= 65535 &&
        ["tcp", "udp"].includes(rule.transport),
    )
  );
}
function outcomeText(outcome: ProfileOutcome): string {
  return `${outcome.message} Applied: ${outcome.applied ? "yes" : "no"}; retry required: ${outcome.retry_required ? "yes" : "no"}; restart required: ${outcome.restart_required ? "yes" : "no"}.`;
}
export function ProfileEditor({
  token,
  profiles,
  profilesReady,
  sessions,
  sessionsReady,
  onDirtyChange,
  refresh,
}: {
  token: string;
  profiles: ProfileMetadata[];
  profilesReady: boolean;
  sessions: Session[];
  sessionsReady: boolean;
  onDirtyChange: (dirty: boolean) => void;
  refresh: () => Promise<void>;
}) {
  const [record, setRecord] = useState<ProfileRecord>();
  const [draft, setDraft] = useState<Profile>();
  const [selected, setSelected] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [priorRevision, setPriorRevision] = useState("");
  const [conflict, setConflict] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const generation = useRef(0);
  useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  const dirty =
    !!record &&
    !!draft &&
    JSON.stringify(record.profile) !== JSON.stringify(draft);
  useEffect(() => {
    onDirtyChange(dirty);
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty, onDirtyChange]);
  const metadata = profiles.find((item) => item.id === record?.id);
  const current =
    !!record &&
    !!metadata &&
    metadata.name === record.name &&
    metadata.project === record.project &&
    metadata.path === record.path &&
    metadata.revision === record.revision;
  const eligible = sessions.filter(
    (session) =>
      session.state === "running" &&
      session.profile?.id === record?.id &&
      session.profile?.name === record?.name &&
      session.project === record?.project &&
      (session.profile?.revision === record?.revision ||
        (!!priorRevision && session.profile?.revision === priorRevision)),
  );
  async function load(id: string) {
    if (
      dirty &&
      !window.confirm(
        "Discard unsaved profile edits and load another revision?",
      )
    )
      return;
    const sequence = ++generation.current;
    setSelected(id);
    setRecord(undefined);
    setDraft(undefined);
    setPriorRevision("");
    setConflict(false);
    setSessionId("");
    setError("");
    setMessage("");
    if (!id) return;
    setBusy(true);
    try {
      const next = await profileApi.get(token, id);
      if (sequence !== generation.current) return;
      if (next.id !== id)
        throw new Error("Profile identity did not match the selection.");
      setRecord(next);
      setDraft(structuredClone(next.profile));
    } catch (err) {
      if (sequence === generation.current)
        setError(err instanceof Error ? err.message : "Profile load failed");
    } finally {
      if (sequence === generation.current) setBusy(false);
    }
  }
  async function save() {
    if (
      !record ||
      !draft ||
      conflict ||
      !current ||
      !profilesReady ||
      !metadata?.capabilities?.edit ||
      !validProfile(draft)
    )
      return;
    const sequence = ++generation.current;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await profileApi.save(
        token,
        record.id,
        record.revision,
        draft,
      );
      if (sequence !== generation.current) return;
      if (result.profile.id !== record.id)
        throw new Error("Profile identity did not match the selection.");
      setPriorRevision(record.revision);
      setRecord(result.profile);
      setDraft(structuredClone(result.profile.profile));
      setMessage(outcomeText(result));
      await refresh();
    } catch (err) {
      if (sequence !== generation.current) return;
      if (err instanceof ApiError && err.status === 409) setConflict(true);
      setError(
        err instanceof ApiError && err.status === 409
          ? `Revision conflict. Your edits are preserved. ${err.currentRevision ? `Current revision: ${err.currentRevision}. ` : ""}Load the current revision explicitly to discard them.`
          : err instanceof Error
            ? err.message
            : "Save failed",
      );
    } finally {
      if (sequence === generation.current) setBusy(false);
    }
  }
  async function reload() {
    const session = eligible.find((item) => item.id === sessionId);
    if (
      !record ||
      !session ||
      dirty ||
      !current ||
      !profilesReady ||
      !sessionsReady ||
      !metadata?.capabilities?.reload
    )
      return;
    const sequence = ++generation.current;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await profileApi.reload(
        token,
        record.id,
        session.id,
        record.revision,
      );
      if (sequence !== generation.current) return;
      if (result.profile.id !== record.id)
        throw new Error("Profile identity did not match the selection.");
      setMessage(outcomeText(result));
      await refresh();
    } catch (err) {
      if (sequence === generation.current)
        setError(
          err instanceof ApiError && err.status === 409
            ? "Revision or session conflict. Refresh and load the current revision explicitly; edits are preserved."
            : err instanceof Error
              ? err.message
              : "Reload failed",
        );
    } finally {
      if (sequence === generation.current) setBusy(false);
    }
  }
  return (
    <section className={styles.panel}>
      <h2>Project profiles</h2>
      <p className={styles.muted}>
        Profiles can also be edited outside Syd. Managed editing requires a
        protected backend and root helper; discovered candidates are not
        trusted. Saving does not change running permissions.
      </p>
      <label htmlFor="profile-select">Selected project profile</label>
      <select
        id="profile-select"
        className={styles.input}
        value={selected}
        disabled={busy || !profilesReady}
        onChange={(event) => void load(event.target.value)}
      >
        <option value="">Select a profile</option>
        {profiles.map((item) => (
          <option key={item.id} value={item.id}>
            {item.project} — {item.name}
          </option>
        ))}
      </select>
      {!profilesReady && (
        <p>
          Profile service unavailable or refreshing; editing and saved decisions
          are unavailable.
        </p>
      )}
      {error && (
        <p role="alert" className={styles.warning}>
          {error}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {record && draft && (
        <>
          {record.authority === "untrusted-candidate" && (
            <p className={styles.warning}>
              Untrusted candidate.{" "}
              {record.description ??
                "Discovered candidate; not applied to this session"}{" "}
              Editing, reload, and saved decisions are unavailable.
            </p>
          )}
          <p>Project: {record.project}</p>
          <p>Profile: {record.name}</p>
          <p>Profile ID: {record.id}</p>
          <p>Profile path: {record.path}</p>
          <p>Revision: {record.revision}</p>
          {!current && (
            <p className={styles.warning}>
              Profile metadata is stale. Your edits are preserved; load the
              current revision explicitly.
            </p>
          )}
          <button
            type="button"
            className={styles.button}
            disabled={busy || !profilesReady}
            onClick={() => void load(record.id)}
          >
            Load current revision
          </button>
          <p>
            Read means inspect; write means create or edit; delete includes
            rename or replace. No-delete does not preserve file contents.
          </p>
          <h3>File rules</h3>
          {draft.files.map((rule, index) => (
            <fieldset
              key={index}
              disabled={busy || !metadata?.capabilities?.edit}
            >
              <legend>File rule {index + 1}</legend>
              <label>
                Path{" "}
                <input
                  className={styles.input}
                  value={rule.path}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      files: draft.files.map((item, i) =>
                        i === index
                          ? { ...item, path: event.target.value }
                          : item,
                      ),
                    })
                  }
                />
              </label>
              {groups.map((group) => (
                <label key={group}>
                  <input
                    type="checkbox"
                    checked={rule.access.includes(group)}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        files: draft.files.map((item, i) =>
                          i === index
                            ? {
                                ...item,
                                access: event.target.checked
                                  ? [...item.access, group]
                                  : item.access.filter(
                                      (value) => value !== group,
                                    ),
                              }
                            : item,
                        ),
                      })
                    }
                  />{" "}
                  {group}{" "}
                </label>
              ))}
              <label>
                <input
                  type="checkbox"
                  checked={rule.recursive}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      files: draft.files.map((item, i) =>
                        i === index
                          ? { ...item, recursive: event.target.checked }
                          : item,
                      ),
                    })
                  }
                />{" "}
                Recursive
              </label>
              <button
                type="button"
                className={styles.button}
                onClick={() =>
                  setDraft({
                    ...draft,
                    files: draft.files.filter((_, i) => i !== index),
                  })
                }
              >
                Remove file rule
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className={styles.button}
            disabled={busy || !metadata?.capabilities?.edit}
            onClick={() =>
              setDraft({
                ...draft,
                files: [
                  ...draft.files,
                  { path: "", access: [], recursive: false },
                ],
              })
            }
          >
            Add file rule
          </button>
          <h3>Exact network rules</h3>
          {draft.network.map((rule, index) => (
            <fieldset
              key={index}
              disabled={busy || !metadata?.capabilities?.edit}
            >
              <legend>Network rule {index + 1}</legend>
              <label>
                Host{" "}
                <input
                  className={styles.input}
                  value={rule.host}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      network: draft.network.map((item, i) =>
                        i === index
                          ? { ...item, host: event.target.value }
                          : item,
                      ),
                    })
                  }
                />
              </label>
              <label>
                Port{" "}
                <input
                  className={styles.input}
                  type="number"
                  min="1"
                  max="65535"
                  value={rule.port || ""}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      network: draft.network.map((item, i) =>
                        i === index
                          ? { ...item, port: event.target.valueAsNumber }
                          : item,
                      ),
                    })
                  }
                />
              </label>
              <label>
                Transport{" "}
                <select
                  value={rule.transport}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      network: draft.network.map((item, i) =>
                        i === index
                          ? { ...item, transport: event.target.value }
                          : item,
                      ),
                    })
                  }
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </label>
              <button
                type="button"
                className={styles.button}
                onClick={() =>
                  setDraft({
                    ...draft,
                    network: draft.network.filter((_, i) => i !== index),
                  })
                }
              >
                Remove network rule
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className={styles.button}
            disabled={busy || !metadata?.capabilities?.edit}
            onClick={() =>
              setDraft({
                ...draft,
                network: [
                  ...draft.network,
                  { host: "", port: 0, transport: "tcp" },
                ],
              })
            }
          >
            Add network rule
          </button>
          {dirty && (
            <details open>
              <summary>Unsaved profile diff (before / after)</summary>
              <pre className={styles.diff}>
                {JSON.stringify(record.profile, null, 2)}
              </pre>
              <pre className={styles.diff}>
                {JSON.stringify(draft, null, 2)}
              </pre>
            </details>
          )}
          {!validProfile(draft) && (
            <p className={styles.warning}>
              Invalid rule: provide a valid path and access, or an exact host,
              port 1–65535 and TCP/UDP transport.
            </p>
          )}
          <div className={styles.row}>
            <button
              type="button"
              className={styles.button}
              disabled={
                busy ||
                !profilesReady ||
                conflict ||
                !current ||
                !metadata?.capabilities?.edit ||
                !dirty ||
                !validProfile(draft)
              }
              onClick={() => void save()}
            >
              Save profile
            </button>
            {!metadata?.capabilities?.edit && (
              <span>Profile editing unavailable.</span>
            )}
          </div>
          <h3>Reload running session</h3>
          <label htmlFor="reload-session">Active session</label>
          <select
            id="reload-session"
            className={styles.input}
            value={sessionId}
            disabled={busy || !sessionsReady}
            onChange={(event) => setSessionId(event.target.value)}
          >
            <option value="">Select a session</option>
            {eligible.map((session) => (
              <option key={session.id} value={session.id}>
                {session.name} — {session.id} — revision{" "}
                {session.profile?.revision}
              </option>
            ))}
          </select>
          <button
            type="button"
            className={styles.button}
            disabled={
              busy ||
              dirty ||
              !current ||
              !profilesReady ||
              !sessionsReady ||
              !metadata?.capabilities?.reload ||
              !eligible.some((session) => session.id === sessionId)
            }
            onClick={() => void reload()}
          >
            Reload profile into session
          </button>
          {!metadata?.capabilities?.reload && (
            <p>Profile reload unavailable.</p>
          )}
        </>
      )}
    </section>
  );
}
