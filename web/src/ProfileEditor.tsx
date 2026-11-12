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
import {
  parseProfileJSON,
  profileDigest,
  sameProfile,
  validateProfile,
  validSaveOutcome,
} from "./profileValidation";

const groups: Access[] = ["read", "write", "delete"];
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
  onUnauthorized,
  refresh,
}: {
  token: string;
  profiles: ProfileMetadata[];
  profilesReady: boolean;
  sessions: Session[];
  sessionsReady: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onUnauthorized?: (requestToken: string) => void;
  refresh: () => Promise<void>;
}) {
  const [record, setRecord] = useState<ProfileRecord>();
  const [draft, setDraft] = useState<Profile>();
  const [selected, setSelected] = useState("");
  const [mode, setMode] = useState<"form" | "json">("form");
  const [raw, setRaw] = useState("");
  const [savedRaw, setSavedRaw] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [priorRevision, setPriorRevision] = useState("");
  const [conflict, setConflict] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const generation = useRef(0);
  const latestSaveContext = useRef({
    token,
    profilesReady,
    current: false,
    editable: false,
    id: "",
    revision: "",
    conflict: false,
  });
  useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  const rawResult =
    record && mode === "json" ? parseProfileJSON(raw, record.name) : undefined;
  const validationError =
    draft && record ? validateProfile(draft, record.name) : undefined;
  const intentDirty =
    !!record && !!draft && !sameProfile(record.profile, draft);
  const rawDirty = !!record && raw !== savedRaw;
  const dirty = intentDirty || rawDirty || !!rawResult?.error;
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
  latestSaveContext.current = {
    token,
    profilesReady,
    current,
    editable: !!metadata?.capabilities?.edit,
    id: record?.id ?? "",
    revision: record?.revision ?? "",
    conflict,
  };
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
    setRaw("");
    setSavedRaw("");
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
      const text = JSON.stringify(next.profile, null, 2);
      setRaw(text);
      setSavedRaw(text);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401)
        onUnauthorized?.(token);
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
      !intentDirty ||
      !!validationError ||
      !!rawResult?.error
    )
      return;
    const parsedRaw = parseProfileJSON(raw, record.name);
    const retainRaw =
      !!parsedRaw.profile && sameProfile(parsedRaw.profile, draft);
    if (
      rawDirty &&
      !retainRaw &&
      !window.confirm(
        "Discard the previous JSON text if this form draft is saved?",
      )
    )
      return;
    const submitted = structuredClone(draft);
    const submittedJSON = JSON.stringify(submitted);
    const sequence = ++generation.current;
    setBusy(true);
    setError("");
    setMessage("");
    let sent = false;
    try {
      const digest = await profileDigest(submittedJSON);
      const latest = latestSaveContext.current;
      if (
        sequence !== generation.current ||
        latest.token !== token ||
        !latest.profilesReady ||
        !latest.current ||
        !latest.editable ||
        latest.conflict ||
        latest.id !== record.id ||
        latest.revision !== record.revision
      ) {
        if (sequence === generation.current)
          setError(
            "Profile was not submitted because the selection or authorization changed. Review and try again.",
          );
        return;
      }
      sent = true;
      const result = await profileApi.save(
        token,
        record.id,
        record.revision,
        submitted,
      );
      if (sequence !== generation.current) return;
      if (!validSaveOutcome(result, record, submitted, digest))
        throw new Error("Save response did not match the submitted profile.");
      setPriorRevision(record.revision);
      setRecord(result.profile);
      setDraft(structuredClone(result.profile.profile));
      const text = retainRaw
        ? raw
        : JSON.stringify(result.profile.profile, null, 2);
      setRaw(text);
      setSavedRaw(text);
      setMessage(outcomeText(result));
      await refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401)
        onUnauthorized?.(token);
      if (sequence !== generation.current) return;
      if (!sent) {
        setError(
          "Profile was not submitted: unable to calculate its SHA-256 digest. Your edits are preserved.",
        );
        return;
      }
      const revisionConflict = err instanceof ApiError && err.status === 409;
      const definiteRejection =
        err instanceof ApiError &&
        [401, 403, 404, 409, 422, 501].includes(err.status) &&
        err.code !== "indeterminate";
      const uncertain = !definiteRejection;
      if (revisionConflict || uncertain) setConflict(true);
      setError(
        revisionConflict
          ? `Revision conflict. Your edits are preserved. ${err.currentRevision ? `Current revision: ${err.currentRevision}. ` : ""}Load the current revision explicitly to discard them.`
          : uncertain
            ? "Save outcome indeterminate. Your edits are preserved. The save may have committed; do not retry blindly. Load the current revision explicitly to reconcile before saving again."
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
      if (err instanceof ApiError && err.status === 401)
        onUnauthorized?.(token);
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
          <h3>Saved profile editing mode</h3>
          <div className={styles.row}>
            <button
              type="button"
              className={styles.button}
              aria-pressed={mode === "form"}
              disabled={busy}
              onClick={() => {
                if (
                  mode === "json" &&
                  rawResult?.error &&
                  !window.confirm(
                    "Discard invalid JSON text and return to the last valid form draft?",
                  )
                )
                  return;
                if (rawResult?.error) setRaw(JSON.stringify(draft, null, 2));
                setMode("form");
              }}
            >
              Form
            </button>
            <button
              type="button"
              className={styles.button}
              aria-pressed={mode === "json"}
              disabled={busy}
              onClick={() => {
                if (mode !== "json") {
                  const parsed = parseProfileJSON(raw, record.name);
                  if (!parsed.profile || !sameProfile(parsed.profile, draft)) {
                    if (
                      rawDirty &&
                      !window.confirm(
                        "Discard the previous JSON text to show the changed form draft?",
                      )
                    )
                      return;
                    setRaw(JSON.stringify(draft, null, 2));
                  }
                }
                setMode("json");
              }}
            >
              JSON
            </button>
          </div>
          <p>
            These rules express allow intent as a union; rule order is not
            security priority. System protected denies remain fixed. Saving
            changes the saved profile, not running permissions.
          </p>
          {mode === "json" ? (
            <>
              <label htmlFor="profile-json">Saved profile JSON</label>
              <textarea
                id="profile-json"
                className={styles.input}
                rows={18}
                value={raw}
                disabled={busy || !metadata?.capabilities?.edit}
                onChange={(event) => {
                  const text = event.target.value;
                  setRaw(text);
                  const parsed = parseProfileJSON(text, record.name);
                  if (parsed.profile) setDraft(parsed.profile);
                }}
              />
              {rawResult?.error && (
                <p role="alert" className={styles.warning}>
                  Invalid profile JSON: {rawResult.error}
                </p>
              )}
            </>
          ) : (
            <>
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
            </>
          )}
          {dirty && (
            <details open>
              <summary>
                {rawResult?.error
                  ? "Saved profile / last valid draft (JSON above is invalid)"
                  : "Unsaved profile diff (before / after)"}
              </summary>
              <pre className={styles.diff}>
                {JSON.stringify(record.profile, null, 2)}
              </pre>
              <pre className={styles.diff}>
                {JSON.stringify(draft, null, 2)}
              </pre>
            </details>
          )}
          {mode === "form" && validationError && (
            <p className={styles.warning}>Invalid profile: {validationError}</p>
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
                !intentDirty ||
                !!validationError ||
                !!rawResult?.error
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
