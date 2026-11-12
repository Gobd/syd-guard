import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  type FileRequest,
  type NetworkRequest,
  networkLabel,
  requestSession,
  type Session,
} from "./api";
import * as styles from "./theme.css";
import * as approvals from "./approvals.css";

export function App() {
  const [token, setToken] = useState(
    () => new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "",
  );
  const [sessions, setSessions] = useState<Session[]>([]);
  const [network, setNetwork] = useState<NetworkRequest[]>([]);
  const [files, setFiles] = useState<FileRequest[]>([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const refreshSequence = useRef(0);
  useEffect(() => {
    window.history.replaceState(null, "", window.location.pathname);
  }, []);
  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    if (!token) {
      setError("Enter a UI token from sydguard ui status.");
      return;
    }
    try {
      const [active, net, fs] = await Promise.all([
        api<Session[]>(token, "/api/sessions"),
        api<NetworkRequest[]>(token, "/api/network/pending"),
        api<FileRequest[]>(token, "/api/files/pending"),
      ]);
      if (sequence !== refreshSequence.current) return;
      setSessions(active);
      setNetwork(net);
      setFiles(fs);
      setError("");
    } catch (error) {
      if (sequence !== refreshSequence.current) return;
      setError(
        error instanceof Error ? error.message : "Controller unavailable",
      );
    }
  }, [token]);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => {
      void refresh();
    }, 2000);
    const sequence = refreshSequence;
    return () => {
      clearInterval(timer);
      sequence.current++;
    };
  }, [refresh]);
  async function decide(
    kind: "files" | "network",
    id: string,
    action: "allow" | "deny",
    scope: "run" | "saved",
  ) {
    setBusy(true);
    setMessage("");
    try {
      await api(token, `/api/${kind}/decisions`, { id, action, scope });
      setMessage(
        `${action === "allow" ? "Approved" : "Denied"}. The workload must retry; no paused syscall was resumed.`,
      );
      await refresh();
    } catch (error) {
      setError(error instanceof Error ? error.message : "Decision failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className={`${styles.theme} ${styles.page}`}>
      <h1>Syd Guard approvals</h1>
      <p className={styles.muted}>
        Operator controls only. This page cannot start a terminal or silently
        grant access.
      </p>
      <section className={styles.panel}>
        <label htmlFor="operator-token">
          UI access token (not the controller’s master token)
        </label>
        <input
          id="operator-token"
          className={styles.input}
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          autoComplete="off"
        />
        <p className={styles.muted}>
          Token stays in this page’s memory and expires after 30 minutes. Run
          sydguard ui status to recover a current URL; stopping or restarting
          the UI invalidates it.
        </p>
      </section>
      <p role="alert" className={styles.warning}>
        {error}
      </p>
      <p role="status">{message}</p>
      <section className={styles.panel}>
        <h2>Active sessions</h2>
        {sessions.length === 0 ? (
          <p className={styles.muted}>No tracked foreground sessions.</p>
        ) : (
          sessions.map((session) => (
            <div key={session.id}>
              <strong>{session.name}</strong>
              <p className={approvals.target}>{session.project}</p>
              <p>
                Session ID: {session.id} · State: {session.state}
              </p>
              <p>
                Command: {session.command?.[0] ?? "Unavailable"} · PID:{" "}
                {session.pid ?? "Unavailable"}
              </p>
              <p>Profile: not supplied by launcher</p>
            </div>
          ))
        )}
      </section>
      <h2>File requests ({files.length})</h2>
      <p className={styles.muted}>
        Exact-path, per-run grants within declared immutable ceilings.
        Read/write/create/delete/rename are separate. Metadata access
        accompanies a grant.
      </p>
      {files.length === 0 && (
        <p className={styles.muted}>
          No pending file requests. Eligibility is not an approval; --scope adds
          an advanced immutable ceiling.
        </p>
      )}
      {files.map((request) => (
        <section className={styles.panel} key={request.id}>
          <div className={styles.row}>
            <strong>{request.session_name}</strong>
            <span className={approvals.badge}>{request.capability}</span>
            <small>{request.attempts} attempts</small>
          </div>
          <p>Session ID: {request.session_id}</p>
          <p>
            Project:{" "}
            {requestSession(sessions, request)?.project ??
              "Unavailable; refresh before deciding"}
          </p>
          <p>Profile: not yet selected by launcher</p>
          <div className={approvals.target}>{request.path}</div>
          {request.restart_required && (
            <p className={styles.warning}>
              Outside the immutable ceiling. Review the ceiling and restart;
              live approval is unavailable.
            </p>
          )}
          <div className={styles.row}>
            <button
              type="button"
              className={styles.button}
              disabled={
                busy ||
                !!error ||
                !!request.restart_required ||
                !requestSession(sessions, request)
              }
              onClick={() => void decide("files", request.id, "allow", "run")}
            >
              Allow exact path for run
            </button>
            <button
              type="button"
              className={styles.button}
              disabled={busy || !!error || !requestSession(sessions, request)}
              onClick={() => void decide("files", request.id, "deny", "run")}
            >
              Deny for run
            </button>
          </div>
        </section>
      ))}
      <h2>Network requests ({network.length})</h2>
      <p className={styles.warning}>
        Exact host and TCP port requests require approval and a retry.
        Transparent enforcement remains experimental and is not a TLS identity
        guarantee.
      </p>
      {network.length === 0 && (
        <p className={styles.muted}>No pending network targets.</p>
      )}
      {network.map((request) => (
        <section className={styles.panel} key={request.id}>
          <div className={styles.row}>
            <strong>{request.session_name}</strong>
            <small>{request.attempts} attempts</small>
          </div>
          <p>Session ID: {request.session_id}</p>
          <p>
            Project:{" "}
            {requestSession(sessions, request)?.project ??
              "Unavailable; refresh before deciding"}
          </p>
          <p>Profile: not yet selected by launcher</p>
          <div className={approvals.target}>{networkLabel(request)}</div>
          <div className={styles.row}>
            <button
              type="button"
              className={styles.button}
              disabled={busy || !!error || !requestSession(sessions, request)}
              onClick={() => void decide("network", request.id, "allow", "run")}
            >
              Allow for run
            </button>
            <button
              type="button"
              className={styles.button}
              disabled
              title="Saving to a selected project profile is not implemented"
            >
              Save to profile (unavailable)
            </button>
            <button
              type="button"
              className={styles.button}
              disabled={busy || !!error || !requestSession(sessions, request)}
              onClick={() => void decide("network", request.id, "deny", "run")}
            >
              Deny for run
            </button>
          </div>
        </section>
      ))}
    </main>
  );
}
