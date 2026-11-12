import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  ApiError,
  validDecisionOutcome,
  type FileRequest,
  type NetworkRequest,
  networkLabel,
  requestSession,
  type Session,
  type Access,
  type ProfileMetadata,
  profileApi,
} from "./api";
import { ProfileEditor } from "./ProfileEditor";
import { SavedDecision } from "./SavedDecision";
import * as styles from "./theme.css";
import * as approvals from "./approvals.css";

function outcomeFlag(value: boolean | undefined): string {
  return value === undefined ? "unknown" : value ? "yes" : "no";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasStrings(value: Record<string, unknown>, keys: string[]): boolean {
  return keys.every(
    (key) => typeof value[key] === "string" && value[key] !== "",
  );
}

function validStatus(active: unknown, net: unknown, fs: unknown): boolean {
  return (
    Array.isArray(active) &&
    active.every(
      (item) =>
        isObject(item) &&
        hasStrings(item, ["id", "name", "state", "project"]) &&
        (item.profile === undefined ||
          item.profile === null ||
          (isObject(item.profile) &&
            hasStrings(item.profile, ["id", "name", "revision"]))) &&
        (item.command === undefined ||
          item.command === null ||
          (Array.isArray(item.command) &&
            item.command.every((part: unknown) => typeof part === "string"))) &&
        (item.pid === undefined ||
          item.pid === null ||
          typeof item.pid === "number"),
    ) &&
    Array.isArray(net) &&
    net.every(
      (item) =>
        isObject(item) &&
        hasStrings(item, ["id", "session_id", "session_name"]) &&
        typeof item.attempts === "number" &&
        isObject(item.target) &&
        hasStrings(item.target, ["host", "transport"]) &&
        typeof item.target.port === "number",
    ) &&
    Array.isArray(fs) &&
    fs.every(
      (item) =>
        isObject(item) &&
        hasStrings(item, [
          "id",
          "session_id",
          "session_name",
          "capability",
          "path",
        ]) &&
        typeof item.attempts === "number" &&
        (item.restart_required === undefined ||
          typeof item.restart_required === "boolean") &&
        (item.is_directory === undefined ||
          typeof item.is_directory === "boolean"),
    )
  );
}

function validCapabilities(value: unknown): boolean {
  return (
    value === undefined ||
    value === null ||
    (isObject(value) &&
      ["edit", "reload", "saved_decisions"].every(
        (key) => value[key] === undefined || typeof value[key] === "boolean",
      ))
  );
}

function validCatalog(list: unknown): list is ProfileMetadata[] {
  return (
    Array.isArray(list) &&
    list.every(
      (item) =>
        isObject(item) &&
        hasStrings(item, ["id", "name", "project", "path", "revision"]) &&
        validCapabilities(item.capabilities),
    )
  );
}

type DecisionGuard = {
  kind: "files" | "network";
  id: string;
  action: "allow" | "deny";
  tokenGeneration: number;
  outcome: "pending" | "applied" | "rejected" | "unknown";
  detail: string;
};

export function App() {
  const [token, setToken] = useState(
    () => new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "",
  );
  const [sessions, setSessions] = useState<Session[]>([]);
  const [network, setNetwork] = useState<NetworkRequest[]>([]);
  const [files, setFiles] = useState<FileRequest[]>([]);
  const [profiles, setProfiles] = useState<ProfileMetadata[]>([]);
  const [profilesReady, setProfilesReady] = useState(false);
  const [profileDirty, setProfileDirty] = useState(false);
  const [sessionsReady, setSessionsReady] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [decisionGuard, setDecisionGuard] = useState<DecisionGuard>();
  const busy = !!decisionGuard;
  const decision = useRef<DecisionGuard | undefined>(undefined);
  const reconciling = useRef(false);
  const mounted = useRef(false);
  const tokenGeneration = useRef(0);
  const tokenRef = useRef(token);
  const invalidAuth = useRef(false);
  const lifetime = useRef(0);
  const refreshSequence = useRef(0);
  // Overlapping polls must not hide a timeout, or let an older result replace
  // a newer settled snapshot.
  const settledRefresh = useRef(0);
  const profileSequence = useRef(0);
  const profileFlight = useRef<
    { token: string; promise: Promise<void> } | undefined
  >(undefined);
  useEffect(() => {
    mounted.current = true;
    const generation = tokenGeneration;
    return () => {
      mounted.current = false;
      generation.current++;
    };
  }, []);
  // ProfileEditor reports direct profile API 401s through this same token epoch.
  const authGeneration = tokenGeneration.current;
  const onUnauthorized = useCallback(
    (requestToken: string, generation: number) => {
      if (
        !mounted.current ||
        generation !== tokenGeneration.current ||
        requestToken !== tokenRef.current
      )
        return;
      invalidAuth.current = true;
      setProfiles([]);
      setProfilesReady(false);
      setSessionsReady(false);
      setError(
        "UI token unauthorized (401). Displayed data may be stale; enter a new UI token.",
      );
    },
    [],
  );
  const profileEditorAuth = {
    onUnauthorized: (requestToken: string) =>
      onUnauthorized(requestToken, authGeneration),
  };
  useEffect(() => {
    window.history.replaceState(null, "", window.location.pathname);
  }, []);
  const refreshProfiles = useCallback(async () => {
    // Catalog sequencing is independent of live status. A slow catalog is not
    // superseded on every poll, and a stalled status read cannot freeze it.
    if (profileFlight.current?.token === token)
      return profileFlight.current.promise;
    const sequence = ++profileSequence.current;
    const generation = lifetime.current;
    const authGeneration = tokenGeneration.current;
    const promise = profileApi
      .list(token)
      .then((list) => {
        if (!validCatalog(list))
          throw new Error("Invalid profile catalog response");
        if (
          generation === lifetime.current &&
          sequence === profileSequence.current &&
          !invalidAuth.current
        ) {
          setProfiles(list);
          setProfilesReady(true);
        }
      })
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 401)
          onUnauthorized(token, authGeneration);
        if (
          generation === lifetime.current &&
          sequence === profileSequence.current
        ) {
          setProfiles([]);
          setProfilesReady(false);
        }
      })
      .finally(() => {
        if (
          generation === lifetime.current &&
          sequence === profileSequence.current
        )
          profileFlight.current = undefined;
      });
    profileFlight.current = { token, promise };
    await promise;
  }, [token, onUnauthorized]);
  const readStatus = useCallback(
    async (authGeneration: number) => {
      const observe = <T,>(request: Promise<T>): Promise<T> =>
        request.catch((error: unknown) => {
          if (error instanceof ApiError && error.status === 401)
            onUnauthorized(token, authGeneration);
          throw error;
        });
      const [active, net, fs] = await Promise.all([
        observe(api<Session[]>(token, "/api/sessions")),
        observe(api<NetworkRequest[]>(token, "/api/network/pending")),
        observe(api<FileRequest[]>(token, "/api/files/pending")),
      ]);
      if (!validStatus(active, net, fs))
        throw new Error("Invalid status response");
      return { active, net, fs };
    },
    [token, onUnauthorized],
  );
  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    const generation = lifetime.current;
    if (!token) {
      setSessionsReady(false);
      setProfilesReady(false);
      setError("Enter a UI token from sydguard ui status.");
      return;
    }
    if (invalidAuth.current) return;
    const profileRefresh = refreshProfiles();
    try {
      const { active, net, fs } = await readStatus(tokenGeneration.current);
      if (
        generation !== lifetime.current ||
        invalidAuth.current ||
        sequence <= settledRefresh.current
      )
        return;
      settledRefresh.current = sequence;
      setSessions(active);
      setNetwork(net);
      setFiles(fs);
      setSessionsReady(true);
      setError("");
    } catch (error) {
      if (
        generation !== lifetime.current ||
        invalidAuth.current ||
        sequence <= settledRefresh.current
      )
        return;
      settledRefresh.current = sequence;
      setSessionsReady(false);
      setError(
        `Status unavailable; displayed data may be stale. ${error instanceof Error ? error.message : "Controller unavailable"}`,
      );
    }
    await profileRefresh;
  }, [token, refreshProfiles, readStatus]);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => {
      void refresh();
    }, 2000);
    const activeLifetime = lifetime;
    const sequence = refreshSequence;
    const catalogSequence = profileSequence;
    const catalogFlight = profileFlight;
    return () => {
      clearInterval(timer);
      activeLifetime.current++;
      sequence.current++;
      catalogSequence.current++;
      catalogFlight.current = undefined;
    };
  }, [refresh]);
  async function decide(
    kind: "files" | "network",
    id: string,
    action: "allow" | "deny",
    scope: "run" | "saved",
    saved?: {
      profile_id: string;
      expected_revision: string;
      access?: Access[];
      recursive?: boolean;
    },
  ) {
    if (decision.current || invalidAuth.current) return;
    const operation: DecisionGuard = {
      kind,
      id,
      action,
      tokenGeneration: tokenGeneration.current,
      outcome: "pending",
      detail:
        "Decision response is still pending; do not send a conflicting decision.",
    };
    decision.current = operation;
    setDecisionGuard(operation);
    setMessage("");
    try {
      const result = await api<unknown>(token, `/api/${kind}/decisions`, {
        id,
        action,
        scope,
        ...saved,
      });
      if (!mounted.current || decision.current !== operation) return;
      if (!validDecisionOutcome(result, kind, scope))
        throw new Error("Unrecognized decision response");
      const detail =
        scope === "saved"
          ? `${result.message ?? result.status ?? "Decision response received."} Applied: ${outcomeFlag(result.applied)}; retry required: ${outcomeFlag(result.retry_required)}; restart required: ${outcomeFlag(result.restart_required)}.`
          : `${action === "allow" ? "Approved" : "Denied"}. The workload must retry; no paused syscall was resumed.`;
      if (
        operation.tokenGeneration === tokenGeneration.current &&
        !invalidAuth.current
      ) {
        setMessage(detail);
        await refresh();
        if (!mounted.current || decision.current !== operation) return;
        if (
          operation.tokenGeneration === tokenGeneration.current &&
          !invalidAuth.current
        ) {
          decision.current = undefined;
          setDecisionGuard(undefined);
          return;
        }
      }
      const settled: DecisionGuard = {
        ...operation,
        outcome: "applied",
        detail,
      };
      decision.current = settled;
      setDecisionGuard(settled);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401)
        onUnauthorized(token, operation.tokenGeneration);
      if (!mounted.current || decision.current !== operation) return;
      const rejected = error instanceof ApiError && error.status === 401;
      const settled: DecisionGuard = {
        ...operation,
        outcome: rejected ? "rejected" : "unknown",
        detail: rejected
          ? "The decision was rejected as unauthorized."
          : "The decision outcome is unknown and may have applied; do not retry blindly.",
      };
      decision.current = settled;
      setDecisionGuard(settled);
    }
  }

  async function reconcileDecision() {
    const operation = decision.current;
    if (
      !operation ||
      operation.outcome === "pending" ||
      reconciling.current ||
      invalidAuth.current ||
      !token
    )
      return;
    reconciling.current = true;
    const generation = lifetime.current;
    const authGeneration = tokenGeneration.current;
    const sequence = ++refreshSequence.current;
    try {
      const { active, net, fs } = await readStatus(authGeneration);
      if (
        !mounted.current ||
        generation !== lifetime.current ||
        invalidAuth.current ||
        decision.current !== operation
      )
        return;
      if (sequence <= settledRefresh.current) {
        setMessage(
          "Reconciliation was superseded by a newer status read. Fetch a fresh snapshot again.",
        );
        return;
      }
      settledRefresh.current = sequence;
      setSessions(active);
      setNetwork(net);
      setFiles(fs);
      setSessionsReady(true);
      setError("");
      const stillPending = (operation.kind === "files" ? fs : net).some(
        (request) => request.id === operation.id,
      );
      if (stillPending && operation.outcome !== "rejected") {
        setMessage(
          "The original request is still pending. Its prior decision may have applied; conflicting decisions remain blocked. Do not retry blindly.",
        );
        return;
      }
      decision.current = undefined;
      setDecisionGuard(undefined);
      setMessage(
        operation.outcome === "unknown"
          ? "The original request is absent from the fresh pending snapshot. Its decision outcome remains unknown; absence does not prove failure. Do not retry blindly."
          : `${operation.detail} Fresh pending requests were fetched.`,
      );
    } catch (error) {
      if (
        mounted.current &&
        generation === lifetime.current &&
        !invalidAuth.current
      ) {
        setSessionsReady(false);
        setError(
          `Reconciliation failed; displayed data may be stale. ${error instanceof Error ? error.message : "Controller unavailable"}`,
        );
      }
    } finally {
      reconciling.current = false;
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
          onChange={(event) => {
            if (
              profileDirty &&
              !window.confirm(
                "Discard unsaved profile edits and change the UI token?",
              )
            )
              return;
            setProfileDirty(false);
            lifetime.current++;
            tokenGeneration.current++;
            tokenRef.current = event.target.value;
            invalidAuth.current = false;
            setMessage("");
            setError("");
            refreshSequence.current++;
            profileSequence.current++;
            profileFlight.current = undefined;
            setSessionsReady(false);
            setProfilesReady(false);
            setSessions([]);
            setNetwork([]);
            setFiles([]);
            setProfiles([]);
            setToken(event.target.value);
          }}
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
      {decisionGuard && (
        <section className={styles.panel}>
          <p className={styles.warning}>
            {decisionGuard.action} · {decisionGuard.kind} request{" "}
            {decisionGuard.id}: {decisionGuard.detail} All request decisions are
            blocked until the outcome is reconciled.
          </p>
          <button
            type="button"
            className={styles.button}
            disabled={
              decisionGuard.outcome === "pending" ||
              !token ||
              invalidAuth.current
            }
            onClick={() => void reconcileDecision()}
          >
            Fetch fresh pending requests to reconcile
          </button>
        </section>
      )}
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
              <p>
                Profile:{" "}
                {session.profile
                  ? `${session.profile.name} · ID: ${session.profile.id} · Revision: ${session.profile.revision}`
                  : "not supplied by launcher"}
              </p>
            </div>
          ))
        )}
      </section>
      <ProfileEditor
        key={token}
        {...profileEditorAuth}
        token={token}
        profiles={profiles}
        profilesReady={profilesReady}
        sessions={sessions}
        sessionsReady={sessionsReady}
        onDirtyChange={setProfileDirty}
        refresh={refresh}
      />
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
          <p>
            Profile:{" "}
            {requestSession(sessions, request)?.profile?.name ??
              "not yet selected by launcher"}
          </p>
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
                !sessionsReady ||
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
              disabled={
                busy ||
                !sessionsReady ||
                !!error ||
                !requestSession(sessions, request)
              }
              onClick={() => void decide("files", request.id, "deny", "run")}
            >
              Deny for run
            </button>
          </div>
          <SavedDecision
            kind="files"
            key={`${request.id}:${request.session_id}:${request.session_name}:${request.capability}:${request.is_directory}`}
            request={request}
            sessions={sessions}
            profiles={profiles}
            ready={profilesReady && sessionsReady && !error}
            busy={busy}
            decide={(saved) =>
              void decide("files", request.id, "allow", "saved", saved)
            }
          />
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
          <p>
            Profile:{" "}
            {requestSession(sessions, request)?.profile?.name ??
              "not yet selected by launcher"}
          </p>
          <div className={approvals.target}>{networkLabel(request)}</div>
          <div className={styles.row}>
            <button
              type="button"
              className={styles.button}
              disabled={
                busy ||
                !sessionsReady ||
                !!error ||
                !requestSession(sessions, request)
              }
              onClick={() => void decide("network", request.id, "allow", "run")}
            >
              Allow for run
            </button>
            <button
              type="button"
              className={styles.button}
              disabled={
                busy ||
                !sessionsReady ||
                !!error ||
                !requestSession(sessions, request)
              }
              onClick={() => void decide("network", request.id, "deny", "run")}
            >
              Deny for run
            </button>
          </div>
          <SavedDecision
            kind="network"
            request={request}
            sessions={sessions}
            profiles={profiles}
            ready={profilesReady && sessionsReady && !error}
            busy={busy}
            decide={(saved) =>
              void decide("network", request.id, "allow", "saved", saved)
            }
          />
        </section>
      ))}
    </main>
  );
}
