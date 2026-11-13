import { useState } from "react";
import {
  fileAccess,
  matchingProfile,
  requestSession,
  type Access,
  type FileRequest,
  type NetworkRequest,
  type ProfileMetadata,
  type Session,
} from "./api";
import * as styles from "./theme.css";

export function SavedDecision({
  kind,
  request,
  sessions,
  profiles,
  ready,
  busy,
  decide,
}: {
  kind: "files" | "network";
  request: FileRequest | NetworkRequest;
  sessions: Session[];
  profiles: ProfileMetadata[];
  ready: boolean;
  busy: boolean;
  decide: (body: {
    profile_id: string;
    expected_revision: string;
    access?: Access[];
    recursive?: boolean;
  }) => void;
}) {
  const file = kind === "files" ? (request as FileRequest) : undefined;
  const initial = file ? fileAccess(file.capability) : undefined;
  const [access, setAccess] = useState<Access[]>(initial ? [initial] : []);
  const [recursive, setRecursive] = useState(false);
  const session = requestSession(sessions, request);
  const profile = matchingProfile(session, profiles);
  // Legacy pending events are not authenticated managed denial events.
  // Never turn one into a persistent live approval.
  const available = false;
  return (
    <div>
      {file && initial && (
        <fieldset disabled={!available || busy}>
          <legend>Saved file access</legend>
          {(["read", "write", "delete"] as Access[]).map((group) => (
            <label key={group}>
              <input
                type="checkbox"
                checked={access.includes(group)}
                onChange={(event) =>
                  setAccess(
                    event.target.checked
                      ? [...access, group]
                      : access.filter((item) => item !== group),
                  )
                }
              />{" "}
              {group}{" "}
            </label>
          ))}
          <label>
            <input
              type="checkbox"
              checked={recursive && file.is_directory === true}
              disabled={file.is_directory !== true}
              onChange={(event) => setRecursive(event.target.checked)}
            />{" "}
            Recursive directory
          </label>
        </fieldset>
      )}
      {file && !initial && <p>Saving this access type is unsupported.</p>}
      <button
        type="button"
        className={styles.button}
        disabled={busy || !available || (!!file && access.length === 0)}
        onClick={() => {
          if (profile)
            decide({
              profile_id: profile.id,
              expected_revision: profile.revision,
              ...(file
                ? { access, recursive: file.is_directory === true && recursive }
                : {}),
            });
        }}
      >
        Save to profile{available ? "" : " (unavailable)"}
      </button>
      {!available && (
        <p className={styles.muted}>
          Persistent approval is unavailable without an authenticated managed
          denial binding.
        </p>
      )}
    </div>
  );
}
