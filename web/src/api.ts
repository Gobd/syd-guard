export type Access = "read" | "write" | "delete";
export type Profile = {
  version: 1;
  name: string;
  files: { path: string; access: Access[]; recursive: boolean }[];
  network: { host: string; port: number; transport: string }[];
};
export type ProfileCapabilities = {
  edit: boolean;
  reload: boolean;
  saved_decisions: boolean;
};
export type ProfileMetadata = {
  id: string;
  name: string;
  project: string;
  path: string;
  revision: string;
  authority?: string;
  description?: string;
  capabilities?: Partial<ProfileCapabilities>;
};
export type ProfileRecord = ProfileMetadata & { profile: Profile };
export type ProfileOutcome = {
  status: "saved" | "applied" | "restart_required";
  profile: ProfileRecord;
  applied: boolean;
  retry_required: boolean;
  restart_required: boolean;
  message: string;
};
export type Session = {
  id: string;
  name: string;
  state: string;
  project: string;
  command?: string[];
  pid?: number;
  profile?: { id: string; name: string; revision: string };
};
export type NetworkRequest = {
  id: string;
  session_id: string;
  session_name: string;
  target: { host: string; port: number; transport: string };
  attempts: number;
};
export type FileRequest = {
  id: string;
  session_id: string;
  session_name: string;
  capability: string;
  path: string;
  attempts: number;
  restart_required?: boolean;
  is_directory?: boolean;
};
export function requestSession(
  sessions: Session[],
  request: { session_id: string; session_name: string },
): Session | undefined {
  return sessions.find(
    (session) =>
      session.id === request.session_id &&
      session.name === request.session_name &&
      session.state === "running",
  );
}
export function matchingProfile(
  session: Session | undefined,
  profiles: ProfileMetadata[],
): ProfileMetadata | undefined {
  if (!session?.profile) return undefined;
  return profiles.find(
    (profile) =>
      profile.id === session.profile?.id &&
      profile.name === session.profile.name &&
      profile.revision === session.profile.revision &&
      profile.project === session.project,
  );
}
export function fileAccess(capability: string): Access | undefined {
  if (["read", "stat", "readdir", "chdir", "readlink"].includes(capability))
    return "read";
  if (
    [
      "write",
      "create",
      "truncate",
      "chmod",
      "chattr",
      "mkdir",
      "symlink",
    ].includes(capability)
  )
    return "write";
  if (["delete", "rmdir", "rename"].includes(capability)) return "delete";
  return undefined;
}
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly currentRevision?: string,
  ) {
    super(message);
  }
}
export async function api<T>(
  token: string,
  path: string,
  body?: unknown,
  method?: "PUT",
): Promise<T> {
  const response = await fetch(path, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
  });
  if (!response.ok) {
    let detail: {
      error?: unknown;
      code?: unknown;
      current_revision?: unknown;
    } = {};
    try {
      detail = await response.json();
    } catch {
      /* Legacy responses may not be JSON. */
    }
    const message =
      typeof detail.error === "string"
        ? detail.error
        : `Request to ${path} failed (${response.status}). ${response.status === 401 ? "Run sydguard ui status for a current token." : "Refresh if the session or request has ended."}`;
    throw new ApiError(
      message,
      response.status,
      typeof detail.code === "string" ? detail.code : undefined,
      typeof detail.current_revision === "string"
        ? detail.current_revision
        : undefined,
    );
  }
  return (await response.json()) as T;
}
export const profileApi = {
  list: (token: string) => api<ProfileMetadata[]>(token, "/api/profiles"),
  get: (token: string, id: string) =>
    api<ProfileRecord>(token, `/api/profiles/${encodeURIComponent(id)}`),
  save: (
    token: string,
    id: string,
    expected_revision: string,
    profile: Profile,
  ) =>
    api<ProfileOutcome>(
      token,
      `/api/profiles/${encodeURIComponent(id)}`,
      { expected_revision, profile },
      "PUT",
    ),
  reload: (
    token: string,
    id: string,
    session_id: string,
    expected_revision: string,
  ) =>
    api<ProfileOutcome>(
      token,
      `/api/profiles/${encodeURIComponent(id)}/reload`,
      { session_id, expected_revision },
    ),
};
export function networkLabel(request: NetworkRequest): string {
  return `${request.target.host}:${request.target.port} / ${request.target.transport.toUpperCase()}`;
}
