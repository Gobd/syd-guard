export type Session = {
  id: string;
  name: string;
  state: string;
  project: string;
  command?: string[];
  pid?: number;
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
export async function api<T>(
  token: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
  });
  if (!response.ok)
    throw new Error(
      `Request to ${path} failed (${response.status}). ${response.status === 401 ? "Run sydguard ui status for a current token." : "Refresh if the session or request has ended."}`,
    );
  return (await response.json()) as T;
}
export function networkLabel(request: NetworkRequest): string {
  return `${request.target.host}:${request.target.port} / ${request.target.transport.toUpperCase()}`;
}
