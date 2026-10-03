const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

export function getAccessToken(): string | null {
  return typeof window === "undefined" ? null : sessionStorage.getItem("securewatch_access_token");
}

export function setAccessToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) sessionStorage.setItem("securewatch_access_token", token);
  else sessionStorage.removeItem("securewatch_access_token");
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getAccessToken();
  const response = await fetch(`${API_URL}${path}`, {
    ...init, credentials: "include",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...init.headers }
  });
  const payload = await response.json() as { success: boolean; data?: T; error?: { code: string; message: string } };
  if (!response.ok || !payload.success) throw new ApiError(response.status, payload.error?.code ?? "API_ERROR", payload.error?.message ?? "Request failed");
  return payload.data as T;
}

export async function refreshAccessToken(): Promise<boolean> {
  try {
    const data = await api<{ accessToken: string }>("/api/v1/auth/refresh", { method: "POST", body: "{}" });
    setAccessToken(data.accessToken);
    return true;
  } catch { return false; }
}

export { API_URL };
