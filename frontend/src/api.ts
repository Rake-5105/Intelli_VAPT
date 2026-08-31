/** API client with typed request helper for IntelliVAPT backend. */

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

/**
 * Make an authenticated API request.
 * Throws an Error with the server's detail message on non-OK responses.
 */
export async function request(
  path: string,
  token: string,
  options: RequestInit = {}
): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
    ...(options.headers as Record<string, string>),
  };

  const response = await fetch(`${API}${path}`, { ...options, headers });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(body.detail || "Request failed");
  }

  return response.status === 204 ? null : response.json();
}

/**
 * Perform a login request (no auth token required).
 */
export async function loginRequest(email: string, password: string) {
  const response = await fetch(`${API}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Login failed" }));
    throw new Error(body.detail || "Login failed");
  }

  return response.json();
}

/**
 * Download a report blob and trigger a browser download.
 */
export async function downloadReport(
  reportId: string,
  reportName: string,
  token: string
): Promise<void> {
  const response = await fetch(`${API}/api/reports/${reportId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    throw new Error("Report download failed");
  }

  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = `${reportName}.pdf`;
  link.click();
  URL.revokeObjectURL(url);
}
