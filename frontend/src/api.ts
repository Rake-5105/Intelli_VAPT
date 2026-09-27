/** API client with typed request helper and WebSocket support for IntelliVAPT backend. */

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_API = API.replace(/^http/, "ws");

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
 * Perform a registration request (no auth token required).
 */
export async function registerRequest(name: string, email: string, password: string) {
  const response = await fetch(`${API}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Registration failed" }));
    throw new Error(body.detail || "Registration failed");
  }

  return response.json();
}

/**
 * Perform a server-side logout request to revoke the JWT token.
 */
export async function logoutRequest(token: string): Promise<void> {
  if (!token) return;
  try {
    await fetch(`${API}/api/auth/logout`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    // Graceful degradation if backend is unreachable
  }
}

/**
 * Perform a password change request.
 */
export async function changePasswordRequest(
  currentPassword: string,
  newPassword: string,
  token: string
) {
  const response = await fetch(`${API}/api/auth/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Password update failed" }));
    throw new Error(body.detail || "Password update failed");
  }

  return response.json();
}

/**
 * Download a report blob and trigger a browser download.
 */
export async function downloadReport(
  reportId: string,
  reportName: string,
  token: string,
  format: string = "pdf"
): Promise<void> {
  const response = await fetch(`${API}/api/reports/${reportId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    throw new Error("Report download failed");
  }

  const ext = format.toLowerCase().replace(/^\./, "");
  let filename = reportName;
  if (!filename.toLowerCase().endsWith(`.${ext}`)) {
    filename = `${filename}.${ext}`;
  }

  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// WebSocket helpers for real-time scan streaming
// ---------------------------------------------------------------------------

export type ScanWSEvent = {
  event: "log" | "progress" | "status" | "finding" | "asset" | "stage";
  data: any;
};

export type ScanWSCallbacks = {
  onLog?: (message: string) => void;
  onProgress?: (progress: number, stage?: string) => void;
  onStatus?: (status: string) => void;
  onFinding?: (finding: any) => void;
  onAsset?: (asset: any) => void;
  onStage?: (stage: string, step: number, total: number) => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
};

/**
 * Create a WebSocket connection for real-time scan streaming.
 * Returns a close() function to tear down the connection.
 */
export function createScanWebSocket(
  scanId: string,
  callbacks: ScanWSCallbacks
): { close: () => void } {
  const url = `${WS_API}/ws/scans/${scanId}`;
  let ws: WebSocket | null = new WebSocket(url);
  let reconnectTimer: number | null = null;
  let closed = false;

  function connect() {
    if (closed) return;
    ws = new WebSocket(url);

    ws.onopen = () => {
      console.log(`[WS] Connected to scan ${scanId}`);
    };

    ws.onmessage = (evt) => {
      try {
        const event: ScanWSEvent = JSON.parse(evt.data);
        switch (event.event) {
          case "log":
            callbacks.onLog?.(event.data.message);
            break;
          case "progress":
            callbacks.onProgress?.(event.data.progress, event.data.stage);
            break;
          case "status":
            callbacks.onStatus?.(event.data.status);
            break;
          case "finding":
            callbacks.onFinding?.(event.data);
            break;
          case "asset":
            callbacks.onAsset?.(event.data);
            break;
          case "stage":
            callbacks.onStage?.(event.data.stage, event.data.step, event.data.total);
            break;
        }
      } catch (err) {
        console.warn("[WS] Failed to parse event:", err);
      }
    };

    ws.onclose = () => {
      if (!closed) {
        // Auto-reconnect after 2 seconds
        reconnectTimer = window.setTimeout(connect, 2000);
      }
      callbacks.onClose?.();
    };

    ws.onerror = (err) => {
      callbacks.onError?.(err);
    };
  }

  connect();

  return {
    close: () => {
      closed = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      ws?.close();
      ws = null;
    },
  };
}
