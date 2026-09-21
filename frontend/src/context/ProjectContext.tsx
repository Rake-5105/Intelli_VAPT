/**
 * Project context — manages project list, selected project, and associated data.
 * Uses WebSocket for real-time scan streaming instead of HTTP polling.
 */
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { createScanWebSocket, request } from "../api";
import { useAuth } from "./AuthContext";
import type { Asset, Finding, Project, ScanState, Surface, Target, View } from "../types";

type ProjectContextValue = {
  projects: Project[];
  selected: Project | null;
  targets: Target[];
  assets: Asset[];
  findings: Finding[];
  surface: Surface;
  scanLog: string;
  activeScan: ScanState | null;
  view: View;
  error: string;
  notice: string;
  showCreate: boolean;

  /** Live counters updated via WebSocket during scans */
  liveAssetCount: number;
  liveFindingCount: number;
  scanStage: string;

  setSelected: (p: Project | null) => void;
  setView: (v: View) => void;
  setError: (msg: string) => void;
  setNotice: (msg: string) => void;
  setShowCreate: (show: boolean) => void;
  loadProjects: () => Promise<void>;
  loadProjectData: () => Promise<void>;
  setActiveScan: (s: ScanState | null) => void;
  setScanLog: (log: string) => void;
};

const ProjectContext = createContext<ProjectContextValue | null>(null);

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { token } = useAuth();

  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [surface, setSurface] = useState<Surface>({ nodes: [], edges: [] });
  const [scanLog, setScanLog] = useState("");
  const [activeScan, setActiveScan] = useState<ScanState | null>(null);
  const [view, setView] = useState<View>("overview");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  // Real-time counters from WebSocket
  const [liveAssetCount, setLiveAssetCount] = useState(0);
  const [liveFindingCount, setLiveFindingCount] = useState(0);
  const [scanStage, setScanStage] = useState("");

  // WebSocket close handle
  const wsRef = useRef<{ close: () => void } | null>(null);

  // Load project list
  async function loadProjects() {
    try {
      const data = await request("/api/projects", token);
      setProjects(data);
      setSelected((current) =>
        data.find((p: Project) => p.id === current?.id) || current || data[0] || null
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load projects");
    }
  }

  useEffect(() => {
    if (token) loadProjects();
  }, [token]);

  // Load project-specific data when selection changes
  async function loadProjectData() {
    if (!selected || !token) return;
    try {
      const [t, a, f, s] = await Promise.all([
        request(`/api/projects/${selected.id}/targets`, token),
        request(`/api/projects/${selected.id}/assets`, token),
        request(`/api/projects/${selected.id}/vulnerabilities`, token),
        request(`/api/projects/${selected.id}/attack-surface`, token),
      ]);
      setTargets(t);
      setAssets(a);
      setFindings(f);
      setSurface(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load project data");
    }
  }

  useEffect(() => {
    loadProjectData();
  }, [selected?.id, token]);

  // -------------------------------------------------------------------------
  // WebSocket-based real-time scan streaming
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!activeScan) {
      // Clean up any existing WebSocket
      wsRef.current?.close();
      wsRef.current = null;
      return;
    }

    // Reset live counters
    setLiveAssetCount(0);
    setLiveFindingCount(0);
    setScanStage("");
    setScanLog("");

    // Also do an initial HTTP fetch to get any logs that were written
    // before the WebSocket connected
    (async () => {
      try {
        const log = await request(`/api/scans/${activeScan.id}/logs`, token);
        if (log.log) setScanLog(log.log);
      } catch {
        // Ignore — WS will deliver logs going forward
      }
    })();

    const ws = createScanWebSocket(activeScan.id, {
      onLog: (message) => {
        setScanLog((prev) => prev + message + "\n");
      },
      onProgress: (progress) => {
        setActiveScan((prev) => prev ? { ...prev, progress } : prev);
      },
      onStatus: async (status) => {
        setActiveScan((prev) => prev ? { ...prev, status } : prev);

        if (status === "COMPLETED" || status === "CANCELLED" || status === "FAILED") {
          if (status === "COMPLETED") {
            setNotice("Assessment completed. Generating and downloading final report...");
            try {
              const currentProjId = selected?.id;
              if (currentProjId) {
                const report = await request(`/api/projects/${currentProjId}/reports`, token, {
                  method: "POST",
                  body: "{}",
                });
                const response = await fetch(
                  `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/api/reports/${report.id}/download`,
                  { headers: { Authorization: `Bearer ${token}` } }
                );
                if (response.ok) {
                  const blob = await response.blob();
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `${report.name}.pdf`;
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  URL.revokeObjectURL(url);
                }
              }
            } catch (err) {
              console.error("Auto report generation failed:", err);
            }
          } else {
            setNotice(`Scan ${status.toLowerCase()}.`);
          }

          // Close WebSocket and refresh data
          wsRef.current?.close();
          wsRef.current = null;
          setActiveScan(null);
          setScanStage("");
          await loadProjects();
          await loadProjectData();
        }
      },
      onFinding: () => {
        setLiveFindingCount((c) => c + 1);
      },
      onAsset: () => {
        setLiveAssetCount((c) => c + 1);
      },
      onStage: (stage) => {
        setScanStage(stage);
      },
    });

    wsRef.current = ws;

    return () => {
      ws.close();
    };
  }, [activeScan?.id]);

  return (
    <ProjectContext.Provider
      value={{
        projects,
        selected,
        targets,
        assets,
        findings,
        surface,
        scanLog,
        activeScan,
        view,
        error,
        notice,
        showCreate,
        liveAssetCount,
        liveFindingCount,
        scanStage,
        setSelected,
        setView,
        setError,
        setNotice,
        setShowCreate,
        loadProjects,
        loadProjectData,
        setActiveScan,
        setScanLog,
      }}
    >
      {children}
    </ProjectContext.Provider>
  );
}

export function useProject(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error("useProject must be used within ProjectProvider");
  return ctx;
}
