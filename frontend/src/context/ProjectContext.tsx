/**
 * Project context — manages project list, selected project, and associated data.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { request } from "../api";
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

  // Poll active scan progress
  useEffect(() => {
    if (!activeScan) return;

    const poll = async () => {
      try {
        const scan = await request(`/api/scans/${activeScan.id}`, token);
        const log = await request(`/api/scans/${activeScan.id}/logs`, token);
        setActiveScan(scan);
        setScanLog(log.log);

        if (
          scan.status === "COMPLETED" ||
          scan.status === "CANCELLED" ||
          scan.status === "FAILED"
        ) {
          if (scan.status === "COMPLETED") {
            setNotice("Assessment completed. Generating and downloading final report...");
            try {
              const currentProjId = selected?.id || scan.project_id;
              if (currentProjId) {
                // Auto-generate and download report
                const report = await request(`/api/projects/${currentProjId}/reports`, token, {
                  method: "POST",
                  body: "{}",
                });
                const response = await fetch(`${import.meta.env.VITE_API_URL || "http://localhost:8000"}/api/reports/${report.id}/download`, {
                  headers: { Authorization: `Bearer ${token}` },
                });
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
            setNotice(`Scan ${scan.status.toLowerCase()}.`);
          }
          setActiveScan(null);
          await loadProjects();
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not update simulation");
        setActiveScan(null);
      }
    };

    poll();
    const timer = window.setInterval(poll, 1000);
    return () => window.clearInterval(timer);
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
