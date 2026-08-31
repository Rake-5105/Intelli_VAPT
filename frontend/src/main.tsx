/**
 * IntelliVAPT — Application entry point.
 */
import { FormEvent, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, FolderKanban, Radar, ShieldCheck } from "lucide-react";

import { AuthProvider, useAuth } from "./context/AuthContext";
import { ProjectProvider, useProject } from "./context/ProjectContext";
import { ToastProvider, useToast } from "./context/ToastContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { request, downloadReport } from "./api";

import { Nav } from "./components/Nav";
import { CreateProjectModal } from "./components/CreateProjectModal";

import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Projects } from "./pages/Projects";
import { Assets } from "./pages/Assets";
import { Findings } from "./pages/Findings";
import { Surface } from "./pages/Surface";
import { Remediation } from "./pages/Remediation";
import { Reports } from "./pages/Reports";

import type { View } from "./types";
import "./styles.css";

function AppShell() {
  const { token, user, login, logout } = useAuth();
  const { addToast } = useToast();
  const ctx = useProject();
  const {
    projects,
    selected,
    targets,
    assets,
    findings,
    surface,
    scanLog,
    activeScan,
    view,
    showCreate,
    setSelected,
    setView,
    setShowCreate,
    loadProjects,
    loadProjectData,
    setActiveScan,
    setScanLog,
  } = ctx;

  const [confirmDelete, setConfirmDelete] = useState(false);

  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    try {
      await login(fd.get("email") as string, fd.get("password") as string);
      addToast("Successfully signed in", "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Login failed", "error");
    }
  }

  async function createProject(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    try {
      const project = await request("/api/projects", token, {
        method: "POST",
        body: JSON.stringify({
          name: fd.get("name"),
          client: fd.get("client"),
          description: fd.get("description"),
        }),
      });
      setSelected(project);
      setView("projects");
      setShowCreate(false);
      addToast("Project created. Add an authorized target to begin.", "success");
      await loadProjects();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not create project", "error");
    }
  }

  async function addTarget(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selected) return;
    const fd = new FormData(e.currentTarget);
    try {
      await request(`/api/projects/${selected.id}/targets`, token, {
        method: "POST",
        body: JSON.stringify({ value: fd.get("target") }),
      });
      addToast("Authorized target added.", "success");
      await loadProjectData();
      await loadProjects();
      (e.target as HTMLFormElement).reset();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not add target", "error");
    }
  }

  async function toggleTarget(targetId: string) {
    if (!selected) return;
    try {
      await request(`/api/projects/${selected.id}/targets/${targetId}/toggle`, token, {
        method: "PATCH",
      });
      addToast("Target scope updated.", "info");
      await loadProjectData();
      await loadProjects();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not toggle target", "error");
    }
  }

  async function deleteTarget(targetId: string) {
    if (!selected) return;
    try {
      await request(`/api/projects/${selected.id}/targets/${targetId}`, token, {
        method: "DELETE",
      });
      addToast("Target removed from scope.", "info");
      await loadProjectData();
      await loadProjects();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not remove target", "error");
    }
  }

  async function startScan() {
    if (!selected || activeScan) return;
    try {
      const scan = await request(`/api/projects/${selected.id}/scans`, token, {
        method: "POST",
        body: JSON.stringify({ profile: "SAFE" }),
      });
      setActiveScan(scan);
      setScanLog("[assessment] Security assessment queued.\n");
      addToast("Assessment started across in-scope targets.", "info");
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not start scan", "error");
    }
  }

  async function saveFinding(id: string, status: string, remediation: string) {
    try {
      await request(`/api/vulnerabilities/${id}`, token, {
        method: "PATCH",
        body: JSON.stringify({ finding_status: status, remediation }),
      });
      addToast("Finding remediation updated.", "success");
      await loadProjectData();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not update finding", "error");
    }
  }

  async function generateReport() {
    if (!selected) return;
    try {
      const report = await request(`/api/projects/${selected.id}/reports`, token, {
        method: "POST",
        body: "{}",
      });
      await downloadReport(report.id, report.name, token);
      addToast("PDF report generated and downloaded.", "success");
      setView("reports");
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not generate report", "error");
    }
  }

  async function deleteProject() {
    if (!selected) return;
    try {
      await request(`/api/projects/${selected.id}`, token, { method: "DELETE" });
      setSelected(null);
      setConfirmDelete(false);
      setView("projects");
      addToast("Project removed.", "info");
      await loadProjects();
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Could not remove project", "error");
    }
  }

  function go(next: View) {
    setView(next);
  }

  if (!token) return <Login onSubmit={handleLogin} error="" />;

  const activeTitle: Record<View, string> = {
    overview: "Assessment dashboard",
    projects: "Projects",
    surface: "Attack surface",
    assets: "Asset inventory",
    findings: "Vulnerabilities",
    remediation: "Remediation",
    reports: "Reports",
  };

  return (
    <div className="shell">
      <aside>
        <h2>
          <ShieldCheck size={20} /> IntelliVAPT
        </h2>
        <nav>
          <Nav
            icon={<Activity />}
            label="Overview"
            active={view === "overview"}
            onClick={() => go("overview")}
          />
          <Nav
            icon={<FolderKanban />}
            label="Projects"
            active={view === "projects"}
            onClick={() => go("projects")}
          />
          <Nav
            icon={<Radar />}
            label="Attack Surface"
            active={view === "surface"}
            onClick={() => go("surface")}
          />
        </nav>
        <footer>
          INTELLIVAPT SUITE
          <br />
          <small>Automated Security Assessment</small>
        </footer>
      </aside>

      <main>
        <header>
          <div className="header-left">
            {view !== "overview" && view !== "projects" && (
              <button className="btn-back" onClick={() => go("projects")}>
                ← Back
              </button>
            )}
            <div>
              <p className="eyebrow">SECURITY OPERATIONS</p>
              <h1>{activeTitle[view]}</h1>
            </div>
          </div>
          <div className="identity">
            <div className="user-badge">
              <span>{user?.name || "Analyst"}</span>
              <span className="role-pill">{user?.role || "SECURITY_ANALYST"}</span>
            </div>
            <button className="logout" onClick={logout}>
              Logout
            </button>
          </div>
        </header>

        {view === "overview" && (
          <Overview
            projects={projects}
            findings={findings}
            onCreate={() => setShowCreate(true)}
            onViewProjects={() => go("projects")}
          />
        )}

        {view === "projects" && (
          <Projects
            projects={projects}
            selected={selected}
            targets={targets}
            onSelect={(p) => {
              setSelected(p);
            }}
            onCreate={() => setShowCreate(true)}
            onTarget={addTarget}
            onToggleTarget={toggleTarget}
            onDeleteTarget={deleteTarget}
            onScan={startScan}
            onAssets={() => go("assets")}
            onFindings={() => go("findings")}
            onReport={generateReport}
            onDelete={() => setConfirmDelete(true)}
            scanLog={scanLog}
            activeScan={activeScan}
          />
        )}

        {view === "assets" && (
          <Assets assets={assets} />
        )}

        {view === "findings" && (
          <Findings
            findings={findings}
            onSaveFinding={saveFinding}
            projectName={selected?.name || "Project"}
          />
        )}

        {view === "surface" && <Surface surface={surface} />}

        {view === "remediation" && <Remediation findings={findings} />}

        {view === "reports" && (
          <Reports
            onGenerate={generateReport}
          />
        )}

        {showCreate && (
          <CreateProjectModal
            onClose={() => setShowCreate(false)}
            onSubmit={createProject}
          />
        )}

        {confirmDelete && selected && (
          <ConfirmDialog
            title="Remove Project"
            message={`Are you sure you want to permanently delete "${selected.name}" and all of its associated scan logs, assets, and findings? This action cannot be undone.`}
            confirmLabel="Delete Project"
            onConfirm={deleteProject}
            onCancel={() => setConfirmDelete(false)}
          />
        )}
      </main>
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ToastProvider>
          <ProjectProvider>
            <AppShell />
          </ProjectProvider>
        </ToastProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
