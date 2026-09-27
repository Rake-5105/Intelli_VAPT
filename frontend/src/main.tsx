/**
 * IntelliVAPT — Application entry point.
 */
import { FormEvent, useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { Activity, FolderKanban, Radar, ShieldCheck, Sun, Moon, ScrollText, KeyRound, LogOut, User as UserIcon } from "lucide-react";

import { AuthProvider, useAuth } from "./context/AuthContext";
import { ProjectProvider, useProject } from "./context/ProjectContext";
import { ToastProvider, useToast } from "./context/ToastContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { request, downloadReport } from "./api";

import { Nav } from "./components/Nav";
import { CreateProjectModal } from "./components/CreateProjectModal";
import { ChangePasswordModal } from "./components/ChangePasswordModal";

import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Projects } from "./pages/Projects";
import { Assets } from "./pages/Assets";
import { Findings } from "./pages/Findings";
import { Surface } from "./pages/Surface";
import { Remediation } from "./pages/Remediation";
import { Reports } from "./pages/Reports";
import { AuditLogs } from "./pages/AuditLogs";

import type { View } from "./types";
import "./styles.css";

function AppShell() {
  const { token, user, loading, login, register, logout } = useAuth();
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
  const [showChangePassword, setShowChangePassword] = useState(false);

  // Persistent Theme State (Dark / Light)
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      const saved = localStorage.getItem("intellivapt-theme");
      return saved === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.body.setAttribute("data-theme", theme);
    if (theme === "light") {
      document.body.classList.add("light-theme");
    } else {
      document.body.classList.remove("light-theme");
    }
    try {
      localStorage.setItem("intellivapt-theme", theme);
    } catch {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

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

  async function handleRegister(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    try {
      await register(
        fd.get("name") as string,
        fd.get("email") as string,
        fd.get("password") as string
      );
      addToast("Account created successfully! Welcome to IntelliVAPT.", "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Registration failed", "error");
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

  if (loading) {
    return (
      <main className="auth-page">
        <div style={{ textAlign: "center", color: "var(--accent)" }}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="pulse-icon">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <p style={{ marginTop: 12, fontSize: 14, color: "var(--text-muted)" }}>Verifying session…</p>
        </div>
      </main>
    );
  }

  if (!token) return <Login onLogin={handleLogin} onRegister={handleRegister} error="" />;

  const activeTitle: Record<View, string> = {
    overview: "Assessment dashboard",
    projects: "Projects",
    surface: "Attack surface",
    assets: "Asset inventory",
    findings: "Vulnerabilities",
    remediation: "Remediation",
    reports: "Reports",
    audit: "Security audit trail",
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
          <Nav
            icon={<ScrollText />}
            label="Audit Trail"
            active={view === "audit"}
            onClick={() => go("audit")}
          />
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-identity">
            <div className="user-header">
              <div className="user-avatar" title={user?.name || "Security Administrator"}>
                <UserIcon size={16} />
              </div>
              <div className="user-badge">
                <span className="user-name">{user?.name || "Security Administrator"}</span>
                <span className="role-pill">{user?.role || "ADMIN"}</span>
              </div>
            </div>
            <div className="sidebar-actions">
              <button
                type="button"
                className="action-btn"
                onClick={() => setShowChangePassword(true)}
                title="Change Password"
              >
                <KeyRound size={13} /> Password
              </button>
              <button
                type="button"
                className="logout-btn"
                onClick={logout}
                title="Logout"
              >
                <LogOut size={13} /> Logout
              </button>
            </div>
          </div>
          <footer>
            INTELLIVAPT SUITE
            <br />
            <small>Automated Security Assessment</small>
          </footer>
        </div>
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
          <div className="header-right">
            <button
              className="theme-toggle-btn"
              onClick={toggleTheme}
              title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
              aria-label="Toggle Theme"
            >
              {theme === "dark" ? (
                <>
                  <Sun size={16} className="theme-icon sun" />
                  <span>Light Mode</span>
                </>
              ) : (
                <>
                  <Moon size={16} className="theme-icon moon" />
                  <span>Dark Mode</span>
                </>
              )}
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
            liveAssetCount={ctx.liveAssetCount}
            liveFindingCount={ctx.liveFindingCount}
            scanStage={ctx.scanStage}
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
            selected={selected}
            projects={projects}
            token={token}
            onSelectProject={(p) => setSelected(p)}
            onGenerate={generateReport}
          />
        )}

        {view === "audit" && <AuditLogs token={token} />}

        {showChangePassword && (
          <ChangePasswordModal onClose={() => setShowChangePassword(false)} />
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
