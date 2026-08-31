/** Projects list and detail page with live Target management and exclusion toggle. */
import { Bug, CheckCircle, FileText, Play, Plus, Server, Slash, Target as TargetIcon, Trash2 } from "lucide-react";
import type { FormEvent } from "react";
import type { Project, ScanState, Target } from "../types";

type ProjectsProps = {
  projects: Project[];
  selected: Project | null;
  targets: Target[];
  onSelect: (p: Project) => void;
  onCreate: () => void;
  onTarget: (e: FormEvent<HTMLFormElement>) => void;
  onToggleTarget: (targetId: string) => void;
  onDeleteTarget: (targetId: string) => void;
  onScan: () => void;
  onAssets: () => void;
  onFindings: () => void;
  onReport: () => void;
  onDelete: () => void;
  scanLog: string;
  activeScan: ScanState | null;
};

export function Projects({
  projects,
  selected,
  targets,
  onSelect,
  onCreate,
  onTarget,
  onToggleTarget,
  onDeleteTarget,
  onScan,
  onAssets,
  onFindings,
  onReport,
  onDelete,
  scanLog,
  activeScan,
}: ProjectsProps) {
  return (
    <div className="projects-layout">
      {/* Project list sidebar */}
      <section className="panel project-list">
        <div className="section-title">
          <h2>All projects</h2>
          <button onClick={onCreate}>
            <Plus size={15} /> New
          </button>
        </div>
        {projects.map((p) => (
          <button
            className={
              selected?.id === p.id ? "project-row selected" : "project-row"
            }
            onClick={() => onSelect(p)}
            key={p.id}
          >
            <strong>{p.name}</strong>
            <small>
              {p.client || "No client"} | {p.targets} targets | {p.status}
            </small>
          </button>
        ))}
      </section>

      {/* Project detail */}
      <section className="panel">
        <>
          {selected ? (
            <>
              <p className="eyebrow">SELECTED PROJECT</p>
              <h2>{selected.name}</h2>
              <p className="muted">
                {selected.description || "No description provided."}
              </p>

              <div className="actions">
                <button onClick={onScan} disabled={!!activeScan}>
                  <Play size={15} />{" "}
                  {activeScan ? "Assessment Running" : "Launch Security Scan"}
                </button>
                <button className="secondary" onClick={onAssets}>
                  <Server size={15} /> Assets
                </button>
                <button className="secondary" onClick={onFindings}>
                  <Bug size={15} /> Findings
                </button>
                <button className="secondary" onClick={onReport}>
                  <FileText size={15} /> Report
                </button>
                <button className="danger" onClick={onDelete}>
                  Remove project
                </button>
              </div>

              {/* Targets List */}
              <div style={{ marginTop: 20, marginBottom: 20 }}>
                <h3 style={{ fontSize: 14, color: "#ebdbb2", marginBottom: 10 }}>
                  Authorized Scope Targets ({targets.length})
                </h3>
                <div style={{ display: "grid", gap: 8 }}>
                  {targets.map((t) => (
                    <div
                      key={t.id}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "8px 12px",
                        background: "#1d2021",
                        border: `1px solid ${t.excluded ? "#504945" : "#689d6a"}`,
                        borderRadius: 4,
                        opacity: t.excluded ? 0.6 : 1,
                      }}
                    >
                      <div>
                        <strong style={{ color: t.excluded ? "#a89984" : "#ebdbb2", fontSize: 13 }}>{t.value}</strong>
                        <span style={{ fontSize: 10, marginLeft: 8, color: "#83a598" }}>[{t.type}]</span>
                        {t.excluded && <span style={{ fontSize: 10, marginLeft: 8, color: "#fb4934" }}>(EXCLUDED FROM SCAN)</span>}
                      </div>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => onToggleTarget(t.id)}
                          style={{ fontSize: 11, padding: "4px 8px", display: "flex", alignItems: "center", gap: 4 }}
                        >
                          {t.excluded ? <CheckCircle size={12} color="#b8bb26" /> : <Slash size={12} color="#fabd2f" />}
                          {t.excluded ? "Include" : "Exclude"}
                        </button>
                        <button
                          type="button"
                          className="danger"
                          onClick={() => onDeleteTarget(t.id)}
                          style={{ fontSize: 11, padding: "4px 8px" }}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                  ))}
                  {!targets.length && <p className="empty" style={{ padding: 10 }}>No targets added yet. Add an in-scope target below to begin scanning.</p>}
                </div>
              </div>

              {/* Add target form */}
              <form className="target-form" onSubmit={onTarget}>
                <label>
                  Add Scope Target (Domain, URL, IP, or CIDR)
                  <input
                    name="target"
                    placeholder="example.com or https://api.example.com"
                    required
                  />
                </label>
                <button>
                  <TargetIcon size={15} /> Add target
                </button>
              </form>

              {activeScan && (
                <div className="progress">
                  <span>
                    {activeScan.status} {activeScan.progress}%
                  </span>
                  <i>
                    <b style={{ width: `${activeScan.progress}%` }} />
                  </i>
                </div>
              )}

              {scanLog && <pre className="scan-log">{scanLog}</pre>}
            </>
          ) : (
            <p className="empty">Select or create a project.</p>
          )}
        </>
      </section>
    </div>
  );
}
