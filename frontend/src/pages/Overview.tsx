/** Overview dashboard page with severity charts and posture summary. */
import { Plus } from "lucide-react";
import { Metric } from "../components/Metric";
import type { Finding, Project } from "../types";

type OverviewProps = {
  projects: Project[];
  findings: Finding[];
  onCreate: () => void;
  onViewProjects: () => void;
};

export function Overview({ projects, findings, onCreate, onViewProjects }: OverviewProps) {
  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
  const medium = findings.filter((f) => f.severity === "MEDIUM").length;
  const low = findings.filter((f) => f.severity === "LOW").length;
  const totalFindings = findings.length || 1;

  return (
    <>
      <section className="metrics">
        <Metric label="Projects" value={projects.length} />
        <Metric
          label="Authorized targets"
          value={projects.reduce((n, p) => n + p.targets, 0)}
        />
        <Metric
          label="Open findings"
          value={findings.filter((f) => f.status !== "REMEDIATED").length}
        />
        <Metric
          label="Critical findings"
          value={critical}
          alert={critical > 0}
        />
      </section>

      {/* Severity distribution posture bar */}
      <section className="panel" style={{ marginBottom: 20 }}>
        <p className="eyebrow">RISK POSTURE</p>
        <h2 style={{ margin: "6px 0 14px" }}>Vulnerability Severity Distribution</h2>
        
        <div style={{ height: 18, display: "flex", borderRadius: 4, overflow: "hidden", background: "#1d2021", border: "1px solid #504945" }}>
          {critical > 0 && <div title={`Critical: ${critical}`} style={{ width: `${(critical / totalFindings) * 100}%`, background: "#fb4934" }} />}
          {high > 0 && <div title={`High: ${high}`} style={{ width: `${(high / totalFindings) * 100}%`, background: "#fe8019" }} />}
          {medium > 0 && <div title={`Medium: ${medium}`} style={{ width: `${(medium / totalFindings) * 100}%`, background: "#fabd2f" }} />}
          {low > 0 && <div title={`Low: ${low}`} style={{ width: `${(low / totalFindings) * 100}%`, background: "#b8bb26" }} />}
        </div>

        <div style={{ display: "flex", gap: 20, marginTop: 12, fontSize: 12 }}>
          <span><b style={{ color: "#fb4934" }}>■</b> Critical ({critical})</span>
          <span><b style={{ color: "#fe8019" }}>■</b> High ({high})</span>
          <span><b style={{ color: "#fabd2f" }}>■</b> Medium ({medium})</span>
          <span><b style={{ color: "#b8bb26" }}>■</b> Low ({low})</span>
        </div>
      </section>

      <section className="panel">
        <div className="section-title">
          <div>
            <p className="eyebrow">WORKSPACE</p>
            <h2>Start an assessment</h2>
          </div>
          <button onClick={onCreate}>
            <Plus size={15} /> New project
          </button>
        </div>
        <p className="empty">
          Create a project, define its explicitly authorized scope, then use the
          project actions to run a safe demo scan.
        </p>
        <button className="secondary" onClick={onViewProjects}>
          Open projects
        </button>
      </section>
    </>
  );
}
