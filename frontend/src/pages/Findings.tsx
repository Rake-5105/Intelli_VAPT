/** Vulnerability findings page with search, severity filter, status filter, CSV export, and editable remediation modal. */
import { useState } from "react";
import { Download, Edit3 } from "lucide-react";
import { FindingModal } from "../components/FindingModal";
import type { Finding } from "../types";

type FindingsProps = {
  findings: Finding[];
  onSaveFinding: (id: string, status: string, remediation: string) => Promise<void>;
  projectName?: string;
  onBack?: () => void;
};

export function Findings({ findings, onSaveFinding, projectName = "VAPT" }: FindingsProps) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [editingFinding, setEditingFinding] = useState<Finding | null>(null);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(search.toLowerCase()) ||
      (f.cwe && f.cwe.toLowerCase().includes(search.toLowerCase()));
    const matchesSeverity =
      severityFilter === "ALL" || f.severity === severityFilter;
    const matchesStatus =
      statusFilter === "ALL" || f.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  function exportCSV() {
    const headers = ["ID", "Title", "Severity", "CVSS", "Endpoint", "CWE", "CVE", "Status", "Scanner", "Remediation"];
    const rows = filteredFindings.map((f) => [
      `"${f.id}"`,
      `"${f.title.replace(/"/g, '""')}"`,
      `"${f.severity}"`,
      f.cvss_score,
      `"${f.endpoint.replace(/"/g, '""')}"`,
      `"${f.cwe || ""}"`,
      `"${f.cve || ""}"`,
      `"${f.status}"`,
      `"${f.scanner}"`,
      `"${(f.remediation || "").replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${projectName}_Findings_Export.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(filteredFindings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${projectName}_Findings_Export.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const getSeverityBadge = (sev: string) => {
    const color = sev === "CRITICAL" ? "#fb4934" : sev === "HIGH" ? "#fe8019" : sev === "MEDIUM" ? "#fabd2f" : "#b8bb26";
    return <span style={{ color, fontWeight: 700 }}>{sev}</span>;
  };

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="secondary" onClick={exportCSV} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
            <Download size={14} /> Export CSV
          </button>
          <button className="secondary" onClick={exportJSON} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
            <Download size={14} /> Export JSON
          </button>
        </div>
        <span className="muted">
          Showing {filteredFindings.length} of {findings.length} findings
        </span>
      </div>

      <div className="panel" style={{ marginBottom: 16, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <input
          type="text"
          placeholder="Search by title, endpoint, CWE..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 200, padding: 8, background: "#1d2021", border: "1px solid #504945", color: "#ebdbb2" }}
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ padding: 8, background: "#1d2021", border: "1px solid #504945", color: "#ebdbb2" }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Informational</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{ padding: 8, background: "#1d2021", border: "1px solid #504945", color: "#ebdbb2" }}
        >
          <option value="ALL">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="REMEDIATED">Remediated</option>
          <option value="FALSE_POSITIVE">False Positive</option>
          <option value="ACCEPTED_RISK">Accepted Risk</option>
        </select>
      </div>

      <section className="panel">
        <div className="table">
          <div className="table-row table-head" style={{ gridTemplateColumns: "1fr 2.5fr 2fr 0.8fr 1.2fr 0.8fr" }}>
            <span>Severity</span>
            <span>Finding</span>
            <span>Endpoint</span>
            <span>CVSS</span>
            <span>Status</span>
            <span>Action</span>
          </div>
          {filteredFindings.map((f) => (
            <div key={f.id} className="table-row" style={{ gridTemplateColumns: "1fr 2.5fr 2fr 0.8fr 1.2fr 0.8fr", alignItems: "center" }}>
              <span>{getSeverityBadge(f.severity)}</span>
              <span><strong>{f.title}</strong></span>
              <span style={{ color: "#83a598", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.endpoint}</span>
              <span>{f.cvss_score.toFixed(1)}</span>
              <span>
                <span style={{
                  fontSize: 10,
                  padding: "2px 6px",
                  borderRadius: 3,
                  border: `1px solid ${f.status === "REMEDIATED" ? "#b8bb26" : f.status === "IN_PROGRESS" ? "#fabd2f" : "#504945"}`,
                  color: f.status === "REMEDIATED" ? "#b8bb26" : f.status === "IN_PROGRESS" ? "#fabd2f" : "#d5c4a1"
                }}>
                  {f.status}
                </span>
              </span>
              <span>
                <button
                  className="secondary"
                  onClick={() => setEditingFinding(f)}
                  style={{ padding: "4px 8px", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                >
                  <Edit3 size={12} /> Edit
                </button>
              </span>
            </div>
          ))}
          {!filteredFindings.length && <p className="empty">No findings matched the selected criteria.</p>}
        </div>
      </section>

      {editingFinding && (
        <FindingModal
          finding={editingFinding}
          onClose={() => setEditingFinding(null)}
          onSave={onSaveFinding}
        />
      )}
    </>
  );
}
