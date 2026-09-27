/**
 * Reports generation and export page supporting PDF, CSV, and JSON formats.
 */
import { useEffect, useState } from "react";
import {
  FileText,
  Table,
  Code2,
  Download,
  Clock,
  RefreshCw,
  FolderKanban,
  CheckCircle,
} from "lucide-react";
import { request, downloadReport } from "../api";
import { useToast } from "../context/ToastContext";
import type { Project } from "../types";

type ReportItem = {
  id: string;
  name: string;
  format: string;
  created_at: string;
};

type ReportsProps = {
  selected?: Project | null;
  projects?: Project[];
  token?: string;
  onSelectProject?: (p: Project) => void;
  onGenerate?: () => void;
};

export function Reports({ selected, projects = [], token = "", onSelectProject, onGenerate }: ReportsProps) {
  const { addToast } = useToast();
  const [generatingFormat, setGeneratingFormat] = useState<string | null>(null);
  const [reportHistory, setReportHistory] = useState<ReportItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Active project ID
  const activeProject = selected || (projects.length > 0 ? projects[0] : null);

  // Load report history for active project
  const loadReports = async () => {
    if (!activeProject || !token) return;
    setLoadingHistory(true);
    try {
      const data: ReportItem[] = await request(`/api/projects/${activeProject.id}/reports`, token);
      setReportHistory(data || []);
    } catch (e) {
      console.warn("Could not load reports history:", e);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, [activeProject?.id, token]);

  // Handle generating and downloading report in specified format
  const handleGenerate = async (format: "PDF" | "CSV" | "JSON") => {
    if (!activeProject) {
      addToast("Please select a project first", "error");
      return;
    }

    if (!token && onGenerate) {
      onGenerate();
      return;
    }

    setGeneratingFormat(format);
    try {
      const report: ReportItem = await request(`/api/projects/${activeProject.id}/reports?format=${format}`, token, {
        method: "POST",
        body: JSON.stringify({ format }),
      });

      await downloadReport(report.id, report.name, token, format);
      addToast(`${format} report generated and downloaded successfully!`, "success");
      await loadReports();
    } catch (e) {
      addToast(e instanceof Error ? e.message : `Failed to generate ${format} report`, "error");
    } finally {
      setGeneratingFormat(null);
    }
  };

  const handleDownloadExisting = async (report: ReportItem) => {
    try {
      await downloadReport(report.id, report.name, token, report.format);
      addToast(`Downloaded ${report.name}`, "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Download failed", "error");
    }
  };

  return (
    <section className="panel" style={{ padding: "24px 28px" }}>
      {/* Header & Project Context */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, marginBottom: 20 }}>
        <div>
          <p className="eyebrow">CLIENT DELIVERABLES & EXPORTS</p>
          <h2 style={{ fontSize: 24, marginTop: 4 }}>Assessment Reports & Exports</h2>
          <p className="muted" style={{ fontSize: 14, marginTop: 4 }}>
            Generate executive compliance reports and raw machine-readable data feeds across PDF, CSV, and JSON formats.
          </p>
        </div>

        {/* Project Selector if multiple projects exist */}
        {projects.length > 0 && onSelectProject && (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <FolderKanban size={16} color="var(--accent)" />
            <select
              value={activeProject?.id || ""}
              onChange={(e) => {
                const p = projects.find((proj) => proj.id === e.target.value);
                if (p) onSelectProject(p);
              }}
              style={{
                padding: "8px 12px",
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                color: "var(--text-primary)",
                borderRadius: 4,
                fontSize: 14,
                fontWeight: 600,
              }}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.client || "Self"})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {activeProject ? (
        <>
          {/* Active Project Banner */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "12px 18px",
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              marginBottom: 24,
              fontSize: 14,
            }}
          >
            <div>
              <strong>Active Project:</strong> <span style={{ color: "var(--accent)" }}>{activeProject.name}</span>
              {activeProject.client && (
                <span style={{ marginLeft: 12, color: "var(--text-muted)" }}>
                  Client: {activeProject.client}
                </span>
              )}
            </div>
            <div style={{ color: "var(--text-muted)", fontSize: 13 }}>
              {activeProject.targets || 0} Targets · {activeProject.scans || 0} Scans Recorded
            </div>
          </div>

          {/* 3 Format Cards Grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: 20,
              marginBottom: 32,
            }}
          >
            {/* 1. PDF Report Card */}
            <div
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderTop: "3px solid #fb4934",
                borderRadius: 6,
                padding: 20,
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                boxShadow: "0 2px 8px rgba(0,0,0,0.04)",
              }}
            >
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ padding: 8, background: "rgba(251, 73, 52, 0.1)", borderRadius: 6, display: "flex" }}>
                      <FileText size={22} color="#fb4934" />
                    </div>
                    <h3 style={{ fontSize: 18, margin: 0 }}>PDF Report</h3>
                  </div>
                  <span
                    style={{
                      background: "rgba(251, 73, 52, 0.15)",
                      color: "#fb4934",
                      padding: "3px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    EXECUTIVE
                  </span>
                </div>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
                  Formal assessment report with executive risk posture charts, finding severity tables, and security compliance statements.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleGenerate("PDF")}
                disabled={generatingFormat === "PDF"}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  padding: "10px 14px",
                  fontSize: 14,
                  fontWeight: 600,
                  borderRadius: 4,
                  cursor: "pointer",
                }}
              >
                {generatingFormat === "PDF" ? <RefreshCw size={15} className="spin" /> : <Download size={15} />}
                {generatingFormat === "PDF" ? "Compiling PDF..." : "Download PDF"}
              </button>
            </div>

            {/* 2. CSV Spreadsheet Card */}
            <div
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderTop: "3px solid #b8bb26",
                borderRadius: 6,
                padding: 20,
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                boxShadow: "0 2px 8px rgba(0,0,0,0.04)",
              }}
            >
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ padding: 8, background: "rgba(184, 187, 38, 0.1)", borderRadius: 6, display: "flex" }}>
                      <Table size={22} color="#b8bb26" />
                    </div>
                    <h3 style={{ fontSize: 18, margin: 0 }}>CSV Spreadsheet</h3>
                  </div>
                  <span
                    style={{
                      background: "rgba(184, 187, 38, 0.15)",
                      color: "#b8bb26",
                      padding: "3px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    EXCEL / JIRA
                  </span>
                </div>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
                  Tabular spreadsheet containing all findings with CVSS scores, endpoints, CWE/CVE identifiers, and developer remediation notes.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleGenerate("CSV")}
                disabled={generatingFormat === "CSV"}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  padding: "10px 14px",
                  fontSize: 14,
                  fontWeight: 600,
                  borderRadius: 4,
                  cursor: "pointer",
                }}
              >
                {generatingFormat === "CSV" ? <RefreshCw size={15} className="spin" /> : <Download size={15} />}
                {generatingFormat === "CSV" ? "Exporting CSV..." : "Download CSV"}
              </button>
            </div>

            {/* 3. JSON Machine-Readable Card */}
            <div
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderTop: "3px solid #83a598",
                borderRadius: 6,
                padding: 20,
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                boxShadow: "0 2px 8px rgba(0,0,0,0.04)",
              }}
            >
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ padding: 8, background: "rgba(131, 165, 152, 0.1)", borderRadius: 6, display: "flex" }}>
                      <Code2 size={22} color="#83a598" />
                    </div>
                    <h3 style={{ fontSize: 18, margin: 0 }}>JSON Payload</h3>
                  </div>
                  <span
                    style={{
                      background: "rgba(131, 165, 152, 0.15)",
                      color: "#83a598",
                      padding: "3px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    API / SIEM
                  </span>
                </div>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
                  Complete structured data feed including project metadata, discovered host assets, technology stacks, and categorized vulnerabilities.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleGenerate("JSON")}
                disabled={generatingFormat === "JSON"}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  padding: "10px 14px",
                  fontSize: 14,
                  fontWeight: 600,
                  borderRadius: 4,
                  cursor: "pointer",
                }}
              >
                {generatingFormat === "JSON" ? <RefreshCw size={15} className="spin" /> : <Download size={15} />}
                {generatingFormat === "JSON" ? "Exporting JSON..." : "Download JSON"}
              </button>
            </div>
          </div>

          {/* Generated Reports History */}
          <div style={{ marginTop: 28 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h3 style={{ fontSize: 17, margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <Clock size={16} color="var(--accent)" /> Generated Reports Archive
              </h3>
              <button
                type="button"
                className="secondary"
                onClick={loadReports}
                disabled={loadingHistory}
                style={{ fontSize: 12, padding: "4px 8px", display: "flex", alignItems: "center", gap: 6 }}
              >
                <RefreshCw size={12} className={loadingHistory ? "spin" : ""} /> Refresh
              </button>
            </div>

            {reportHistory.length > 0 ? (
              <div
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "2.5fr 1fr 1.5fr 1fr",
                    padding: "10px 16px",
                    background: "var(--bg-tertiary)",
                    fontSize: 12,
                    fontWeight: 700,
                    color: "var(--text-muted)",
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  <span>REPORT NAME</span>
                  <span>FORMAT</span>
                  <span>GENERATED DATE</span>
                  <span style={{ textAlign: "right" }}>ACTION</span>
                </div>

                {reportHistory.map((r) => (
                  <div
                    key={r.id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "2.5fr 1fr 1.5fr 1fr",
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--border)",
                      fontSize: 13,
                      alignItems: "center",
                    }}
                  >
                    <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{r.name}</span>
                    <span>
                      <span
                        style={{
                          padding: "2px 8px",
                          borderRadius: 4,
                          fontSize: 11,
                          fontWeight: 700,
                          background:
                            r.format === "PDF"
                              ? "rgba(251, 73, 52, 0.15)"
                              : r.format === "CSV"
                              ? "rgba(184, 187, 38, 0.15)"
                              : "rgba(131, 165, 152, 0.15)",
                          color:
                            r.format === "PDF"
                              ? "#fb4934"
                              : r.format === "CSV"
                              ? "#b8bb26"
                              : "#83a598",
                        }}
                      >
                        {r.format}
                      </span>
                    </span>
                    <span style={{ color: "var(--text-muted)" }}>
                      {new Date(r.created_at).toLocaleString()}
                    </span>
                    <div style={{ textAlign: "right" }}>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => handleDownloadExisting(r)}
                        style={{ padding: "4px 10px", fontSize: 12, display: "inline-flex", alignItems: "center", gap: 4 }}
                      >
                        <Download size={12} /> Download
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  padding: 24,
                  background: "var(--bg-secondary)",
                  border: "1px dashed var(--border)",
                  borderRadius: 6,
                  textAlign: "center",
                  color: "var(--text-muted)",
                  fontSize: 14,
                }}
              >
                No reports generated yet for this project. Select a format above to create your first deliverable.
              </div>
            )}
          </div>
        </>
      ) : (
        <div
          style={{
            padding: 36,
            background: "var(--bg-secondary)",
            border: "1px dashed var(--border)",
            borderRadius: 6,
            textAlign: "center",
            color: "var(--text-muted)",
          }}
        >
          <FolderKanban size={32} style={{ marginBottom: 12, color: "var(--accent)" }} />
          <h3>No Project Selected</h3>
          <p style={{ marginTop: 6 }}>Please create or select a project from the Projects tab to generate assessment reports.</p>
        </div>
      )}
    </section>
  );
}
