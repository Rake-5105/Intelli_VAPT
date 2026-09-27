/**
 * Security Audit Logs Page — Real-time immutable audit trail for security operations.
 */
import { useEffect, useState, useMemo } from "react";
import {
  ShieldAlert,
  RefreshCw,
  Search,
  Filter,
  User,
  Globe,
  Clock,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Lock,
  Radar,
  Trash2,
} from "lucide-react";
import { request } from "../api";
import { useToast } from "../context/ToastContext";
import type { AuditLog } from "../types";

type AuditLogsProps = {
  token: string;
};

export function AuditLogs({ token }: AuditLogsProps) {
  const { addToast } = useToast();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [actionCategory, setActionCategory] = useState<string>("ALL");

  const loadLogs = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const data: AuditLog[] = await request("/api/audit-logs?limit=200", token);
      setLogs(data || []);
    } catch (e) {
      addToast(e instanceof Error ? e.message : "Failed to load audit logs", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [token]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // Category filter
      if (actionCategory !== "ALL") {
        if (actionCategory === "AUTH" && !log.action.includes("LOGIN") && !log.action.includes("REGISTER") && !log.action.includes("LOGOUT") && !log.action.includes("PASSWORD")) {
          return false;
        }
        if (actionCategory === "SCANS" && !log.action.includes("SCAN")) {
          return false;
        }
        if (actionCategory === "PROJECTS" && !log.action.includes("PROJECT")) {
          return false;
        }
        if (actionCategory === "TARGETS" && !log.action.includes("TARGET")) {
          return false;
        }
        if (actionCategory === "REPORTS" && !log.action.includes("REPORT")) {
          return false;
        }
      }

      // Search term
      if (!searchTerm) return true;
      const term = searchTerm.toLowerCase();
      return (
        log.action.toLowerCase().includes(term) ||
        (log.user_email && log.user_email.toLowerCase().includes(term)) ||
        (log.ip_address && log.ip_address.toLowerCase().includes(term)) ||
        (log.detail && log.detail.toLowerCase().includes(term)) ||
        (log.resource_type && log.resource_type.toLowerCase().includes(term))
      );
    });
  }, [logs, actionCategory, searchTerm]);

  // Determine badge styling based on action severity
  const getActionBadge = (action: string) => {
    if (action.includes("FAILED") || action.includes("LOCKED") || action.includes("DELETE") || action.includes("CANCEL")) {
      return {
        bg: "rgba(251, 73, 52, 0.15)",
        color: "#fb4934",
        border: "1px solid rgba(251, 73, 52, 0.3)",
        icon: <AlertTriangle size={13} />,
      };
    }
    if (action.includes("PASSWORD") || action.includes("SCOPE") || action.includes("UPDATE")) {
      return {
        bg: "rgba(250, 189, 47, 0.15)",
        color: "#fabd2f",
        border: "1px solid rgba(250, 189, 47, 0.3)",
        icon: <Lock size={13} />,
      };
    }
    if (action.includes("CREATE") || action.includes("ADD") || action.includes("START")) {
      return {
        bg: "rgba(131, 165, 152, 0.15)",
        color: "#83a598",
        border: "1px solid rgba(131, 165, 152, 0.3)",
        icon: <Radar size={13} />,
      };
    }
    return {
      bg: "rgba(184, 187, 38, 0.15)",
      color: "#b8bb26",
      border: "1px solid rgba(184, 187, 38, 0.3)",
      icon: <CheckCircle2 size={13} />,
    };
  };

  return (
    <section className="panel" style={{ padding: "24px 28px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, marginBottom: 20 }}>
        <div>
          <p className="eyebrow">DEFENSE & COMPLIANCE TELEMETRY</p>
          <h2 style={{ fontSize: 24, marginTop: 4, display: "flex", alignItems: "center", gap: 10 }}>
            <ShieldAlert size={26} color="var(--accent)" /> Security Operations & Audit Trail
          </h2>
          <p className="muted" style={{ fontSize: 14, marginTop: 4 }}>
            Immutable forensic record of all user authentications, scan executions, scope modifications, and compliance exports.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "rgba(184, 187, 38, 0.12)",
              color: "#b8bb26",
              border: "1px solid rgba(184, 187, 38, 0.3)",
              padding: "6px 12px",
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: 0.5,
            }}
          >
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#b8bb26", display: "inline-block" }} />
            IMMUTABLE AUDIT LOG
          </span>

          <button
            type="button"
            className="secondary"
            onClick={loadLogs}
            disabled={loading}
            style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px" }}
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 16,
          background: "var(--bg-secondary)",
          padding: "14px 18px",
          borderRadius: 6,
          border: "1px solid var(--border)",
          marginBottom: 20,
        }}
      >
        {/* Category Pills */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 13, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4 }}>
            <Filter size={14} /> Filter:
          </span>
          {[
            { id: "ALL", label: "All Events" },
            { id: "AUTH", label: "Authentication" },
            { id: "SCANS", label: "Scans" },
            { id: "PROJECTS", label: "Projects" },
            { id: "TARGETS", label: "Targets & Scope" },
            { id: "REPORTS", label: "Reports" },
          ].map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => setActionCategory(cat.id)}
              style={{
                fontSize: 12,
                padding: "5px 12px",
                borderRadius: 4,
                cursor: "pointer",
                background: actionCategory === cat.id ? "var(--accent)" : "var(--bg-tertiary)",
                color: actionCategory === cat.id ? "#282828" : "var(--text-primary)",
                border: "1px solid var(--border)",
                fontWeight: actionCategory === cat.id ? 700 : 500,
              }}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 260 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              padding: "6px 12px",
              width: "100%",
            }}
          >
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search user, IP, or detail..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--text-primary)",
                fontSize: 13,
                width: "100%",
              }}
            />
          </div>
        </div>
      </div>

      {/* Log Entries Table */}
      {filteredLogs.length > 0 ? (
        <div style={{ overflowX: "auto", border: "1px solid var(--border)", borderRadius: 6 }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                <th style={{ padding: "12px 16px", fontWeight: 600 }}>ACTION</th>
                <th style={{ padding: "12px 16px", fontWeight: 600 }}>ACTOR</th>
                <th style={{ padding: "12px 16px", fontWeight: 600 }}>SOURCE IP</th>
                <th style={{ padding: "12px 16px", fontWeight: 600 }}>RESOURCE</th>
                <th style={{ padding: "12px 16px", fontWeight: 600 }}>DETAIL</th>
                <th style={{ padding: "12px 16px", fontWeight: 600, textAlign: "right" }}>TIMESTAMP</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log) => {
                const badge = getActionBadge(log.action);
                return (
                  <tr
                    key={log.id}
                    style={{
                      borderBottom: "1px solid var(--border)",
                      transition: "background 0.15s ease",
                    }}
                  >
                    <td style={{ padding: "12px 16px", whiteSpace: "nowrap" }}>
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          background: badge.bg,
                          color: badge.color,
                          border: badge.border,
                          padding: "3px 8px",
                          borderRadius: 4,
                          fontSize: 11,
                          fontWeight: 700,
                          letterSpacing: 0.5,
                        }}
                      >
                        {badge.icon}
                        {log.action}
                      </span>
                    </td>

                    <td style={{ padding: "12px 16px", whiteSpace: "nowrap" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <User size={14} color="var(--text-muted)" />
                        <span style={{ fontWeight: 600 }}>{log.user_email || "System"}</span>
                      </div>
                    </td>

                    <td style={{ padding: "12px 16px", whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-secondary)" }}>
                        <Globe size={13} color="var(--text-muted)" />
                        {log.ip_address || "Internal / Loopback"}
                      </div>
                    </td>

                    <td style={{ padding: "12px 16px", whiteSpace: "nowrap" }}>
                      <span
                        style={{
                          background: "var(--bg-tertiary)",
                          padding: "2px 6px",
                          borderRadius: 3,
                          fontSize: 11,
                          fontFamily: "monospace",
                          color: "var(--text-secondary)",
                          border: "1px solid var(--border)",
                        }}
                      >
                        {log.resource_type || "general"}
                      </span>
                    </td>

                    <td style={{ padding: "12px 16px", color: "var(--text-secondary)", maxWidth: 380, lineHeight: 1.4 }}>
                      {log.detail}
                    </td>

                    <td style={{ padding: "12px 16px", textAlign: "right", whiteSpace: "nowrap", color: "var(--text-muted)", fontSize: 12 }}>
                      <div style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                        <Clock size={12} />
                        {new Date(log.created_at).toLocaleString()}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          style={{
            textAlign: "center",
            padding: "48px 24px",
            background: "var(--bg-secondary)",
            borderRadius: 6,
            border: "1px dashed var(--border)",
            color: "var(--text-muted)",
          }}
        >
          <ShieldAlert size={36} color="var(--text-muted)" style={{ marginBottom: 12, opacity: 0.5 }} />
          <h4 style={{ fontSize: 16, marginBottom: 6 }}>No Audit Events Found</h4>
          <p style={{ fontSize: 13 }}>
            {searchTerm || actionCategory !== "ALL"
              ? "No events match the selected criteria. Try adjusting your filters."
              : "Security audit events will be automatically recorded as users authenticate, run scans, and export deliverables."}
          </p>
        </div>
      )}
    </section>
  );
}
