/** Modal dialog to inspect and edit a finding's remediation status and notes. */
import { useState, type FormEvent } from "react";
import type { Finding } from "../types";

type FindingModalProps = {
  finding: Finding;
  onClose: () => void;
  onSave: (id: string, status: string, remediation: string) => Promise<void>;
};

export function FindingModal({ finding, onClose, onSave }: FindingModalProps) {
  const [status, setStatus] = useState(finding.status);
  const [remediation, setRemediation] = useState(finding.remediation || "");
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(finding.id, status, remediation);
      onClose();
    } finally {
      setSaving(false);
    }
  }

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "CRITICAL": return "#fb4934";
      case "HIGH": return "#fe8019";
      case "MEDIUM": return "#fabd2f";
      case "LOW": return "#b8bb26";
      default: return "#83a598";
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 640 }}>
        <div className="section-title">
          <div>
            <span style={{ fontSize: 15, fontWeight: 700, color: getSeverityColor(finding.severity) }}>
              [{finding.severity}] {finding.cvss_score ? `CVSS ${finding.cvss_score}` : ""}
            </span>
            <h2 style={{ fontSize: 20, marginTop: 4 }}>{finding.title}</h2>
          </div>
          <button type="button" className="secondary" onClick={onClose}>
            Close
          </button>
        </div>

        <div style={{ display: "grid", gap: 10, fontSize: 16, color: "var(--text-secondary)", background: "var(--bg-primary)", border: "1px solid var(--border)", padding: 14, borderRadius: 4 }}>
          <div><strong>Endpoint:</strong> <span style={{ color: "var(--info)" }}>{finding.endpoint}</span></div>
          {finding.cwe && <div><strong>CWE:</strong> {finding.cwe}</div>}
          {finding.cve && <div><strong>CVE:</strong> {finding.cve}</div>}
          <div><strong>Scanner Source:</strong> {finding.scanner}</div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14, marginTop: 10 }}>
          <label style={{ display: "grid", gap: 6, fontSize: 16 }}>
            Remediation Status
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              style={{ padding: 10, fontSize: 16, background: "var(--bg-secondary)", border: "1px solid var(--border)", color: "var(--text-primary)" }}
            >
              <option value="OPEN">OPEN (Unaddressed)</option>
              <option value="IN_PROGRESS">IN_PROGRESS (Fix in development)</option>
              <option value="REMEDIATED">REMEDIATED (Verified resolved)</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE (Not vulnerable)</option>
              <option value="ACCEPTED_RISK">ACCEPTED_RISK (Risk accepted by business)</option>
            </select>
          </label>

          <label style={{ display: "grid", gap: 6, fontSize: 16 }}>
            Remediation Notes / Fix Guidance
            <textarea
              rows={4}
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
              placeholder="Document the code fix, patch version, or developer instructions..."
              style={{ padding: 10, fontSize: 16, background: "var(--bg-secondary)", border: "1px solid var(--border)", color: "var(--text-primary)" }}
            />
          </label>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 10 }}>
            <button type="button" className="secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" disabled={saving}>
              {saving ? "Saving..." : "Update Finding"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
