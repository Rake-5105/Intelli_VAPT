/**
 * Change Password Modal with live NIST/OWASP password strength meter.
 */
import { useState, type FormEvent } from "react";
import { Lock, Check, X, Shield, KeyRound, AlertCircle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

type ChangePasswordModalProps = {
  onClose: () => void;
};

export function ChangePasswordModal({ onClose }: ChangePasswordModalProps) {
  const { changePassword } = useAuth();
  const { addToast } = useToast();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Real-time strength checks
  const hasMinLength = newPassword.length >= 12;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(newPassword);
  const passwordsMatch = newPassword.length > 0 && newPassword === confirmPassword;

  const isFormValid =
    currentPassword.length > 0 &&
    hasMinLength &&
    hasUpper &&
    hasLower &&
    hasDigit &&
    hasSpecial &&
    passwordsMatch;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!isFormValid) return;

    setLoading(true);
    setError("");

    try {
      await changePassword(currentPassword, newPassword);
      addToast("Password changed successfully! All sessions updated.", "success");
      onClose();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to update password";
      setError(msg);
      addToast(msg, "error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0, 0, 0, 0.65)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
        padding: 16,
      }}
    >
      <div
        className="panel"
        style={{
          width: "100%",
          maxWidth: 480,
          background: "var(--bg-secondary)",
          borderRadius: 8,
          border: "1px solid var(--border)",
          padding: "24px 28px",
          boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ padding: 8, background: "rgba(254, 128, 25, 0.15)", borderRadius: 6, display: "flex" }}>
              <KeyRound size={20} color="var(--accent)" />
            </div>
            <div>
              <h3 style={{ fontSize: 18, margin: 0 }}>Change Account Password</h3>
              <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                Enforce OWASP / NIST defense standards
              </p>
            </div>
          </div>
          <button
            type="button"
            className="secondary"
            onClick={onClose}
            style={{ padding: "4px 8px", fontSize: 12 }}
          >
            ✕
          </button>
        </div>

        {error && (
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(251, 73, 52, 0.15)",
              border: "1px solid #fb4934",
              borderRadius: 6,
              color: "#fb4934",
              fontSize: 13,
              marginBottom: 16,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 14 }}>
            <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
              Current Password
            </label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
              style={{
                width: "100%",
                padding: "8px 12px",
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
                fontSize: 14,
              }}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
              New Password
            </label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="At least 12 characters with upper, lower, number, symbol"
              style={{
                width: "100%",
                padding: "8px 12px",
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
                fontSize: 14,
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
              Confirm New Password
            </label>
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-enter new password"
              style={{
                width: "100%",
                padding: "8px 12px",
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
                fontSize: 14,
              }}
            />
          </div>

          {/* Complexity Checklist */}
          <div
            style={{
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "12px 14px",
              marginBottom: 20,
              fontSize: 12,
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 8, color: "var(--text-secondary)" }}>
              Password Complexity Requirements:
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: hasMinLength ? "#b8bb26" : "var(--text-muted)" }}>
                {hasMinLength ? <Check size={13} /> : <X size={13} />} At least 12 characters
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: hasUpper ? "#b8bb26" : "var(--text-muted)" }}>
                {hasUpper ? <Check size={13} /> : <X size={13} />} One uppercase letter
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: hasLower ? "#b8bb26" : "var(--text-muted)" }}>
                {hasLower ? <Check size={13} /> : <X size={13} />} One lowercase letter
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: hasDigit ? "#b8bb26" : "var(--text-muted)" }}>
                {hasDigit ? <Check size={13} /> : <X size={13} />} One digit (0-9)
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: hasSpecial ? "#b8bb26" : "var(--text-muted)" }}>
                {hasSpecial ? <Check size={13} /> : <X size={13} />} One special symbol
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 6, color: passwordsMatch ? "#b8bb26" : "var(--text-muted)" }}>
                {passwordsMatch ? <Check size={13} /> : <X size={13} />} Passwords match
              </span>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
            <button
              type="button"
              className="secondary"
              onClick={onClose}
              style={{ padding: "8px 16px" }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!isFormValid || loading}
              style={{
                padding: "8px 20px",
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontWeight: 600,
                cursor: isFormValid ? "pointer" : "not-allowed",
                opacity: isFormValid ? 1 : 0.6,
              }}
            >
              <Lock size={14} />
              {loading ? "Updating..." : "Update Password"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
