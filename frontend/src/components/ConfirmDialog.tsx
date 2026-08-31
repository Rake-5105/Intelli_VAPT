/** Modal confirmation dialog replacing window.confirm(). */
import { AlertTriangle } from "lucide-react";

type ConfirmDialogProps = {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  isDanger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  isDanger = true,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <div className="modal-backdrop">
      <div className="modal">
        <div className="section-title">
          <h2 style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {isDanger && <AlertTriangle size={18} color="#fb4934" />}
            {title}
          </h2>
          <button type="button" className="secondary" onClick={onCancel}>
            Close
          </button>
        </div>
        <p className="muted" style={{ fontSize: 13, margin: "10px 0" }}>
          {message}
        </p>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 15 }}>
          <button type="button" className="secondary" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={isDanger ? "danger" : ""}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
