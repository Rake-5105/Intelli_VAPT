/** Toast notification context and toast component. */
import { createContext, useContext, useState, type ReactNode } from "react";

export type ToastMessage = {
  id: string;
  type: "success" | "error" | "info";
  message: string;
};

type ToastContextValue = {
  toasts: ToastMessage[];
  addToast: (message: string, type?: "success" | "error" | "info") => void;
  removeToast: (id: string) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  function addToast(message: string, type: "success" | "error" | "info" = "info") {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      removeToast(id);
    }, 4000);
  }

  function removeToast(id: string) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
      <div className="toast-container" style={{ position: "fixed", bottom: 20, right: 20, zIndex: 9999, display: "grid", gap: 10 }}>
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast-${t.type}`}
            style={{
              background: "#282828",
              border: `1px solid ${t.type === "error" ? "#fb4934" : t.type === "success" ? "#b8bb26" : "#83a598"}`,
              color: "#ebdbb2",
              padding: "12px 18px",
              fontSize: "12px",
              borderRadius: "4px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              minWidth: "260px"
            }}
          >
            <span>{t.message}</span>
            <button
              onClick={() => removeToast(t.id)}
              style={{ background: "transparent", border: 0, color: "#a89984", cursor: "pointer", marginLeft: 10, fontSize: 14 }}
            >
              &times;
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
