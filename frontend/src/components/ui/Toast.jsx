import { createContext, useContext, useState, useCallback, useEffect } from "react";
import { CheckCircle, AlertTriangle, XCircle, Info, X } from "lucide-react";

const ToastContext = createContext(null);

const ICONS = {
  success: CheckCircle,
  warning: AlertTriangle,
  error:   XCircle,
  info:    Info,
};

const COLORS = {
  success: "border-green-500 bg-green-500/10 text-green-400",
  warning: "border-yellow-500 bg-yellow-500/10 text-yellow-400",
  error:   "border-red-500 bg-red-500/10 text-red-400",
  info:    "border-blue-500 bg-blue-500/10 text-blue-400",
};

let _globalToast = null;

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside ToastProvider");
  return ctx;
}

function Toast({ toast, onRemove }) {
  const Icon = ICONS[toast.type] ?? Info;

  useEffect(() => {
    const t = setTimeout(() => onRemove(toast.id), toast.duration ?? 4000);
    return () => clearTimeout(t);
  }, [toast.id]);

  return (
    <div
      className={`flex items-start gap-3 px-4 py-3 rounded-lg border backdrop-blur-sm shadow-lg min-w-[280px] max-w-sm animate-slideIn ${COLORS[toast.type]}`}
    >
      <Icon size={16} className="mt-0.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        {toast.title && <p className="text-sm font-semibold">{toast.title}</p>}
        {toast.message && <p className="text-xs opacity-80 mt-0.5">{toast.message}</p>}
      </div>
      <button onClick={() => onRemove(toast.id)} className="flex-shrink-0 opacity-60 hover:opacity-100">
        <X size={14} />
      </button>
    </div>
  );
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const push = useCallback((type, title, message, duration) => {
    const id = crypto.randomUUID();
    setToasts((prev) => [...prev.slice(-4), { id, type, title, message, duration }]);
    return id;
  }, []);

  const remove = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = {
    success: (title, msg, dur) => push("success", title, msg, dur),
    error:   (title, msg, dur) => push("error",   title, msg, dur),
    warning: (title, msg, dur) => push("warning", title, msg, dur),
    info:    (title, msg, dur) => push("info",     title, msg, dur),
  };

  // Allow imperative usage from outside React tree
  _globalToast = toast;

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div key={t.id} className="pointer-events-auto">
            <Toast toast={t} onRemove={remove} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// Imperative helper (usable outside component tree)
export const toast = {
  success: (...a) => _globalToast?.success(...a),
  error:   (...a) => _globalToast?.error(...a),
  warning: (...a) => _globalToast?.warning(...a),
  info:    (...a) => _globalToast?.info(...a),
};
