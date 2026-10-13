import { Terminal, CheckCircle, XCircle, Loader } from "lucide-react";
import { ProgressBar } from "../ui/Loading";

export default function ScanProgress({ status, progress, message, logs = [], error }) {
  const isRunning = status === "running" || status === "starting";
  const isDone = status === "completed";
  const isFailed = status === "failed";

  return (
    <div className="space-y-4">
      {/* Status bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isRunning && <Loader size={16} className="animate-spin text-accent-text" />}
          {isDone && <CheckCircle size={16} className="text-success" />}
          {isFailed && <XCircle size={16} className="text-danger" />}
          <span className={`text-sm font-medium ${
            isDone ? "text-success" : isFailed ? "text-danger" : "text-primary"
          }`}>
            {isDone ? "Scan complete" : isFailed ? "Scan failed" : message || "Initializing..."}
          </span>
        </div>
        <span className="text-xs text-muted font-mono">{progress}%</span>
      </div>

      <ProgressBar value={progress} animated={isRunning && progress === 0} />

      {error && (
        <div role="alert" className="rounded-lg p-3 text-sm text-danger" style={{ background: "var(--accent-soft)", border: "1px solid var(--accent-line)" }}>
          {error}
        </div>
      )}

      {/* Live log terminal */}
      {logs.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--color-border)" }}>
          <div className="flex items-center gap-2 px-3 py-2 text-muted font-mono uppercase"
            style={{ fontSize: "0.68rem", letterSpacing: "0.1em", background: "var(--surface-2)", borderBottom: "1px solid var(--line)" }}>
            <Terminal size={12} />
            <span>Live output</span>
          </div>
          <div
            className="p-3 h-48 overflow-y-auto font-mono text-xs space-y-0.5"
            style={{ background: "var(--bg-sunken)" }}
            aria-live="polite"
          >
            {logs.map((log, i) => (
              <p key={i} className="text-tertiary leading-relaxed">
                <span className="text-accent-text select-none mr-2" aria-hidden="true">›</span>{log}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
