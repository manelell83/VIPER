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
          {isRunning && <Loader size={16} className="animate-spin text-blue-500" />}
          {isDone && <CheckCircle size={16} className="text-green-500" />}
          {isFailed && <XCircle size={16} className="text-red-500" />}
          <span className={`text-sm font-medium ${
            isDone ? "text-success" : isFailed ? "text-danger" : "text-primary"
          }`}>
            {isDone ? "Scan Complete" : isFailed ? "Scan Failed" : message || "Initializing..."}
          </span>
        </div>
        <span className="text-xs text-muted font-mono">{progress}%</span>
      </div>

      <ProgressBar value={progress} animated={isRunning && progress === 0} />

      {error && (
        <div className="rounded-lg p-3 bg-red-500/10 border border-red-500/30 text-sm text-danger">
          {error}
        </div>
      )}

      {/* Live log terminal */}
      {logs.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--color-border)" }}>
          <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted"
            style={{ background: "var(--color-bg-elevated)", borderBottom: "1px solid var(--color-border)" }}>
            <Terminal size={12} />
            <span>Live Output</span>
          </div>
          <div
            className="p-3 h-40 overflow-y-auto font-mono text-xs space-y-0.5"
            style={{ background: "var(--color-bg-elevated)" }}
          >
            {logs.map((log, i) => (
              <p key={i} className="text-tertiary leading-relaxed">
                <span className="text-blue-500/50 select-none mr-2">›</span>{log}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
