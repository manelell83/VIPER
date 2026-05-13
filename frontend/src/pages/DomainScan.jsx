import { useState } from "react";
import { Play, Square, Search, Globe } from "lucide-react";
import ScanProgress from "../components/scan/ScanProgress";
import ScanResults from "../components/scan/ScanResults";
import { useScan } from "../hooks/useScan";

const EXAMPLES = ["scanme.nmap.org", "google.com", "192.168.1.1"];

export default function DomainScan() {
  const [target, setTarget] = useState("");
  const { status, progress, message, hosts, logs, error, startDomainScan, reset } = useScan();

  const isRunning = status === "running" || status === "starting";
  const hasStarted = status !== "idle";

  const handleStart = () => {
    if (!target.trim()) return;
    startDomainScan(target.trim());
  };

  const handleKey = (e) => {
    if (e.key === "Enter" && !isRunning) handleStart();
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-primary">Domain / IP Scan</h1>
        <p className="text-sm text-muted mt-1">
          Scan a domain name, hostname, or IP address
        </p>
      </div>

      {/* Target input */}
      <div className="card space-y-4">
        <div>
          <label className="text-sm font-medium text-secondary block mb-2">Target</label>
          <div className="relative">
            <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              className="input-field pl-9"
              placeholder="e.g. scanme.nmap.org or 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={handleKey}
              disabled={isRunning}
            />
          </div>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className="text-xs text-muted">Examples:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                className="text-xs px-2 py-0.5 rounded font-mono"
                style={{ background: "var(--color-bg-surface-hover)", color: "var(--color-text-tertiary)", border: "1px solid var(--color-border)" }}
                onClick={() => setTarget(ex)}
                disabled={isRunning}
              >
                {ex}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {!isRunning ? (
            <button
              className="btn-primary"
              disabled={!target.trim()}
              onClick={handleStart}
            >
              <Search size={15} />
              {hasStarted ? "Rescan" : "Scan Target"}
            </button>
          ) : (
            <button className="btn-danger" onClick={reset}>
              <Square size={15} />
              Stop
            </button>
          )}
          {hasStarted && !isRunning && (
            <button className="btn-secondary" onClick={reset}>
              New Scan
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      {hasStarted && (
        <div className="card">
          <h2 className="text-sm font-semibold text-primary mb-4">Scan Progress</h2>
          <ScanProgress
            status={status}
            progress={progress}
            message={message}
            logs={logs}
            error={error}
          />
        </div>
      )}

      {/* Results */}
      {hosts.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-primary mb-4">
            Results
            <span className="ml-2 badge badge-blue">{hosts.length}</span>
          </h2>
          <ScanResults hosts={hosts} />
        </div>
      )}
    </div>
  );
}
