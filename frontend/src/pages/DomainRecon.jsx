import { useState } from "react";
import { Search, Globe, Loader2 } from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import ReconResult from "../components/recon/ReconResult";
import { useRecon } from "../hooks/useRecon";

const EXAMPLES = ["nmap.org", "iana.org", "example.com"];

export default function DomainRecon() {
  const [target, setTarget] = useState("");
  const { status, progress, message, logs, result, error, startRecon, reset } = useRecon();

  const isRunning = status === "starting" || status === "running";
  const hasStarted = status !== "idle";

  const start = () => { if (target.trim() && !isRunning) startRecon(target.trim()); };
  const onKey = (e) => { if (e.key === "Enter") start(); };

  return (
    <div className="max-w-5xl space-y-6 animate-fadeIn">
      <PageHeader
        eyebrow="Recon"
        title="Domain recon"
        subtitle="Passive OSINT on a domain: DNS, registration (RDAP/WHOIS), subdomains from Certificate Transparency, and a light web fingerprint. No active scanning."
      />

      <div className="card space-y-4">
        <div>
          <label className="text-sm font-medium text-secondary block mb-2">Domain</label>
          <div className="relative">
            <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              className="input-field pl-9"
              placeholder="e.g. example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={onKey}
              disabled={isRunning}
            />
          </div>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className="text-xs text-muted">Examples:</span>
            {EXAMPLES.map((ex) => (
              <button key={ex} onClick={() => setTarget(ex)} disabled={isRunning}
                      className="text-xs link font-mono disabled:opacity-50">{ex}</button>
            ))}
          </div>
          <p className="text-xs text-tertiary mt-2">
            Recon reads only public data and visits the site once, like a browser. It does not require
            scan authorization because it does not actively scan the target.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button onClick={start} disabled={!target.trim() || isRunning} className="btn-primary">
            {isRunning ? <Loader2 size={15} className="animate-spin" /> : <Search size={15} />}
            {isRunning ? "Running…" : "Start recon"}
          </button>
          {hasStarted && !isRunning && (
            <button onClick={() => { reset(); setTarget(""); }} className="btn-secondary">New recon</button>
          )}
        </div>
      </div>

      {isRunning && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-secondary">{message || "Starting…"}</span>
            <span className="font-mono text-muted">{progress}%</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--surface-2)" }}>
            <div className="h-full rounded-full transition-all duration-500"
                 style={{ width: `${progress}%`, background: "var(--accent)" }} />
          </div>
          <pre className="text-xs text-muted max-h-40 overflow-y-auto font-mono whitespace-pre-wrap">
            {logs.slice(-12).join("\n")}
          </pre>
        </div>
      )}

      {error && (
        <div role="alert" className="card border-danger">
          <p className="text-sm text-danger">{error}</p>
        </div>
      )}

      {status === "completed" && result && <ReconResult result={result} />}
    </div>
  );
}
