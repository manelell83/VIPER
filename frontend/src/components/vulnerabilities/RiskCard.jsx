import { AlertTriangle, Shield, TrendingUp } from "lucide-react";
import { SEVERITY_CONFIG } from "./SeverityBadge";

const LEVEL_COLORS = {
  CRITICAL: "border-red-500/50 bg-red-500/5",
  HIGH:     "border-orange-500/50 bg-orange-500/5",
  MEDIUM:   "border-yellow-500/50 bg-yellow-500/5",
  LOW:      "border-blue-500/50 bg-blue-500/5",
  NONE:     "border-[var(--color-border)] bg-transparent",
};

export default function RiskCard({ network }) {
  if (!network) return null;
  const { network_score = 0, level = "NONE", total_vulns = 0, critical_hosts = 0, high_hosts = 0 } = network;
  const cfg = SEVERITY_CONFIG[level] ?? SEVERITY_CONFIG.NONE;

  return (
    <div className={`rounded-2xl p-5 border ${LEVEL_COLORS[level]}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield size={18} className={cfg.className.split(" ")[1]} />
          <span className="text-sm font-semibold text-primary">Network Risk Score</span>
        </div>
        <span className={`text-xs font-bold px-2 py-1 rounded-full ${cfg.className}`}>{level}</span>
      </div>

      <div className="flex items-end gap-1 mb-4">
        <span className="text-4xl font-bold text-primary">{network_score}</span>
        <span className="text-lg text-muted mb-0.5">/100</span>
      </div>

      {/* Progress bar */}
      <div className="w-full h-2 rounded-full mb-4" style={{ background: "var(--color-border)" }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${Math.min(100, network_score)}%`,
            background: level === "CRITICAL" ? "#ef4444" :
              level === "HIGH" ? "#f97316" :
              level === "MEDIUM" ? "#eab308" : "#3b82f6",
          }}
        />
      </div>

      <div className="grid grid-cols-3 gap-3 text-center">
        <MetricCell label="Total CVEs" value={total_vulns} icon={AlertTriangle} color="text-danger" />
        <MetricCell label="Critical Hosts" value={critical_hosts} icon={TrendingUp} color="text-red-500" />
        <MetricCell label="High Risk" value={high_hosts} icon={TrendingUp} color="text-orange-500" />
      </div>
    </div>
  );
}

function MetricCell({ label, value, icon: Icon, color }) {
  return (
    <div className="rounded-xl p-2.5" style={{ background: "var(--color-bg-surface-hover)" }}>
      <p className={`text-xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-muted mt-0.5">{label}</p>
    </div>
  );
}
