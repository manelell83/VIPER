// Transparent, deterministic score breakdown: one bar per factor, width ∝ points.
const FACTOR_COLOR = {
  exploitation: "#ef4444",
  epss: "#f97316",
  cvss: "#eab308",
  confidence: "#38bdf8",
  exposure: "#a78bfa",
  lateral: "#34d399",
};

export default function ScoreBreakdown({ factors }) {
  const max = Math.max(...factors.map((f) => f.points), 1);
  return (
    <div className="space-y-1.5">
      {factors.map((f) => (
        <div key={f.key} className="flex items-center gap-2 text-xs">
          <span className="w-48 flex-shrink-0 text-tertiary truncate" title={f.label}>{f.label}</span>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--surface-2)" }}>
            <div className="h-full rounded-full" style={{
              width: `${(f.points / max) * 100}%`,
              background: FACTOR_COLOR[f.key] ?? "var(--accent)",
              opacity: f.points > 0 ? 1 : 0.25,
            }} />
          </div>
          <span className="w-10 text-right font-mono text-secondary">{f.points.toFixed(1)}</span>
          <span className="w-56 flex-shrink-0 text-muted truncate" title={f.detail}>{f.detail}</span>
        </div>
      ))}
    </div>
  );
}
