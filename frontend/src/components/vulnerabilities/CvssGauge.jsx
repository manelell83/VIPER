/**
 * Circular CVSS score gauge.
 * score: 0–10
 */
export default function CvssGauge({ score = 0, size = 48 }) {
  const pct = Math.min(10, Math.max(0, score)) / 10;
  const r = (size - 6) / 2;
  const circ = 2 * Math.PI * r;
  const dash = pct * circ;

  const color =
    score >= 9 ? "var(--sev-critical)" :
    score >= 7 ? "var(--sev-high)" :
    score >= 4 ? "var(--sev-medium)" :
    score > 0  ? "var(--sev-low)" : "var(--sev-none)";

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none" stroke="currentColor" strokeWidth={4}
          className="text-gray-200 dark:text-gray-700"
        />
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none" stroke={color} strokeWidth={4}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.5s ease" }}
        />
      </svg>
      <span
        className="absolute text-xs font-bold"
        style={{ color, fontSize: size < 44 ? 9 : 11 }}
      >
        {score?.toFixed(1) ?? "—"}
      </span>
    </div>
  );
}
