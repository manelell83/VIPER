const LEVELS = [
  { key: "critical", label: "Critical", color: "var(--sev-critical)" },
  { key: "high",     label: "High",     color: "var(--sev-high)" },
  { key: "medium",   label: "Medium",   color: "var(--sev-medium)" },
  { key: "low",      label: "Low",      color: "var(--sev-low)" },
];

/**
 * Horizontal stacked bar of findings per severity, with a legend.
 * counts = { critical, high, medium, low }
 */
export default function SeverityBar({ counts, className = "" }) {
  const total = LEVELS.reduce((sum, l) => sum + (counts[l.key] ?? 0), 0);

  return (
    <div className={className}>
      <div
        className="flex h-3 w-full overflow-hidden rounded-full"
        style={{ background: "var(--surface-2)" }}
        role="img"
        aria-label={LEVELS.map((l) => `${counts[l.key] ?? 0} ${l.label}`).join(", ")}
      >
        {total > 0 && LEVELS.map((l) => (
          counts[l.key] > 0 && (
            <span key={l.key} style={{ width: `${(counts[l.key] / total) * 100}%`, background: l.color }} />
          )
        ))}
      </div>
      <ul className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
        {LEVELS.map((l) => (
          <li key={l.key} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: l.color }} aria-hidden="true" />
            <span className="text-xs text-tertiary">{l.label}</span>
            <span className="ml-auto font-display font-semibold text-primary">{counts[l.key] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
