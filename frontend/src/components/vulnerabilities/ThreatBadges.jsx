import { ShieldCheck, AlertTriangle, Flame, Activity } from "lucide-react";

/**
 * Two kinds of signal, kept visually distinct:
 *
 *  - Match confidence — whether the CVE is "confirmed vulnerable here":
 *      Confirmed (CPE)  = the CVE affects the detected product AND version
 *      Weak match (kw)  = keyword match only, may be a false positive
 *
 *  - Exploitation in the world — KEV / EPSS. These describe the CVE globally,
 *    NOT this host. A "Known Exploited" CVE on a weak match does not mean the
 *    host is exploitable.
 */

export function ConfidenceBadge({ confirmed }) {
  return confirmed ? (
    <span className="badge badge-green" title="Matched by CPE: this CVE affects the detected product and version.">
      <ShieldCheck size={11} /> Confirmed
    </span>
  ) : (
    <span className="badge badge-yellow"
          title="Matched by keyword only - the exact product/version could not be identified, so this may be a false positive.">
      <AlertTriangle size={11} /> Weak match
    </span>
  );
}

function epssStyle(epss) {
  if (epss >= 0.5) return "badge-red";
  if (epss >= 0.1) return "badge-yellow";
  return "badge-gray";
}

/** KEV + EPSS badges (exploitation in the world). Renders nothing if neither applies. */
export function ThreatBadges({ vuln, className = "" }) {
  const hasEpss = vuln.epss != null;
  if (!vuln.kev && !hasEpss) return <span className="text-xs text-muted">—</span>;

  return (
    <span className={`inline-flex flex-wrap items-center gap-1.5 ${className}`}>
      {vuln.kev && (
        <span className="badge badge-red"
              title="In the CISA KEV catalogue: this CVE is exploited in the wild. A world-wide signal - it does not by itself mean this host is vulnerable.">
          <Flame size={11} /> Known Exploited
        </span>
      )}
      {hasEpss && (
        <span className={`badge ${epssStyle(vuln.epss)}`}
              title="EPSS: estimated probability this CVE is exploited in the next 30 days (world-wide, not host-specific).">
          <Activity size={11} /> EPSS {(vuln.epss * 100).toFixed(vuln.epss >= 0.1 ? 0 : 1)}%
        </span>
      )}
    </span>
  );
}

/** One-time explanation shown above the findings table. */
export function ThreatLegend() {
  return (
    <div className="rounded-lg p-3 text-xs flex gap-3"
         style={{ background: "var(--surface-2)", border: "1px solid var(--line)" }}>
      <AlertTriangle size={15} className="flex-shrink-0 mt-0.5 text-warning" aria-hidden="true" />
      <div className="space-y-1">
        <p className="text-secondary">
          <span className="text-primary font-semibold">Confirmed</span> means the CVE was matched by CPE to the
          detected product and version. <span className="text-primary font-semibold">Weak match</span> means a
          keyword-only match that may be a false positive.
        </p>
        <p className="text-tertiary">
          <span className="font-semibold">Known Exploited</span> (CISA KEV) and <span className="font-semibold">EPSS</span> describe
          how much a CVE is exploited <em>in the world</em> — they do <strong>not</strong> mean this host is
          exploitable. A weak match with a high EPSS is still likely a false positive.
        </p>
      </div>
    </div>
  );
}
