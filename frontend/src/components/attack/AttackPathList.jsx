import { useState, Fragment } from "react";
import { ChevronDown, ChevronUp, ArrowRight, AlertTriangle, Shield } from "lucide-react";
import SeverityBadge from "../vulnerabilities/SeverityBadge";

const VECTOR_COLORS = {
  REMOTE_ACCESS:        "text-red-400 bg-red-500/10",
  LATERAL_MOVEMENT:     "text-orange-400 bg-orange-500/10",
  PRIVILEGE_ESCALATION: "text-purple-400 bg-purple-500/10",
  DATA_ACCESS:          "text-yellow-400 bg-yellow-500/10",
  PERSISTENCE:          "text-gray-400 bg-gray-500/10",
};

export default function AttackPathList({ paths = [], onPathHover, highlightedId }) {
  const [expanded, setExpanded] = useState(null);

  if (paths.length === 0) {
    return (
      <div className="py-10 text-center text-muted text-sm">
        <Shield size={28} className="mx-auto opacity-20 mb-2" />
        <p>No attack paths found for this scan.</p>
        <p className="text-xs mt-1 text-tertiary">
          This means no exploitable service chains were detected.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {paths.map((path) => (
        <Fragment key={path.id}>
          <div
            className={`rounded-xl border transition-all duration-200 cursor-pointer ${
              highlightedId === path.id
                ? "border-red-500/50 bg-red-500/5"
                : "border-[var(--color-border)] hover:border-[var(--color-border-hover)]"
            }`}
            style={{ background: expanded === path.id ? "var(--color-bg-surface-hover)" : undefined }}
            onMouseEnter={() => onPathHover?.(path)}
            onMouseLeave={() => onPathHover?.(null)}
            onClick={() => setExpanded(expanded === path.id ? null : path.id)}
          >
            {/* Path header */}
            <div className="flex items-center gap-3 p-3">
              {/* Score ring */}
              <ScoreRing score={path.total_score} severity={path.severity} />

              {/* Path summary */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={path.severity} />
                  <span className="text-xs text-muted">{path.hop_count} hop{path.hop_count !== 1 ? "s" : ""}</span>
                  {path.cve_ids?.length > 0 && (
                    <span className="text-xs text-orange-400">{path.cve_ids.length} CVE(s)</span>
                  )}
                </div>
                <PathFlow ips={path.path_ips} />
              </div>

              {expanded === path.id
                ? <ChevronUp size={13} className="text-muted flex-shrink-0" />
                : <ChevronDown size={13} className="text-muted flex-shrink-0" />
              }
            </div>

            {/* Expanded detail */}
            {expanded === path.id && (
              <div className="px-4 pb-4 space-y-3 border-t border-[var(--color-border)]">
                {/* Attack vectors */}
                {path.attack_vectors?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider mt-3 mb-2">Attack Vectors</p>
                    <div className="space-y-1.5">
                      {path.attack_vectors.map((v, i) => {
                        const typeKey = Object.keys(VECTOR_COLORS).find(k =>
                          v.toUpperCase().includes(k.replace("_", " ").split(" ")[0])
                        ) || "PERSISTENCE";
                        return (
                          <div key={i} className="flex items-start gap-2">
                            <span className="text-muted text-xs mt-0.5 font-mono w-4 flex-shrink-0">
                              {i + 1}.
                            </span>
                            <span className={`text-xs px-2 py-0.5 rounded-md font-medium ${VECTOR_COLORS[typeKey]}`}>
                              {v}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* CVEs */}
                {path.cve_ids?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Related CVEs</p>
                    <div className="flex flex-wrap gap-1.5">
                      {path.cve_ids.map((cve) => (
                        <a
                          key={cve}
                          href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="text-xs font-mono text-info hover:underline px-2 py-0.5 rounded-md"
                          style={{ background: "var(--color-bg-surface)" }}
                        >
                          {cve}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between text-xs text-muted pt-1">
                  <span>Entry: <span className="font-mono text-secondary">{path.entry_ip}</span></span>
                  <span>Target: <span className="font-mono text-red-400">{path.target_ip}</span></span>
                </div>
              </div>
            )}
          </div>
        </Fragment>
      ))}
    </div>
  );
}

function PathFlow({ ips = [] }) {
  if (!ips.length) return null;
  return (
    <div className="flex items-center gap-1 flex-wrap mt-1">
      {ips.map((ip, i) => (
        <Fragment key={i}>
          <span className={`text-xs font-mono ${
            ip === "0.0.0.0" ? "text-red-400" :
            i === ips.length - 1 ? "text-orange-300" : "text-secondary"
          }`}>
            {ip === "0.0.0.0" ? "ATTACKER" : ip}
          </span>
          {i < ips.length - 1 && <ArrowRight size={10} className="text-muted flex-shrink-0" />}
        </Fragment>
      ))}
    </div>
  );
}

function ScoreRing({ score, severity }) {
  const color =
    severity === "CRITICAL" ? "var(--sev-critical)" :
    severity === "HIGH" ? "var(--sev-high)" :
    severity === "MEDIUM" ? "var(--sev-medium)" : "var(--sev-low)";

  const size = 40;
  const r = (size - 6) / 2;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div className="relative inline-flex items-center justify-center flex-shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth={4} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={4}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.5s ease" }}
        />
      </svg>
      <span className="absolute text-[10px] font-bold" style={{ color }}>
        {Math.round(score)}
      </span>
    </div>
  );
}
