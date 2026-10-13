import { useEffect, useState, useCallback, Fragment } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Shield, ChevronDown, ChevronUp, ArrowRight, Filter, RefreshCw, ExternalLink, Info } from "lucide-react";
import SeverityBadge from "../components/vulnerabilities/SeverityBadge";
import { LoadingOverlay } from "../components/ui/Loading";
import { resultsApi } from "../services/api";
import API from "../services/api";

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const FACTOR_COLOR = { reachability: "#a78bfa", exploitability: "#ef4444", impact: "#34d399", hop_penalty: "#64748b" };

// 3-component breakdown: value bars (0-100) with the documented weight.
function PathBreakdown({ factors }) {
  return (
    <div className="space-y-1.5">
      {factors.map((f) => (
        <div key={f.key} className="flex items-center gap-2 text-xs">
          <span className="w-56 flex-shrink-0 text-tertiary truncate" title={f.label}>
            {f.label}{f.weight && f.key !== "hop_penalty" ? ` · ×${f.weight}` : ""}
          </span>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--surface-2)" }}>
            <div className="h-full rounded-full" style={{
              width: `${Math.min(100, Math.abs(f.value))}%`,
              background: FACTOR_COLOR[f.key] ?? "var(--accent)",
            }} />
          </div>
          <span className="w-10 text-right font-mono text-secondary">{f.value}</span>
          <span className="w-64 flex-shrink-0 text-muted truncate" title={f.detail}>{f.detail}</span>
        </div>
      ))}
    </div>
  );
}

function MitreTags({ mitre }) {
  if (!mitre?.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {mitre.map((t) => (
        <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
           target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
           className="badge badge-gray hover:underline" title={t.name}>
          {t.id} · {t.name}
        </a>
      ))}
    </div>
  );
}

export default function AttackPaths() {
  const [params] = useSearchParams();
  const initialScanId = params.get("scan");

  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(initialScanId || "");
  const [paths, setPaths] = useState([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    resultsApi.list().then((res) => {
      const completed = res.scans.filter((s) => s.status === "completed");
      setScans(completed);
      if (!selectedScan && completed.length > 0) setSelectedScan(completed[0].id);
    });
  }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(() => {
    // Always scope to one scan: paths across scans each start from their own
    // ATTACKER node and must not be mixed.
    if (!selectedScan) { setPaths([]); return; }
    setLoading(true);
    API.get(`/attack-graph/paths?scan_id=${selectedScan}`)
      .then((res) => setPaths(res.paths ?? []))
      .catch(() => setPaths([]))
      .finally(() => setLoading(false));
  }, [selectedScan]);

  useEffect(() => { load(); }, [load]);

  const filtered = severityFilter === "ALL" ? paths : paths.filter((p) => p.severity === severityFilter);
  const bySev = paths.reduce((acc, p) => { acc[p.severity] = (acc[p.severity] || 0) + 1; return acc; }, {});

  return (
    <div className="max-w-5xl space-y-6 animate-fadeIn">
      <div className="flex items-end justify-between flex-wrap gap-4">
        <div>
          <p className="eyebrow mb-2">Analysis</p>
          <h1 className="page-title">Attack paths</h1>
          <p className="page-subtitle">Chains ranked by an evidence-based score. Each path is justified from the real scan data — reachability, hop exploitability (KEV/EPSS/CPE), and impact.</p>
        </div>
        <div className="flex items-center gap-3">
          <select className="input-field max-w-[240px] text-sm" value={selectedScan}
                  onChange={(e) => setSelectedScan(e.target.value)}>
            <option value="">Select a scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>{s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}</option>
            ))}
          </select>
          <button className="btn-icon" onClick={load} title="Refresh"><RefreshCw size={15} className={loading ? "animate-spin" : ""} /></button>
        </div>
      </div>

      <div className="rounded-lg p-3 text-xs flex gap-3" style={{ background: "var(--surface-2)", border: "1px solid var(--line)" }}>
        <Info size={15} className="flex-shrink-0 mt-0.5 text-tertiary" aria-hidden="true" />
        <p className="text-tertiary">
          This is a <span className="text-secondary font-semibold">heuristic, evidence-based</span> model — not a formal
          attack graph (e.g. MulVAL). It ranks plausible paths from real evidence for you to review; it does not prove
          reachability or chain preconditions. Score = 0.20·reachability + 0.50·exploitability + 0.30·impact.
        </p>
      </div>

      {paths.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button key={sev} onClick={() => setSeverityFilter(sev === severityFilter ? "ALL" : sev)}
                    className={`card-sm text-left transition-all ${severityFilter === sev ? "ring-1 ring-current" : "hover:ring-1 hover:ring-current/20"}`}>
              <p className="text-xl font-bold text-primary">{bySev[sev] ?? 0}</p>
              <SeverityBadge severity={sev} />
            </button>
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={13} className="text-muted" aria-hidden="true" />
        <div className="segmented" role="group" aria-label="Filter by severity">
          {SEVERITIES.map((s) => (
            <button key={s} type="button" onClick={() => setSeverityFilter(s)} aria-pressed={severityFilter === s}>{s}</button>
          ))}
        </div>
        <span className="ml-auto text-xs text-muted">{filtered.length} path{filtered.length !== 1 ? "s" : ""}</span>
      </div>

      <div className="card">
        {loading ? (
          <LoadingOverlay message="Loading attack paths…" />
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center text-muted text-sm">
            <Shield size={28} className="mx-auto opacity-20 mb-2" />
            <p>No attack paths found.</p>
            <p className="text-xs mt-1">
              Complete a network scan first, then visit the{" "}
              <Link to="/app/attack-graph" className="text-info hover:underline">Attack Graph</Link> page.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((path) => (
              <div key={path.id}
                   className="rounded-xl border border-[var(--color-border)] cursor-pointer transition-all hover:border-[var(--color-border-hover)]"
                   style={{ background: expanded === path.id ? "var(--color-bg-surface-hover)" : undefined }}
                   onClick={() => setExpanded(expanded === path.id ? null : path.id)}>
                <div className="flex items-center gap-3 p-3">
                  <div className="w-12 text-center flex-shrink-0">
                    <p className="text-lg font-bold" style={{ color: _sevColor(path.severity) }}>{path.total_score?.toFixed(0)}</p>
                    <p className="text-[10px] text-muted">score</p>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 mb-1">
                      <SeverityBadge severity={path.severity} />
                      <span className="text-xs text-muted">{path.hop_count} hop{path.hop_count !== 1 ? "s" : ""}</span>
                    </div>
                    <PathFlow ips={path.path_ips ?? []} />
                    {path.justification && (
                      <p className="text-xs text-tertiary mt-1 truncate" title={path.justification}>{path.justification}</p>
                    )}
                  </div>
                  {path.cve_ids?.length > 0 && (
                    <span className="text-xs text-orange-400 flex-shrink-0">{path.cve_ids.length} CVE{path.cve_ids.length !== 1 ? "s" : ""}</span>
                  )}
                  {expanded === path.id ? <ChevronUp size={13} className="text-muted flex-shrink-0" /> : <ChevronDown size={13} className="text-muted flex-shrink-0" />}
                </div>

                {expanded === path.id && (
                  <div className="border-t border-[var(--color-border)] px-4 pb-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                    {/* Why (justification) */}
                    {path.justification && (
                      <div className="mt-3">
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-1">Why this path</p>
                        <p className="text-sm text-secondary leading-relaxed">{path.justification}</p>
                      </div>
                    )}

                    {/* Transparent score breakdown */}
                    {path.factors?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Score breakdown</p>
                        <PathBreakdown factors={path.factors} />
                      </div>
                    )}

                    {/* Per-hop steps with MITRE */}
                    {path.hops?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Steps</p>
                        <div className="space-y-2">
                          {path.hops.map((h, i) => (
                            <div key={i} className="rounded-lg p-2.5" style={{ background: "var(--surface-2)" }}>
                              <div className="flex items-start gap-2">
                                <span className="text-xs text-muted font-mono mt-0.5">{i + 1}.</span>
                                <div className="flex-1 min-w-0">
                                  <p className="text-xs text-secondary">{h.justification}</p>
                                  <div className="flex flex-wrap items-center gap-2 mt-1">
                                    <span className="text-[10px] text-muted font-mono">score {h.score}</span>
                                    <MitreTags mitre={h.mitre} />
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* MITRE for the whole path */}
                    {path.mitre?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">MITRE ATT&CK (references)</p>
                        <MitreTags mitre={path.mitre} />
                      </div>
                    )}

                    {/* CVEs */}
                    {path.cve_ids?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">CVEs involved</p>
                        <div className="flex flex-wrap gap-2">
                          {path.cve_ids.map((cve) => (
                            <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
                               onClick={(e) => e.stopPropagation()}
                               className="text-xs font-mono text-info hover:underline flex items-center gap-1">
                              {cve} <ExternalLink size={9} />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function PathFlow({ ips }) {
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {ips.map((ip, i) => (
        <Fragment key={i}>
          <span className={`text-xs font-mono ${ip === "0.0.0.0" ? "text-red-400" : i === ips.length - 1 ? "text-orange-300" : "text-secondary"}`}>
            {ip === "0.0.0.0" ? "ATTACKER" : ip}
          </span>
          {i < ips.length - 1 && <ArrowRight size={9} className="text-muted flex-shrink-0" />}
        </Fragment>
      ))}
    </div>
  );
}

function _sevColor(sev) {
  return sev === "CRITICAL" ? "var(--sev-critical)"
    : sev === "HIGH" ? "var(--sev-high)"
    : sev === "MEDIUM" ? "var(--sev-medium)"
    : "var(--sev-low)";
}
