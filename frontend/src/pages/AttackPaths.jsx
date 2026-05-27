import { useEffect, useState, useCallback, Fragment } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Shield, ChevronDown, ChevronUp, ArrowRight, Filter, RefreshCw, ExternalLink } from "lucide-react";
import SeverityBadge from "../components/vulnerabilities/SeverityBadge";
import { LoadingOverlay } from "../components/ui/Loading";
import { resultsApi } from "../services/api";
import API from "../services/api";

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const ATTACK_TYPE_LABELS = {
  REMOTE_ACCESS:        { label: "Remote Access",        color: "text-red-400 bg-red-500/10" },
  LATERAL_MOVEMENT:     { label: "Lateral Movement",     color: "text-orange-400 bg-orange-500/10" },
  PRIVILEGE_ESCALATION: { label: "Privilege Escalation", color: "text-purple-400 bg-purple-500/10" },
  DATA_ACCESS:          { label: "Data Access",           color: "text-yellow-400 bg-yellow-500/10" },
  PERSISTENCE:          { label: "Persistence",           color: "text-gray-400 bg-gray-500/10" },
};

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
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    const url = selectedScan
      ? `/attack-graph/paths?scan_id=${selectedScan}`
      : "/attack-graph/paths";
    API.get(url)
      .then((res) => setPaths(res.paths ?? []))
      .catch(() => setPaths([]))
      .finally(() => setLoading(false));
  }, [selectedScan]);

  useEffect(() => { load(); }, [load]);

  const filtered = severityFilter === "ALL"
    ? paths
    : paths.filter((p) => p.severity === severityFilter);

  const bySev = paths.reduce((acc, p) => {
    acc[p.severity] = (acc[p.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-primary flex items-center gap-2">
            <Shield size={22} className="text-orange-400" />
            Attack Paths
          </h1>
          <p className="text-sm text-muted mt-1">
            Ranked attack chains derived from real scan vulnerabilities
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            className="input-field max-w-[240px] text-sm"
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
          >
            <option value="">All scans</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          <button className="btn-icon" onClick={load} title="Refresh">
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* Severity stats */}
      {paths.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev === severityFilter ? "ALL" : sev)}
              className={`card-sm text-left transition-all ${
                severityFilter === sev ? "ring-1 ring-current" : "hover:ring-1 hover:ring-current/20"
              }`}
            >
              <p className="text-xl font-bold text-primary">{bySev[sev] ?? 0}</p>
              <SeverityBadge severity={sev} />
            </button>
          ))}
        </div>
      )}

      {/* Filter row */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={13} className="text-muted" />
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setSeverityFilter(s)}
            className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-colors ${
              severityFilter === s
                ? s === "ALL"
                  ? "bg-blue-600 text-white"
                  : "ring-1 ring-current text-primary"
                : "text-tertiary hover:text-secondary"
            }`}
          >
            {s}
          </button>
        ))}
        <span className="ml-auto text-xs text-muted">
          {filtered.length} path{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Path list */}
      <div className="card">
        {loading ? (
          <LoadingOverlay message="Loading attack paths…" />
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center text-muted text-sm">
            <Shield size={28} className="mx-auto opacity-20 mb-2" />
            <p>No attack paths found.</p>
            <p className="text-xs mt-1">
              Complete a network scan first, then visit the{" "}
              <Link to="/attack-graph" className="text-info hover:underline">Attack Graph</Link> page.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((path) => (
              <Fragment key={path.id}>
                <div
                  className="rounded-xl border border-[var(--color-border)] cursor-pointer transition-all hover:border-[var(--color-border-hover)]"
                  style={{ background: expanded === path.id ? "var(--color-bg-surface-hover)" : undefined }}
                  onClick={() => setExpanded(expanded === path.id ? null : path.id)}
                >
                  {/* Row */}
                  <div className="flex items-center gap-3 p-3">
                    {/* Score */}
                    <div className="w-12 text-center flex-shrink-0">
                      <p className="text-lg font-bold" style={{ color: _sevColor(path.severity) }}>
                        {path.total_score?.toFixed(0)}
                      </p>
                      <p className="text-[10px] text-muted">score</p>
                    </div>

                    {/* Path flow */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <SeverityBadge severity={path.severity} />
                        <span className="text-xs text-muted">{path.hop_count} hop{path.hop_count !== 1 ? "s" : ""}</span>
                      </div>
                      <PathFlow ips={path.path_ips ?? []} />
                    </div>

                    {/* CVE count */}
                    {path.cve_ids?.length > 0 && (
                      <span className="text-xs text-orange-400 flex-shrink-0">
                        {path.cve_ids.length} CVE{path.cve_ids.length !== 1 ? "s" : ""}
                      </span>
                    )}

                    {expanded === path.id
                      ? <ChevronUp size={13} className="text-muted flex-shrink-0" />
                      : <ChevronDown size={13} className="text-muted flex-shrink-0" />
                    }
                  </div>

                  {/* Expanded */}
                  {expanded === path.id && (
                    <div className="border-t border-[var(--color-border)] px-4 pb-4 space-y-4">
                      {/* Attack vectors */}
                      {path.attack_vectors?.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Attack Chain</p>
                          <div className="space-y-2">
                            {path.attack_vectors.map((v, i) => {
                              const typeKey = _detectType(v);
                              const cfg = ATTACK_TYPE_LABELS[typeKey] || ATTACK_TYPE_LABELS.PERSISTENCE;
                              return (
                                <div key={i} className="flex items-start gap-2">
                                  <span className="text-xs text-muted font-mono mt-0.5 w-4">{i + 1}.</span>
                                  <span className={`text-xs px-2 py-0.5 rounded-md ${cfg.color}`}>{v}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* CVEs */}
                      {path.cve_ids?.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">CVEs Involved</p>
                          <div className="flex flex-wrap gap-2">
                            {path.cve_ids.map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="text-xs font-mono text-info hover:underline flex items-center gap-1"
                              >
                                {cve} <ExternalLink size={9} />
                              </a>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Entry / target */}
                      <div className="flex items-center justify-between text-xs text-muted">
                        <span>
                          Entry: <span className="font-mono text-secondary">{path.entry_ip}</span>
                        </span>
                        <span>
                          Target: <span className="font-mono text-red-400">{path.target_ip}</span>
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </Fragment>
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
          <span className={`text-xs font-mono ${
            ip === "0.0.0.0" ? "text-red-400" :
            i === ips.length - 1 ? "text-orange-300" : "text-secondary"
          }`}>
            {ip === "0.0.0.0" ? "ATTACKER" : ip}
          </span>
          {i < ips.length - 1 && <ArrowRight size={9} className="text-muted flex-shrink-0" />}
        </Fragment>
      ))}
    </div>
  );
}

function _sevColor(sev) {
  return sev === "CRITICAL" ? "#ef4444"
    : sev === "HIGH" ? "#f97316"
    : sev === "MEDIUM" ? "#eab308"
    : "#3b82f6";
}

function _detectType(vector = "") {
  const v = vector.toUpperCase();
  if (v.includes("PIVOT") || v.includes("SMB") || v.includes("LATERAL") || v.includes("WINRM")) return "LATERAL_MOVEMENT";
  if (v.includes("PRIVILEGE") || v.includes("PRIV") || v.includes("ROOT") || v.includes("SYSTEM")) return "PRIVILEGE_ESCALATION";
  if (v.includes("SQL") || v.includes("DB") || v.includes("DATABASE") || v.includes("REDIS") || v.includes("MONGO")) return "DATA_ACCESS";
  if (v.includes("SMTP") || v.includes("SNMP") || v.includes("PERSIST")) return "PERSISTENCE";
  return "REMOTE_ACCESS";
}
