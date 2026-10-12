import { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Shield, AlertTriangle, RefreshCw, Wifi } from "lucide-react";
import VulnerabilityTable from "../components/vulnerabilities/VulnerabilityTable";
import RiskCard from "../components/vulnerabilities/RiskCard";
import SeverityBadge from "../components/vulnerabilities/SeverityBadge";
import { LoadingOverlay } from "../components/ui/Loading";
import { resultsApi } from "../services/api";
import API from "../services/api";
import PageHeader from "../components/ui/PageHeader";

export default function Vulnerabilities() {
  const [params] = useSearchParams();
  const initialScanId = params.get("scan");

  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(initialScanId || "");
  const [vulns, setVulns] = useState([]);
  const [riskData, setRiskData] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [liveVulns, setLiveVulns] = useState([]);  // real-time discoveries

  // Load scan list
  useEffect(() => {
    resultsApi.list().then((res) => {
      const completed = res.scans.filter((s) => s.status === "completed");
      setScans(completed);
      if (!selectedScan && completed.length > 0) setSelectedScan(completed[0].id);
    });
  }, []);

  // Load global stats
  useEffect(() => {
    API.get("/vulnerabilities/stats").then(setStats).catch(() => {});
  }, [vulns.length]);

  // Load vulnerabilities for selected scan
  const load = useCallback(() => {
    if (!selectedScan) return;
    setLoading(true);
    setVulns([]);
    setRiskData(null);

    Promise.all([
      API.get(`/vulnerabilities?scan_id=${selectedScan}`),
      API.get(`/vulnerabilities/risk/summary?scan_id=${selectedScan}`),
    ])
      .then(([vRes, rRes]) => {
        // Enrich vulns with host IP from the scan results
        const hostMap = {};
        API.get(`/results/${selectedScan}`).then((scanData) => {
          (scanData.hosts || []).forEach((h) => { hostMap[h.id] = h.ip; });
          setVulns(
            vRes.vulnerabilities.map((v) => ({
              ...v,
              host_ip: hostMap[v.host_id] || v.host_id,
            }))
          );
        });
        setRiskData(rRes);
      })
      .finally(() => setLoading(false));
  }, [selectedScan]);

  useEffect(() => { load(); }, [load]);

  // Summary counts
  const bySeverity = vulns.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6 animate-fadeIn">
      <PageHeader
        eyebrow="Analysis"
        title="Vulnerabilities"
        subtitle="CVEs matched to the services found by your scans (NVD API). Matching is keyword-based: verify a finding before acting on it."
      >
          <select
            className="input-field max-w-[240px] text-sm"
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
          >
            <option value="">Select a scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          <button className="btn-icon" onClick={load} title="Refresh">
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          </button>
      </PageHeader>

      {/* Global stats row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { sev: "CRITICAL", count: stats.by_severity?.critical ?? 0 },
            { sev: "HIGH",     count: stats.by_severity?.high ?? 0 },
            { sev: "MEDIUM",   count: stats.by_severity?.medium ?? 0 },
            { sev: "LOW",      count: stats.by_severity?.low ?? 0 },
          ].map(({ sev, count }) => (
            <div key={sev} className="card-sm flex items-center gap-3">
              <div className="flex-1">
                <p className="text-xl font-bold text-primary">{count}</p>
                <SeverityBadge severity={sev} />
              </div>
            </div>
          ))}
          <div className="card-sm flex items-center gap-3">
            <AlertTriangle size={18} className="text-muted" />
            <div>
              <p className="text-xl font-bold text-primary">{stats.total ?? 0}</p>
              <p className="text-xs text-muted">Total CVEs</p>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <LoadingOverlay message="Loading vulnerabilities…" />
      ) : !selectedScan ? (
        <div className="card py-12 text-center">
          <Wifi size={32} className="mx-auto text-muted opacity-30 mb-3" />
          <p className="text-muted text-sm">Select a completed scan to view vulnerabilities.</p>
        </div>
      ) : (
        <div className="space-y-5">
          {/* Risk Summary */}
          {riskData?.network && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-1">
                <RiskCard network={riskData.network} />
              </div>

              {/* Top risky hosts */}
              <div className="lg:col-span-2 card">
                <h2 className="section-title mb-3">Top risky hosts</h2>
                {riskData.hosts?.length === 0 ? (
                  <p className="text-sm text-muted">No risk data available.</p>
                ) : (
                  <div className="space-y-2">
                    {[...riskData.hosts]
                      .sort((a, b) => b.score - a.score)
                      .slice(0, 5)
                      .map((h) => (
                        <HostRiskRow key={h.host_id} host={h} />
                      ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* CVE Table */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="section-title flex items-center gap-2">
                CVE findings
                <span className="badge badge-gray">{vulns.length}</span>
              </h2>
            </div>

            {vulns.length === 0 ? (
              <div className="py-8 text-center text-muted text-sm">
                <Shield size={28} className="mx-auto opacity-20 mb-2" />
                <p>No CVEs found for this scan.</p>
                <p className="text-xs mt-1">This may mean the discovered services have no known vulnerabilities,
                  or NVD returned no results for the detected versions.</p>
              </div>
            ) : (
              <VulnerabilityTable vulnerabilities={vulns} showHostColumn />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function HostRiskRow({ host }) {
  const levelColor = {
    CRITICAL: "var(--sev-critical)",
    HIGH: "var(--sev-high)",
    MEDIUM: "var(--sev-medium)",
    LOW: "var(--sev-low)",
    NONE: "var(--sev-none)",
  }[host.level] ?? "var(--sev-none)";

  return (
    <div className="flex items-center gap-3 rounded-lg p-2.5" style={{ background: "var(--color-bg-surface-hover)" }}>
      <div className="w-2 h-8 rounded-full flex-shrink-0" style={{ background: levelColor }} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-mono text-primary">{host.host_ip}</p>
        <p className="text-xs text-muted">{host.vuln_count} CVE{host.vuln_count !== 1 ? "s" : ""} · {host.critical} critical</p>
      </div>
      <div className="text-right flex-shrink-0">
        <p className="text-sm font-bold" style={{ color: levelColor }}>{host.score}</p>
        <p className="text-xs text-muted">risk score</p>
      </div>
      <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--color-border)" }}>
        <div
          className="h-full rounded-full"
          style={{ width: `${Math.min(100, host.score)}%`, background: levelColor }}
        />
      </div>
    </div>
  );
}
