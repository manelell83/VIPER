import { useState, useEffect } from "react";
import API, { reportsApi } from "../services/api";
import ExploitabilityBadge from "../components/exploitability/ExploitabilityBadge";
import RemediationCard from "../components/exploitability/RemediationCard";
import { Download, RefreshCw, ShieldCheck, AlertTriangle, Crosshair, Route } from "lucide-react";

const SEV_COLOR = {
  CRITICAL: "var(--sev-critical)",
  HIGH:     "var(--sev-high)",
  MEDIUM:   "var(--sev-medium)",
  LOW:      "var(--sev-low)",
};

function ScoreGauge({ score }) {
  const color = score >= 80 ? "var(--success-text)" : score >= 60 ? "var(--warning-text)" : score >= 40 ? "var(--sev-high)" : "var(--danger-text)";
  const label = score >= 80 ? "SECURE" : score >= 60 ? "MODERATE" : score >= 40 ? "AT RISK" : "CRITICAL";
  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className="w-28 h-28 rounded-full flex flex-col items-center justify-center border-4"
        style={{ borderColor: color }}
      >
        <span className="text-3xl font-black" style={{ color }}>{score}</span>
        <span className="text-xs text-muted">/ 100</span>
      </div>
      <span className="text-sm font-bold" style={{ color }}>{label}</span>
    </div>
  );
}

function SectionTitle({ icon: Icon, title }) {
  return (
    <div className="flex items-center gap-2 pb-3 border-b border-[var(--line)]">
      <Icon size={18} className="text-accent-text" aria-hidden="true" />
      <h2 className="section-title">{title}</h2>
    </div>
  );
}

export default function SecurityReport() {
  const [scans, setScans]     = useState([]);
  const [scanId, setScanId]   = useState("");
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    API.get("/results").then((r) => {
      const completed = (r.scans || []).filter((s) => s.status === "completed");
      setScans(completed);
      if (completed.length > 0) setScanId(completed[0].id);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    API.get(`/exploitability/security-summary?scan_id=${scanId}`)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId]);

  const handleExportPDF = async () => {
    if (!scanId) return;
    setExporting(true);
    try {
      await reportsApi.downloadPdf(scanId);
    } catch (_) {} finally {
      setExporting(false);
    }
  };

  const handleExportJSON = async () => {
    if (!scanId) return;
    await reportsApi.downloadJson(scanId).catch(() => {});
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-end justify-between flex-wrap gap-4">
        <div>
          <p className="eyebrow mb-2">Reporting</p>
          <h1 className="page-title">Security report</h1>
          <p className="page-subtitle">The full assessment of one scan: score, vulnerabilities, exploitability, attack paths and remediation.</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="input-field text-sm py-1.5 w-64"
          >
            <option value="">Select a scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          {loading && <RefreshCw size={15} className="animate-spin text-muted" />}
          <button
            onClick={handleExportJSON}
            disabled={!scanId}
            className="btn-secondary text-sm flex items-center gap-1.5 px-3 py-1.5"
          >
            <Download size={13} /> JSON
          </button>
          <button
            onClick={handleExportPDF}
            disabled={!scanId || exporting}
            className="btn-primary text-sm flex items-center gap-1.5 px-3 py-1.5"
          >
            <Download size={13} />
            {exporting ? "Generating…" : "PDF Report"}
          </button>
        </div>
      </div>

      {!scanId && (
        <div className="card flex items-center justify-center h-32 text-muted">
          Select a completed scan to generate a security report.
        </div>
      )}

      {scanId && !data && !loading && (
        <div className="card flex items-center justify-center h-32 text-muted">
          No data available. Run a scan first.
        </div>
      )}

      {data && (
        <div className="space-y-5">
          {/* Score + overview */}
          <div className="card flex flex-col sm:flex-row items-center gap-6 p-5">
            <ScoreGauge score={data.security_score} />
            <div className="flex-1 space-y-2">
              <h2 className="text-lg font-bold text-primary">Executive Summary</h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-sm">
                <div><span className="text-muted">Target: </span><span className="text-primary">{data.scan?.target || "—"}</span></div>
                <div><span className="text-muted">Type: </span><span className="text-primary">{data.scan?.type?.toUpperCase()}</span></div>
                <div><span className="text-muted">Network Risk: </span>
                  <span className={data.network_risk_level === "CRITICAL" ? "text-red-400 font-bold" : data.network_risk_level === "HIGH" ? "text-orange-400 font-bold" : "text-green-400"}>
                    {data.network_risk_level}
                  </span>
                </div>
                <div><span className="text-muted">Hosts: </span><span className="text-primary">{data.hosts?.total}</span></div>
                <div><span className="text-muted">Vulnerabilities: </span><span className="text-primary">{data.vulnerabilities?.total}</span></div>
                <div><span className="text-muted">Attack Paths: </span><span className="text-primary">{data.attack_graph?.paths}</span></div>
              </div>
              {/* Key risk callouts */}
              <div className="flex flex-wrap gap-2 mt-2">
                {data.exploitability?.weaponized > 0 && (
                  <span className="badge badge-red">
                    {data.exploitability.weaponized} Weaponized Exploit(s)
                  </span>
                )}
                {data.vulnerabilities?.by_severity?.CRITICAL > 0 && (
                  <span className="badge badge-red">
                    {data.vulnerabilities.by_severity.CRITICAL} Critical CVE(s)
                  </span>
                )}
                {data.remediation?.immediate > 0 && (
                  <span className="badge badge-yellow">
                    {data.remediation.immediate} Immediate Action(s)
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Vulnerabilities */}
          <div className="card space-y-3">
            <SectionTitle icon={AlertTriangle} title="Vulnerability summary" />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <div key={sev} className="rounded-lg p-3 text-center" style={{ background: SEV_COLOR[sev] + "20", border: `1px solid ${SEV_COLOR[sev]}40` }}>
                  <p className="text-2xl font-bold" style={{ color: SEV_COLOR[sev] }}>
                    {data.vulnerabilities?.by_severity?.[sev] ?? 0}
                  </p>
                  <p className="text-xs text-muted mt-1">{sev}</p>
                </div>
              ))}
            </div>

            {data.vulnerabilities?.critical_cves?.length > 0 && (
              <div className="mt-2">
                <p className="text-xs text-muted mb-2">Critical CVEs (top 10)</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[var(--line)]">
                        {["CVE ID", "CVSS", "Service", "Port"].map((h) => (
                          <th key={h} className="text-left py-1.5 px-2 text-muted font-medium">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.vulnerabilities.critical_cves.map((v) => (
                        <tr key={v.id} className="border-b border-[var(--line)] hover:bg-[var(--surface-2)]">
                          <td className="py-1.5 px-2 font-mono text-red-300">{v.cve_id}</td>
                          <td className="py-1.5 px-2 text-orange-300 font-bold">{v.cvss}</td>
                          <td className="py-1.5 px-2 text-secondary">{v.affected_service || "—"}</td>
                          <td className="py-1.5 px-2 text-secondary">{v.affected_port || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Exploitability */}
          <div className="card space-y-3">
            <SectionTitle icon={ShieldCheck} title="Exploitability assessment" />
            <div className="flex flex-wrap gap-3">
              {[
                { label: "Weaponized", val: data.exploitability?.weaponized, mat: "WEAPONIZED" },
                { label: "Functional", val: data.exploitability?.functional, mat: "FUNCTIONAL" },
                { label: "POC",        val: data.exploitability?.poc,        mat: "POC" },
              ].map(({ label, val, mat }) => (
                <div key={label} className="flex items-center gap-2 bg-[var(--surface-2)] rounded-lg px-3 py-2">
                  <ExploitabilityBadge maturity={mat} size="xs" />
                  <span className="text-sm font-bold text-primary">{val ?? 0}</span>
                </div>
              ))}
            </div>

            {data.exploitability?.top?.length > 0 && (
              <div className="overflow-x-auto mt-2">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[var(--line)]">
                      {["CVE ID", "Maturity", "Score", "Attack Type", "Lateral Mvmt"].map((h) => (
                        <th key={h} className="text-left py-1.5 px-2 text-muted font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.exploitability.top.map((a) => (
                      <tr key={a.id} className="border-b border-[var(--line)] hover:bg-[var(--surface-2)]">
                        <td className="py-1.5 px-2 font-mono text-accent-text">{a.cve_id}</td>
                        <td className="py-1.5 px-2"><ExploitabilityBadge maturity={a.exploit_maturity} size="xs" /></td>
                        <td className="py-1.5 px-2 text-yellow-300 font-bold">{a.exploitability_score?.toFixed(1)}</td>
                        <td className="py-1.5 px-2 text-secondary">{a.attack_type}</td>
                        <td className="py-1.5 px-2 text-secondary">{a.lateral_movement_potential}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Attack Graph */}
          {data.attack_graph?.nodes > 0 && (
            <div className="card space-y-3">
              <SectionTitle icon={Crosshair} title="Attack graph" />
              <div className="grid grid-cols-3 gap-3 text-center">
                {[
                  { label: "Nodes", val: data.attack_graph.nodes },
                  { label: "Edges", val: data.attack_graph.edges },
                  { label: "Paths", val: data.attack_graph.paths },
                ].map(({ label, val }) => (
                  <div key={label} className="bg-[var(--surface-2)] rounded-lg p-3">
                    <p className="text-xl font-bold text-primary">{val}</p>
                    <p className="text-xs text-muted">{label}</p>
                  </div>
                ))}
              </div>
              {data.attack_graph?.top_paths?.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[var(--line)]">
                        {["Entry", "Target", "Hops", "Score", "Severity"].map((h) => (
                          <th key={h} className="text-left py-1.5 px-2 text-muted">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.attack_graph.top_paths.map((p) => (
                        <tr key={p.id} className="border-b border-[var(--line)]">
                          <td className="py-1.5 px-2 font-mono text-secondary">{p.entry_ip}</td>
                          <td className="py-1.5 px-2 font-mono text-secondary">{p.target_ip}</td>
                          <td className="py-1.5 px-2 text-secondary">{p.hop_count}</td>
                          <td className="py-1.5 px-2 text-yellow-300 font-bold">{p.total_score?.toFixed(1)}</td>
                          <td className="py-1.5 px-2">
                            <span className="font-semibold" style={{ color: SEV_COLOR[p.severity] ?? "#94a3b8" }}>
                              {p.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Remediation */}
          <div className="card space-y-3">
            <SectionTitle icon={Route} title={`Remediation plan (${data.remediation?.total ?? 0} items)`} />
            {data.remediation?.items?.length > 0 ? (
              <div>
                {data.remediation.items.map((r) => (
                  <RemediationCard key={r.id} item={r} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted">No remediation items available.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
