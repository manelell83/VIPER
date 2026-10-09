import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Network, Globe, Server, Lock, ArrowRight, Activity, Clock,
  AlertTriangle, ShieldAlert, Crosshair, Route, ClipboardList,
  ShieldCheck, TrendingUp,
} from "lucide-react";
import { resultsApi } from "../services/api";
import API from "../services/api";
import { StatusBadge } from "../components/ui/Badge";
import { LoadingOverlay } from "../components/ui/Loading";

export default function Dashboard() {
  const [scans, setScans]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const [vulnStats, setVulnStats] = useState(null);
  const [secStats, setSecStats]   = useState(null);

  useEffect(() => {
    resultsApi.list()
      .then((res) => setScans(res.scans ?? []))
      .catch(() => {})
      .finally(() => setLoading(false));

    API.get("/vulnerabilities/stats")
      .then(setVulnStats)
      .catch(() => {});

    // Fetch latest completed scan's security summary
    resultsApi.list().then((res) => {
      const latest = (res.scans ?? []).find((s) => s.status === "completed");
      if (latest) {
        API.get(`/exploitability/security-summary?scan_id=${latest.id}`)
          .then(setSecStats)
          .catch(() => {});
      }
    }).catch(() => {});
  }, []);

  const stats = {
    totalScans:  scans.length,
    completed:   scans.filter((s) => s.status === "completed").length,
    totalHosts:  scans.reduce((a, s) => a + (s.hosts_count ?? 0), 0),
    running:     scans.filter((s) => s.status === "running").length,
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-primary">Dashboard</h1>
          <p className="text-sm text-muted mt-1">Intelligent Network Security Assessment Platform</p>
        </div>
        {stats.running > 0 && (
          <div className="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-400/10 border border-yellow-400/30 rounded-full px-3 py-1.5">
            <span className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse" />
            {stats.running} scan{stats.running > 1 ? "s" : ""} in progress
          </div>
        )}
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Total Scans"  value={stats.totalScans}  color="blue"   />
        <StatCard icon={Server}   label="Hosts Found"  value={stats.totalHosts}  color="green"  />
        <StatCard icon={Lock}     label="Completed"    value={stats.completed}   color="purple" />
        <StatCard icon={Clock}    label="Running"      value={stats.running}     color="yellow" pulse={stats.running > 0} />
      </div>

      {/* Security score + latest scan summary */}
      {secStats && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-primary flex items-center gap-2">
              <ShieldCheck size={15} className="text-blue-400" />
              Latest Security Assessment
            </h2>
            <Link to="/app/security-report" className="text-xs text-info flex items-center gap-1 hover:underline">
              Full Report <ArrowRight size={11} />
            </Link>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <SecurityScoreCell score={secStats.security_score} />
            <div className="rounded-lg p-3 bg-slate-800/50 text-center">
              <p className="text-xl font-bold text-red-400">{secStats.exploitability?.weaponized ?? 0}</p>
              <p className="text-xs text-muted mt-0.5">Weaponized</p>
            </div>
            <div className="rounded-lg p-3 bg-slate-800/50 text-center">
              <p className="text-xl font-bold text-purple-400">{secStats.attack_graph?.paths ?? 0}</p>
              <p className="text-xs text-muted mt-0.5">Attack Paths</p>
            </div>
            <div className="rounded-lg p-3 bg-slate-800/50 text-center">
              <p className={`text-xl font-bold ${RISK_COLOR[secStats.network_risk_level] ?? "text-gray-400"}`}>
                {secStats.network_risk_level ?? "N/A"}
              </p>
              <p className="text-xs text-muted mt-0.5">Network Risk</p>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability stats */}
      {vulnStats && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-primary flex items-center gap-2">
              <ShieldAlert size={15} className="text-orange-400" />
              Vulnerability Overview
            </h2>
            <Link to="/app/vulnerabilities" className="text-xs text-info flex items-center gap-1 hover:underline">
              View all <ArrowRight size={11} />
            </Link>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: "Critical", value: vulnStats.by_severity?.critical ?? 0, color: "text-red-500 bg-red-500/10" },
              { label: "High",     value: vulnStats.by_severity?.high ?? 0,     color: "text-orange-500 bg-orange-500/10" },
              { label: "Medium",   value: vulnStats.by_severity?.medium ?? 0,   color: "text-yellow-500 bg-yellow-500/10" },
              { label: "Low",      value: vulnStats.by_severity?.low ?? 0,      color: "text-blue-400 bg-blue-400/10" },
              { label: "Total CVEs", value: vulnStats.total ?? 0,               color: "text-muted bg-slate-800/50" },
            ].map(({ label, value, color }) => (
              <div key={label} className={`rounded-xl p-3 text-center ${color}`}>
                <p className="text-lg font-bold">{value}</p>
                <p className="text-xs mt-0.5 opacity-80">{label}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ActionCard to="/app/scan/network"    icon={Network}       title="Network Scan"       desc="Auto-detect subnet and discover all LAN hosts"                 badge="ARP + Nmap"       color="blue"   />
        <ActionCard to="/app/scan/domain"     icon={Globe}         title="Domain / IP Scan"   desc="Scan a specific domain, hostname, or IP address"              badge="Port scan"        color="purple" />
        <ActionCard to="/app/attack-graph"    icon={Crosshair}     title="Attack Graph"        desc="Visualize attack paths and lateral movement possibilities"    badge="Dynamic analysis" color="red"    />
        <ActionCard to="/app/security-report" icon={ClipboardList} title="Security Report"     desc="Full assessment with score, exploitability and remediation"   badge="PDF Export"       color="orange" />
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-primary flex items-center gap-2">
            <TrendingUp size={15} className="text-blue-400" />
            Recent Scans
          </h2>
          <Link to="/app/history" className="text-xs text-info flex items-center gap-1 hover:underline">
            View all <ArrowRight size={12} />
          </Link>
        </div>

        {loading ? (
          <LoadingOverlay message="Loading scans..." />
        ) : scans.length === 0 ? (
          <div className="py-10 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-blue-500/10 flex items-center justify-center mx-auto">
              <Network size={20} className="text-blue-500 opacity-50" />
            </div>
            <p className="text-muted text-sm">No scans yet.</p>
            <div className="flex justify-center gap-3">
              <Link to="/app/scan/network" className="btn-primary text-xs px-3 py-1.5">Network Scan</Link>
              <Link to="/app/scan/domain"  className="btn-secondary text-xs px-3 py-1.5">Domain Scan</Link>
            </div>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Target</th>
                  <th>Hosts</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <span className="flex items-center gap-1.5 text-tertiary">
                        {scan.type === "network" ? <Network size={13} /> : <Globe size={13} />}
                        <span className="capitalize">{scan.type}</span>
                      </span>
                    </td>
                    <td className="font-mono text-xs max-w-[180px] truncate">{scan.target}</td>
                    <td className="font-medium">{scan.hosts_count ?? 0}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td className="text-xs text-muted">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                    </td>
                    <td>
                      <Link to={`/app/history/${scan.id}`} className="text-xs text-info hover:underline flex items-center gap-0.5">
                        View <ArrowRight size={11} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

const RISK_COLOR = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-green-400",
  NONE:     "text-slate-400",
};

function SecurityScoreCell({ score }) {
  const color = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : score >= 40 ? "text-orange-400" : "text-red-400";
  const label = score >= 80 ? "Secure" : score >= 60 ? "Moderate" : score >= 40 ? "At Risk" : "Critical";
  return (
    <div className="rounded-lg p-3 bg-slate-800/50 text-center">
      <p className={`text-2xl font-black ${color}`}>{score}</p>
      <p className={`text-xs font-semibold mt-0.5 ${color}`}>{label}</p>
      <p className="text-[10px] text-muted">/ 100</p>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color, pulse = false }) {
  const colors = {
    blue:   "text-blue-500 bg-blue-500/10",
    green:  "text-green-500 bg-green-500/10",
    purple: "text-purple-500 bg-purple-500/10",
    yellow: "text-yellow-500 bg-yellow-500/10",
  };

  return (
    <div className="card-sm">
      <div className="flex items-center gap-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${colors[color]} ${pulse ? "animate-pulse-ring" : ""}`}>
          <Icon size={16} className={colors[color].split(" ")[0]} />
        </div>
        <div>
          <p className="text-xl font-bold text-primary">{value}</p>
          <p className="text-xs text-muted">{label}</p>
        </div>
      </div>
    </div>
  );
}

function ActionCard({ to, icon: Icon, title, desc, badge, color }) {
  const colorMap = {
    blue:   "bg-blue-600 hover:bg-blue-700",
    purple: "bg-purple-600 hover:bg-purple-700",
    red:    "bg-red-700 hover:bg-red-800",
    orange: "bg-orange-600 hover:bg-orange-700",
  };

  return (
    <Link to={to} className="card group block hover:ring-1 hover:ring-blue-500/30 transition-all duration-200">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-white ${colorMap[color]}`}>
            <Icon size={18} />
          </div>
          <div>
            <p className="font-semibold text-primary">{title}</p>
            <p className="text-xs text-muted mt-0.5">{badge}</p>
          </div>
        </div>
        <ArrowRight size={16} className="text-muted group-hover:text-primary group-hover:translate-x-1 transition-all" />
      </div>
      <p className="text-sm text-tertiary mt-3">{desc}</p>
    </Link>
  );
}
