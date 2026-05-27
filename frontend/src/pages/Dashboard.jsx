import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Network, Globe, Server, Lock, ArrowRight, Activity, Clock, AlertTriangle, ShieldAlert, Crosshair, Route } from "lucide-react";
import { resultsApi } from "../services/api";
import API from "../services/api";
import { StatusBadge } from "../components/ui/Badge";
import { LoadingOverlay } from "../components/ui/Loading";

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vulnStats, setVulnStats] = useState(null);

  useEffect(() => {
    resultsApi.list()
      .then((res) => setScans(res.scans))
      .catch(() => {})
      .finally(() => setLoading(false));

    API.get("/vulnerabilities/stats").then(setVulnStats).catch(() => {});
  }, []);

  const stats = {
    totalScans: scans.length,
    completed: scans.filter((s) => s.status === "completed").length,
    totalHosts: scans.reduce((a, s) => a + (s.hosts_count ?? 0), 0),
    running: scans.filter((s) => s.status === "running").length,
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-primary">Dashboard</h1>
        <p className="text-sm text-muted mt-1">Real-time network intelligence platform</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Total Scans" value={stats.totalScans} color="blue" />
        <StatCard icon={Server} label="Hosts Found" value={stats.totalHosts} color="green" />
        <StatCard icon={Lock} label="Completed" value={stats.completed} color="purple" />
        <StatCard icon={Clock} label="Running" value={stats.running} color="yellow" pulse={stats.running > 0} />
      </div>

      {/* Vulnerability stats */}
      {vulnStats && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-primary flex items-center gap-2">
              <ShieldAlert size={15} className="text-orange-400" />
              Vulnerability Overview
            </h2>
            <Link to="/vulnerabilities" className="text-xs text-info flex items-center gap-1 hover:underline">
              View all <ArrowRight size={11} />
            </Link>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: "Critical", value: vulnStats.by_severity?.critical ?? 0, color: "text-red-500 bg-red-500/10" },
              { label: "High",     value: vulnStats.by_severity?.high ?? 0,     color: "text-orange-500 bg-orange-500/10" },
              { label: "Medium",   value: vulnStats.by_severity?.medium ?? 0,   color: "text-yellow-500 bg-yellow-500/10" },
              { label: "Low",      value: vulnStats.by_severity?.low ?? 0,      color: "text-blue-500 bg-blue-500/10" },
              { label: "Total CVEs", value: vulnStats.total ?? 0,              color: "text-muted bg-[var(--color-bg-surface-hover)]" },
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
        <ActionCard
          to="/scan/network"
          icon={Network}
          title="Network Scan"
          desc="Auto-detect subnet and scan your LAN in real time"
          badge="ARP + Nmap"
          color="blue"
        />
        <ActionCard
          to="/scan/domain"
          icon={Globe}
          title="Domain / IP Scan"
          desc="Scan a specific domain, hostname, or IP address"
          badge="Port scan"
          color="purple"
        />
        <ActionCard
          to="/attack-graph"
          icon={Crosshair}
          title="Attack Graph"
          desc="Visualize attack paths and lateral movement possibilities"
          badge="Dynamic analysis"
          color="red"
        />
        <ActionCard
          to="/attack-paths"
          icon={Route}
          title="Attack Paths"
          desc="Browse ranked attack chains with CVE correlation"
          badge="Risk scoring"
          color="orange"
        />
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-primary">Recent Scans</h2>
          <Link to="/history" className="text-xs text-info flex items-center gap-1 hover:underline">
            View all <ArrowRight size={12} />
          </Link>
        </div>

        {loading ? (
          <LoadingOverlay message="Loading scans..." />
        ) : scans.length === 0 ? (
          <div className="py-8 text-center text-muted text-sm">
            No scans yet. Start your first scan above.
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
                        {scan.type}
                      </span>
                    </td>
                    <td className="font-mono text-xs">{scan.target}</td>
                    <td>{scan.hosts_count ?? 0}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td className="text-xs text-muted">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"}
                    </td>
                    <td>
                      <Link
                        to={`/history/${scan.id}`}
                        className="text-xs text-info hover:underline flex items-center gap-0.5"
                      >
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

function StatCard({ icon: Icon, label, value, color, pulse = false }) {
  const colors = {
    blue: "text-blue-500 bg-blue-500/10",
    green: "text-green-500 bg-green-500/10",
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
    blue:   "bg-blue-600 text-blue-50 hover:bg-blue-700",
    purple: "bg-purple-600 text-purple-50 hover:bg-purple-700",
    red:    "bg-red-700 text-red-50 hover:bg-red-800",
    orange: "bg-orange-600 text-orange-50 hover:bg-orange-700",
  };

  return (
    <Link to={to} className="card group block hover:ring-1 hover:ring-blue-500/30 transition-all duration-200">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${colorMap[color]}`}>
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
