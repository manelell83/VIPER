import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Network, Globe, Server, CheckCircle2, ArrowRight, Activity, Clock,
  Crosshair, ClipboardList,
} from "lucide-react";
import { resultsApi } from "../services/api";
import API from "../services/api";
import { StatusBadge } from "../components/ui/Badge";
import { LoadingOverlay } from "../components/ui/Loading";
import PageHeader from "../components/ui/PageHeader";
import SeverityBar from "../components/ui/SeverityBar";

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

  const severity = vulnStats && {
    critical: vulnStats.by_severity?.critical ?? 0,
    high: vulnStats.by_severity?.high ?? 0,
    medium: vulnStats.by_severity?.medium ?? 0,
    low: vulnStats.by_severity?.low ?? 0,
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <PageHeader eyebrow="Overview" title="Dashboard" subtitle="Your scans, risk level and priorities at a glance.">
        {stats.running > 0 && (
          <span className="badge badge-yellow">
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
            {stats.running} scan{stats.running > 1 ? "s" : ""} in progress
          </span>
        )}
      </PageHeader>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Activity}     label="Total scans" value={stats.totalScans} />
        <StatCard icon={Server}       label="Hosts found" value={stats.totalHosts} />
        <StatCard icon={CheckCircle2} label="Completed"   value={stats.completed} />
        <StatCard icon={Clock}        label="Running"     value={stats.running} live={stats.running > 0} />
      </div>

      <div className="grid gap-6 xl:grid-cols-5">
        {/* Latest security assessment */}
        <section className="card xl:col-span-2 flex flex-col">
          <div className="flex items-center justify-between">
            <h2 className="section-title">Latest assessment</h2>
            {secStats && (
              <Link to="/app/security-report" className="link text-xs inline-flex items-center gap-1">
                Full report <ArrowRight size={12} />
              </Link>
            )}
          </div>
          {secStats ? (
            <div className="mt-5 flex items-center gap-6 flex-1">
              <ScoreRing score={secStats.security_score} />
              <dl className="grid gap-4 flex-1">
                <Metric label="Network risk" value={secStats.network_risk_level ?? "N/A"} className={RISK_COLOR[secStats.network_risk_level]} />
                <Metric label="Attack paths" value={secStats.attack_graph?.paths ?? 0} />
                <Metric label="Weaponized exploits" value={secStats.exploitability?.weaponized ?? 0} />
              </dl>
            </div>
          ) : (
            <p className="mt-5 text-sm text-muted">Run a scan to get a security score.</p>
          )}
        </section>

        {/* Vulnerability overview */}
        <section className="card xl:col-span-3">
          <div className="flex items-center justify-between">
            <h2 className="section-title">Vulnerabilities by severity</h2>
            <Link to="/app/vulnerabilities" className="link text-xs inline-flex items-center gap-1">
              View all <ArrowRight size={12} />
            </Link>
          </div>
          {severity ? (
            <>
              <p className="mt-5 flex items-baseline gap-2">
                <span className="stat-value text-4xl text-primary">{vulnStats.total ?? 0}</span>
                <span className="text-sm text-muted">CVEs across all scans</span>
              </p>
              <SeverityBar counts={severity} className="mt-5" />
            </>
          ) : (
            <p className="mt-5 text-sm text-muted">No vulnerability data yet.</p>
          )}
        </section>
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <ActionCard to="/app/scan/network"    icon={Network}       title="Network scan"    desc="Discover the hosts of a local network (ARP + Nmap)." />
        <ActionCard to="/app/scan/domain"     icon={Globe}         title="Domain / IP scan" desc="Scan one hostname or IPv4 address." />
        <ActionCard to="/app/attack-graph"    icon={Crosshair}     title="Attack graph"    desc="See entry points and lateral movement." />
        <ActionCard to="/app/security-report" icon={ClipboardList} title="Security report" desc="Score, exploitability and remediation, as PDF." />
      </div>

      {/* Recent scans */}
      <section className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="section-title">Recent scans</h2>
          <Link to="/app/history" className="link text-xs inline-flex items-center gap-1">
            Full history <ArrowRight size={12} />
          </Link>
        </div>

        {loading ? (
          <LoadingOverlay message="Loading scans..." />
        ) : scans.length === 0 ? (
          <div className="py-10 text-center space-y-4">
            <p className="text-muted text-sm">No scans yet. Start with one of these:</p>
            <div className="flex justify-center gap-3">
              <Link to="/app/scan/domain"  className="btn-primary">Domain / IP scan</Link>
              <Link to="/app/scan/network" className="btn-secondary">Network scan</Link>
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
                  <th><span className="sr-only">Actions</span></th>
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
                    <td className="font-mono text-xs max-w-[220px] truncate text-primary">{scan.target}</td>
                    <td className="font-medium">{scan.hosts_count ?? 0}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td className="text-xs text-muted">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                    </td>
                    <td className="text-right">
                      <Link to={`/app/history/${scan.id}`} className="link text-xs inline-flex items-center gap-0.5">
                        View <ArrowRight size={11} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

const RISK_COLOR = {
  CRITICAL: "text-danger",
  HIGH:     "text-orange-500 dark:text-orange-400",
  MEDIUM:   "text-warning",
  LOW:      "text-success",
  NONE:     "text-muted",
};

function scoreColor(score) {
  if (score >= 80) return "var(--success-text)";
  if (score >= 60) return "var(--warning-text)";
  if (score >= 40) return "var(--sev-high)";
  return "var(--danger-text)";
}

/** Circular 0–100 security score (higher is better). */
function ScoreRing({ score = 0 }) {
  const label = score >= 80 ? "Secure" : score >= 60 ? "Moderate" : score >= 40 ? "At risk" : "Critical";
  const r = 42;
  const circumference = 2 * Math.PI * r;
  const color = scoreColor(score);
  return (
    <div className="relative w-32 h-32 flex-shrink-0" role="img" aria-label={`Security score ${score} out of 100, ${label}`}>
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--line)" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={circumference * (1 - score / 100)}
          style={{ transition: "stroke-dashoffset 600ms var(--ease)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="stat-value text-3xl text-primary">{score}</span>
        <span className="text-[11px] font-semibold mt-1" style={{ color }}>{label}</span>
      </div>
    </div>
  );
}

function Metric({ label, value, className = "text-primary" }) {
  return (
    <div className="flex items-baseline justify-between gap-4" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "0.6rem" }}>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={`font-display font-semibold ${className}`}>{value}</dd>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, live = false }) {
  return (
    <div className="card-sm">
      <div className="flex items-center justify-between">
        <p className="font-mono uppercase text-muted" style={{ fontSize: "0.68rem", letterSpacing: "0.1em" }}>{label}</p>
        <Icon size={16} className={live ? "text-accent-text animate-pulse" : "text-muted"} aria-hidden="true" />
      </div>
      <p className="stat-value text-3xl text-primary mt-3">{value}</p>
    </div>
  );
}

function ActionCard({ to, icon: Icon, title, desc }) {
  return (
    <Link to={to} className="card card-link group block">
      <div className="flex items-start justify-between">
        <span className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ background: "var(--accent-soft)", color: "var(--accent-text)" }}>
          <Icon size={18} aria-hidden="true" />
        </span>
        <ArrowRight size={16} className="text-muted group-hover:text-accent-text transition-transform duration-200 group-hover:translate-x-1" />
      </div>
      <p className="section-title mt-4">{title}</p>
      <p className="text-sm text-tertiary mt-1">{desc}</p>
    </Link>
  );
}
