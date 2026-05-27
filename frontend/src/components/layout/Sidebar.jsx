import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, Network, Globe, GitFork,
  FileText, History, Shield, Sun, Moon, AlertTriangle, Crosshair, Route,
  ShieldAlert, ClipboardList,
} from "lucide-react";
import { useTheme } from "../../hooks/useTheme";

const NAV = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan/network", icon: Network, label: "Network Scan" },
  { to: "/scan/domain", icon: Globe, label: "Domain Scan" },
  { to: "/topology", icon: GitFork, label: "Topology" },
  { to: "/vulnerabilities", icon: AlertTriangle, label: "Vulnerabilities" },
  { to: "/attack-graph", icon: Crosshair, label: "Attack Graph" },
  { to: "/attack-paths", icon: Route, label: "Attack Paths" },
  { to: "/exploitability", icon: ShieldAlert, label: "Exploitability" },
  { to: "/security-report", icon: ClipboardList, label: "Security Report" },
  { to: "/history", icon: History, label: "History" },
  { to: "/reports", icon: FileText, label: "Reports" },
];

export default function Sidebar() {
  const { dark, toggle } = useTheme();

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-section">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center flex-shrink-0">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-primary leading-tight">ViperV2</p>
            <p className="text-xs text-muted leading-tight">Network Scanner</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `nav-item ${isActive ? "active" : ""}`
            }
          >
            <Icon size={16} className="flex-shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <button
          onClick={toggle}
          className="nav-item w-full"
          title={dark ? "Switch to light mode" : "Switch to dark mode"}
        >
          {dark ? <Sun size={16} /> : <Moon size={16} />}
          <span>{dark ? "Light Mode" : "Dark Mode"}</span>
        </button>
        <p className="text-xs text-muted mt-3 px-1">v2.0.0 · PFA 2026</p>
      </div>
    </aside>
  );
}
