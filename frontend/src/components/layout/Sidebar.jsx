import { Link, NavLink } from "react-router-dom";
import {
  LayoutDashboard, Network, Globe, GitFork,
  FileText, History, Sun, Moon, AlertTriangle, Crosshair, Route,
  ShieldAlert, ClipboardList, LogOut, UserPlus, Radar,
} from "lucide-react";
import { useTheme } from "../../hooks/useTheme";
import { getUser, clearSession } from "../../services/auth";
import Logo from "../brand/Logo";

// Paths are relative to the authenticated area (/app)
const NAV_GROUPS = [
  {
    label: "Scan",
    items: [
      { to: "/app", icon: LayoutDashboard, label: "Dashboard", end: true },
      { to: "/app/scan/network", icon: Network, label: "Network Scan" },
      { to: "/app/scan/domain", icon: Globe, label: "Domain Scan" },
      { to: "/app/recon", icon: Radar, label: "Domain Recon" },
    ],
  },
  {
    label: "Analysis",
    items: [
      { to: "/app/topology", icon: GitFork, label: "Topology" },
      { to: "/app/vulnerabilities", icon: AlertTriangle, label: "Vulnerabilities" },
      { to: "/app/attack-graph", icon: Crosshair, label: "Attack Graph" },
      { to: "/app/attack-paths", icon: Route, label: "Attack Paths" },
      { to: "/app/exploitability", icon: ShieldAlert, label: "Exploitability" },
    ],
  },
  {
    label: "Reporting",
    items: [
      { to: "/app/security-report", icon: ClipboardList, label: "Security Report" },
      { to: "/app/history", icon: History, label: "History" },
      { to: "/app/reports", icon: FileText, label: "Reports" },
    ],
  },
];

// Shown only to admins. The backend enforces the role (403 for analysts).
const ADMIN_GROUP = {
  label: "Admin",
  items: [{ to: "/app/users", icon: UserPlus, label: "Users" }],
};

export default function Sidebar() {
  const { dark, toggle } = useTheme();
  const user = getUser();
  const groups = user?.role === "admin" ? [...NAV_GROUPS, ADMIN_GROUP] : NAV_GROUPS;

  const logout = () => {
    clearSession();
    window.location.assign("/login");
  };

  return (
    <aside className="sidebar" aria-label="Main navigation">
      <div className="sidebar-section">
        <Link to="/app" aria-label="VIPER dashboard">
          <Logo size={26} subtitle="Risk analysis" />
        </Link>
      </div>

      <nav className="flex-1 px-3 pb-3 overflow-y-auto">
        {groups.map((group) => (
          <div key={group.label}>
            <p className="nav-group-label">{group.label}</p>
            <div className="space-y-0.5">
              {group.items.map(({ to, icon: Icon, label, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                >
                  <Icon size={16} className="flex-shrink-0" />
                  <span>{label}</span>
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="sidebar-footer space-y-1">
        {user && (
          <div className="flex items-center gap-3 px-3 py-2 mb-1">
            <span
              className="w-8 h-8 rounded-full flex items-center justify-center font-display font-semibold text-sm"
              style={{ background: "var(--accent-soft)", color: "var(--accent-text)" }}
              aria-hidden="true"
            >
              {user.username.slice(0, 1).toUpperCase()}
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-primary truncate">{user.username}</span>
              <span className="block font-mono uppercase text-muted" style={{ fontSize: "0.65rem", letterSpacing: "0.1em" }}>
                {user.role}
              </span>
            </span>
          </div>
        )}
        <button onClick={toggle} className="nav-item" title={dark ? "Switch to light mode" : "Switch to dark mode"}>
          {dark ? <Sun size={16} /> : <Moon size={16} />}
          <span>{dark ? "Light theme" : "Dark theme"}</span>
        </button>
        <button onClick={logout} className="nav-item">
          <LogOut size={16} />
          <span>Sign out</span>
        </button>
      </div>
    </aside>
  );
}
