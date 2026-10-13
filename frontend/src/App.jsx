import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import Dashboard from "./pages/Dashboard";
import NetworkScan from "./pages/NetworkScan";
import DomainScan from "./pages/DomainScan";
import DomainRecon from "./pages/DomainRecon";
import Topology from "./pages/Topology";
import { HistoryList, ScanDetail } from "./pages/History";
import Reports from "./pages/Reports";
import Vulnerabilities from "./pages/Vulnerabilities";
import AttackGraph from "./pages/AttackGraph";
import AttackPaths from "./pages/AttackPaths";
import Exploitability from "./pages/Exploitability";
import SecurityReport from "./pages/SecurityReport";
import Login from "./pages/Login";
import Landing from "./pages/Landing";
import Signup from "./pages/Signup";
import Users from "./pages/Users";
import { getToken } from "./services/auth";

// Redirects to /login when there is no token. The real check is on the
// backend (every API route returns 401 without a valid token).
function RequireAuth({ children }) {
  return getToken() ? children : <Navigate to="/login" replace />;
}

// The app used to live at the root (/vulnerabilities, /history/:id, ...).
// Old URLs are redirected to /app/..., keeping the query string.
const LEGACY_SECTIONS = [
  "scan", "topology", "history", "reports", "vulnerabilities",
  "attack-graph", "attack-paths", "exploitability", "security-report",
];

function NotFound() {
  const { pathname, search } = useLocation();
  const section = pathname.split("/")[1];
  if (LEGACY_SECTIONS.includes(section)) {
    return <Navigate to={`/app${pathname}${search}`} replace />;
  }
  return <Navigate to="/" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route index element={<Landing />} />
        <Route path="login" element={<Login />} />
        <Route path="signup" element={<Signup />} />

        <Route path="app" element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route index element={<Dashboard />} />
          <Route path="scan/network" element={<NetworkScan />} />
          <Route path="scan/domain" element={<DomainScan />} />
        <Route path="recon" element={<DomainRecon />} />
          <Route path="topology" element={<Topology />} />
          <Route path="history" element={<HistoryList />} />
          <Route path="history/:id" element={<ScanDetail />} />
          <Route path="reports" element={<Reports />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="attack-graph" element={<AttackGraph />} />
          <Route path="attack-paths" element={<AttackPaths />} />
          <Route path="exploitability" element={<Exploitability />} />
          <Route path="security-report" element={<SecurityReport />} />
          <Route path="users" element={<Users />} />
          <Route path="*" element={<Navigate to="/app" replace />} />
        </Route>

        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}
