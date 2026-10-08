import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import Dashboard from "./pages/Dashboard";
import NetworkScan from "./pages/NetworkScan";
import DomainScan from "./pages/DomainScan";
import Topology from "./pages/Topology";
import { HistoryList, ScanDetail } from "./pages/History";
import Reports from "./pages/Reports";
import Vulnerabilities from "./pages/Vulnerabilities";
import AttackGraph from "./pages/AttackGraph";
import AttackPaths from "./pages/AttackPaths";
import Exploitability from "./pages/Exploitability";
import SecurityReport from "./pages/SecurityReport";
import Login from "./pages/Login";
import { getToken } from "./services/auth";

// Redirects to /login when there is no token. The real check is on the
// backend (every API route returns 401 without a valid token).
function RequireAuth({ children }) {
  return getToken() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="login" element={<Login />} />
        <Route element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route index element={<Dashboard />} />
          <Route path="scan/network" element={<NetworkScan />} />
          <Route path="scan/domain" element={<DomainScan />} />
          <Route path="topology" element={<Topology />} />
          <Route path="history" element={<HistoryList />} />
          <Route path="history/:id" element={<ScanDetail />} />
          <Route path="reports" element={<Reports />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="attack-graph" element={<AttackGraph />} />
          <Route path="attack-paths" element={<AttackPaths />} />
          <Route path="exploitability" element={<Exploitability />} />
          <Route path="security-report" element={<SecurityReport />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
