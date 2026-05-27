import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import Dashboard from "./pages/Dashboard";
import NetworkScan from "./pages/NetworkScan";
import DomainScan from "./pages/DomainScan";
import Topology from "./pages/Topology";
import { HistoryList, ScanDetail } from "./pages/History";
import Reports from "./pages/Reports";
import Vulnerabilities from "./pages/Vulnerabilities";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="scan/network" element={<NetworkScan />} />
          <Route path="scan/domain" element={<DomainScan />} />
          <Route path="topology" element={<Topology />} />
          <Route path="history" element={<HistoryList />} />
          <Route path="history/:id" element={<ScanDetail />} />
          <Route path="reports" element={<Reports />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
