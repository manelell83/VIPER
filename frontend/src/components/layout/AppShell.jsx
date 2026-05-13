import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function AppShell() {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "var(--color-bg-body)" }}>
      <Sidebar />

      {/* Main content — offset by sidebar width (w-52 = 208px) */}
      <main className="flex-1 ml-52 overflow-y-auto">
        <div className="min-h-screen p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
