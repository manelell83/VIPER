import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function AppShell() {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "var(--bg)" }}>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 btn-primary"
      >
        Skip to content
      </a>
      <Sidebar />

      {/* Main content — offset by the sidebar width (w-60 = 240px) */}
      <main id="main" className="flex-1 ml-60 overflow-y-auto">
        <div className="min-h-screen px-8 py-8 max-w-[1440px] mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
