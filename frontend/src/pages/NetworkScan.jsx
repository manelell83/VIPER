import { useState } from "react";
import { Play, Square, GitFork, Info, AlertTriangle } from "lucide-react";
import { Link } from "react-router-dom";
import InterfaceSelector from "../components/scan/InterfaceSelector";
import ScanProgress from "../components/scan/ScanProgress";
import ScanResults from "../components/scan/ScanResults";
import AuthorizationConfirm from "../components/scan/AuthorizationConfirm";
import { useScan } from "../hooks/useScan";
import PageHeader from "../components/ui/PageHeader";

export default function NetworkScan() {
  const [selectedIface, setSelectedIface] = useState("");
  const [ifaceInfo, setIfaceInfo] = useState(null);
  // Confirmation applies to one network: changing the interface clears it
  const [authorized, setAuthorized] = useState(false);
  // Number of host addresses in the selected subnet (e.g. /24 -> 254, /16 -> 65,534)
  const subnetHosts = ifaceInfo?.prefix_len != null ? 2 ** (32 - ifaceInfo.prefix_len) - 2 : null;
  const { status, progress, message, hosts, logs, error, scanId, startNetworkScan, reset } = useScan();

  const isRunning = status === "running" || status === "starting";
  const isDone = status === "completed";
  const hasStarted = status !== "idle";

  const handleStart = () => {
    if (!selectedIface) return;
    if (!authorized) return;
    startNetworkScan(selectedIface, authorized);
  };

  return (
    <div className="max-w-4xl space-y-6 animate-fadeIn">
      <PageHeader
        eyebrow="Scan"
        title="Network scan"
        subtitle="Pick an interface: VIPER computes its subnet and discovers every host on it."
      >
        {isDone && scanId && (
          <Link
            to={`/app/topology?scan=${scanId}`}
            className="btn-info"
          >
            <GitFork size={15} />
            View Topology
          </Link>
        )}
      </PageHeader>

      {/* Config card */}
      <div className="card space-y-5">
        <InterfaceSelector
          value={selectedIface}
          onChange={(name, iface) => { setSelectedIface(name); setIfaceInfo(iface ?? null); setAuthorized(false); }}
          disabled={isRunning}
        />

        <div className="flex gap-2 rounded-lg p-3 text-xs text-secondary"
             style={{ background: "var(--color-bg-surface-hover)", border: "1px solid var(--color-border)" }}>
          <Info size={14} className="flex-shrink-0 mt-0.5 text-info" />
          <p>
            LAN discovery only sees your real network when the backend runs directly on this
            machine with administrator/root rights (and Npcap on Windows). If VIPER runs in
            Docker, the interfaces listed here belong to the container&apos;s internal network,
            not your LAN — use <span className="text-primary">Domain / IP Scan</span> instead.
          </p>
        </div>

        {subnetHosts > 254 && (
          <div className="flex gap-2 rounded-lg p-3 text-xs text-warning"
               style={{ background: "rgba(234, 179, 8, 0.08)", border: "1px solid rgba(234, 179, 8, 0.3)" }}>
            <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
            <p>
              <span className="font-mono">{ifaceInfo.subnet}</span> contains{" "}
              {subnetHosts.toLocaleString("en-US")} addresses. Scanning it can take a very long time;
              a /24 network or smaller is recommended.
            </p>
          </div>
        )}

        <AuthorizationConfirm
          checked={authorized}
          onChange={setAuthorized}
          target={ifaceInfo?.subnet}
          disabled={isRunning || !selectedIface}
        />

        <div className="flex items-center gap-3 pt-2">
          {!isRunning ? (
            <button
              className="btn-primary"
              disabled={!selectedIface || !authorized}
              onClick={handleStart}
            >
              <Play size={15} />
              {hasStarted ? "Restart Scan" : "Start Scan"}
            </button>
          ) : (
            <button className="btn-danger" onClick={reset}>
              <Square size={15} />
              Stop
            </button>
          )}

          {hasStarted && !isRunning && (
            <button className="btn-secondary" onClick={reset}>
              New Scan
            </button>
          )}

          {selectedIface && !hasStarted && (
            <p className="text-xs text-muted">
              Will auto-scan the subnet of <span className="font-mono text-primary">{selectedIface}</span>
            </p>
          )}
        </div>
      </div>

      {/* Progress */}
      {hasStarted && (
        <div className="card">
          <h2 className="section-title mb-4">Scan progress</h2>
          <ScanProgress
            status={status}
            progress={progress}
            message={message}
            logs={logs}
            error={error}
          />
        </div>
      )}

      {/* Live results */}
      {hosts.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="section-title flex items-center gap-2">
              Discovered hosts
              <span className="badge badge-gray">{hosts.length}</span>
            </h2>
          </div>
          <ScanResults hosts={hosts} />
        </div>
      )}
    </div>
  );
}
