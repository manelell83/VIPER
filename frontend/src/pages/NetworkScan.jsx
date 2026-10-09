import { useState } from "react";
import { Play, Square, GitFork, Info, AlertTriangle } from "lucide-react";
import { Link } from "react-router-dom";
import InterfaceSelector from "../components/scan/InterfaceSelector";
import ScanProgress from "../components/scan/ScanProgress";
import ScanResults from "../components/scan/ScanResults";
import { useScan } from "../hooks/useScan";

export default function NetworkScan() {
  const [selectedIface, setSelectedIface] = useState("");
  const [ifaceInfo, setIfaceInfo] = useState(null);
  // Number of host addresses in the selected subnet (e.g. /24 -> 254, /16 -> 65,534)
  const subnetHosts = ifaceInfo?.prefix_len != null ? 2 ** (32 - ifaceInfo.prefix_len) - 2 : null;
  const { status, progress, message, hosts, logs, error, scanId, startNetworkScan, reset } = useScan();

  const isRunning = status === "running" || status === "starting";
  const isDone = status === "completed";
  const hasStarted = status !== "idle";

  const handleStart = () => {
    if (!selectedIface) return;
    startNetworkScan(selectedIface);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-primary">Network Scan</h1>
          <p className="text-sm text-muted mt-1">
            Automatically detect subnet and discover all LAN hosts
          </p>
        </div>
        {isDone && scanId && (
          <Link
            to={`/topology?scan=${scanId}`}
            className="btn-info"
          >
            <GitFork size={15} />
            View Topology
          </Link>
        )}
      </div>

      {/* Config card */}
      <div className="card space-y-5">
        <InterfaceSelector
          value={selectedIface}
          onChange={(name, iface) => { setSelectedIface(name); setIfaceInfo(iface ?? null); }}
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

        <div className="flex items-center gap-3 pt-2">
          {!isRunning ? (
            <button
              className="btn-primary"
              disabled={!selectedIface}
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
          <h2 className="text-sm font-semibold text-primary mb-4">Scan Progress</h2>
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
            <h2 className="text-sm font-semibold text-primary">
              Discovered Hosts
              <span className="ml-2 badge badge-blue">{hosts.length}</span>
            </h2>
          </div>
          <ScanResults hosts={hosts} />
        </div>
      )}
    </div>
  );
}
