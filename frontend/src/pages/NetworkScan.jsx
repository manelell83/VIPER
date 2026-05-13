import { useState } from "react";
import { Play, Square, GitFork } from "lucide-react";
import { Link } from "react-router-dom";
import InterfaceSelector from "../components/scan/InterfaceSelector";
import ScanProgress from "../components/scan/ScanProgress";
import ScanResults from "../components/scan/ScanResults";
import { useScan } from "../hooks/useScan";

export default function NetworkScan() {
  const [selectedIface, setSelectedIface] = useState("");
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
          onChange={setSelectedIface}
          disabled={isRunning}
        />

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
