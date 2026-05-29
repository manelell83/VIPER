import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { GitFork, RefreshCw } from "lucide-react";
import TopologyViewer from "../components/topology/TopologyViewer";
import { resultsApi, topologyApi } from "../services/api";
import { LoadingOverlay } from "../components/ui/Loading";

export default function Topology() {
  const [params] = useSearchParams();
  const initialScanId = params.get("scan");

  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(initialScanId || "");
  const [elements, setElements] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    resultsApi.list()
      .then((res) => {
        const completed = (res.scans || []).filter((s) => s.status === "completed");
        setScans(completed);
        if (!selectedScan && completed.length > 0) setSelectedScan(completed[0].id);
      })
      .catch(() => {});
  }, []);

  const loadTopology = (scanId) => {
    if (!scanId) return;
    setLoading(true);
    setError(null);
    topologyApi.get(scanId)
      .then((res) => {
        setElements(res.elements);
        setStats(res.stats);
      })
      .catch(() => setError("Failed to load topology. The scan may still be processing."))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadTopology(selectedScan); }, [selectedScan]);

  return (
    <div className="h-[calc(100vh-3rem)] flex flex-col gap-4 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-primary">Topology</h1>
          <p className="text-sm text-muted mt-0.5">Live network graph visualization</p>
        </div>
        <div className="flex items-center gap-3">
          {stats && (
            <div className="flex items-center gap-3 text-xs text-muted">
              <span>{stats.nodes} nodes</span>
              <span>·</span>
              <span>{stats.edges} edges</span>
            </div>
          )}
          <select
            className="input-field max-w-[220px] text-sm"
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
          >
            <option value="">Select a scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          <button
            className="btn-icon"
            onClick={() => loadTopology(selectedScan)}
            title="Refresh"
            disabled={loading}
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* Main topology canvas */}
      <div className="flex-1 min-h-0">
        {loading ? (
          <div className="h-full rounded-xl flex items-center justify-center"
            style={{ border: "1px solid var(--color-border)", background: "var(--color-topology-bg)" }}>
            <LoadingOverlay message="Building topology..." />
          </div>
        ) : error ? (
          <div className="h-full rounded-xl flex flex-col items-center justify-center gap-3"
            style={{ border: "1px solid var(--color-border)", background: "var(--color-topology-bg)" }}>
            <p className="text-orange-400 text-sm">{error}</p>
            <button className="btn-secondary text-xs" onClick={() => loadTopology(selectedScan)}>
              <RefreshCw size={13} /> Retry
            </button>
          </div>
        ) : !selectedScan ? (
          <div className="h-full rounded-xl flex items-center justify-center text-muted text-sm"
            style={{ border: "1px solid var(--color-border)", background: "var(--color-topology-bg)" }}>
            Select a completed scan to view the topology.
          </div>
        ) : (
          <TopologyViewer elements={elements} onNodeClick={setSelectedNode} />
        )}
      </div>
    </div>
  );
}
