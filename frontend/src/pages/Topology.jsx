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
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    resultsApi.list().then((res) => {
      const completed = res.scans.filter((s) => s.status === "completed");
      setScans(completed);
      if (!selectedScan && completed.length > 0) setSelectedScan(completed[0].id);
    });
  }, []);

  useEffect(() => {
    if (!selectedScan) return;
    setLoading(true);
    topologyApi.get(selectedScan)
      .then((res) => {
        setElements(res.elements);
        setStats(res.stats);
      })
      .finally(() => setLoading(false));
  }, [selectedScan]);

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
            onClick={() => selectedScan && setSelectedScan((v) => v)}
            title="Refresh"
          >
            <RefreshCw size={15} />
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
        ) : (
          <TopologyViewer elements={elements} onNodeClick={setSelectedNode} />
        )}
      </div>
    </div>
  );
}
