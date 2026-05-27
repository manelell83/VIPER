import { useEffect, useState, useCallback } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Shield, AlertTriangle, RefreshCw, Network, ChevronRight, Target, Zap } from "lucide-react";
import AttackGraphViewer from "../components/attack/AttackGraphViewer";
import AttackPathList from "../components/attack/AttackPathList";
import { LoadingOverlay } from "../components/ui/Loading";
import { resultsApi } from "../services/api";
import API from "../services/api";

const RISK_COLORS = {
  CRITICAL: { text: "text-red-400", bg: "bg-red-500/10 border-red-500/40" },
  HIGH:     { text: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/40" },
  MEDIUM:   { text: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/40" },
  LOW:      { text: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/40" },
  NONE:     { text: "text-muted", bg: "" },
};

export default function AttackGraph() {
  const [params] = useSearchParams();
  const initialScanId = params.get("scan");

  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(initialScanId || "");
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [highlightedPath, setHighlightedPath] = useState(null);

  // Load completed scans
  useEffect(() => {
    resultsApi.list().then((res) => {
      const completed = res.scans.filter((s) => s.status === "completed");
      setScans(completed);
      if (!selectedScan && completed.length > 0) setSelectedScan(completed[0].id);
    });
  }, []);

  // Load attack graph
  const load = useCallback(() => {
    if (!selectedScan) return;
    setLoading(true);
    setError(null);
    setGraphData(null);

    API.get(`/attack-graph/${selectedScan}`)
      .then(setGraphData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedScan]);

  useEffect(() => { load(); }, [load]);

  const regenerate = () => {
    if (!selectedScan) return;
    setLoading(true);
    API.post(`/attack-graph/${selectedScan}/regenerate`)
      .then(() => load())
      .catch((e) => { setError(e.message); setLoading(false); });
  };

  const riskLevel = graphData?.stats?.risk_level ?? "NONE";
  const riskColor = RISK_COLORS[riskLevel] ?? RISK_COLORS.NONE;
  const analysis = graphData?.risk_analysis;

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-primary flex items-center gap-2">
            <Network size={22} className="text-red-400" />
            Attack Graph
          </h1>
          <p className="text-sm text-muted mt-1">
            Dynamic attack path visualization from real scan data
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            className="input-field max-w-[240px] text-sm"
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
            onClick={regenerate}
            disabled={!selectedScan || loading}
            title="Regenerate attack graph"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {graphData?.stats && (
        <div className={`flex items-center gap-4 rounded-xl px-4 py-3 border flex-shrink-0 ${riskColor.bg}`}>
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className={riskColor.text} />
            <span className={`text-sm font-bold ${riskColor.text}`}>{riskLevel} RISK</span>
          </div>
          <div className="h-4 w-px bg-[var(--color-border)]" />
          <StatPill label="Nodes" value={graphData.stats.nodes} />
          <StatPill label="Attack Edges" value={graphData.stats.edges} />
          <StatPill label="Paths" value={graphData.stats.paths} />
          <StatPill label="Entry Points" value={graphData.stats.entry_points} />
          {analysis?.most_dangerous_host && (
            <>
              <div className="h-4 w-px bg-[var(--color-border)]" />
              <div className="flex items-center gap-1.5 text-xs">
                <Target size={12} className="text-red-400" />
                <span className="text-muted">Most Dangerous:</span>
                <span className="font-mono text-red-300">{analysis.most_dangerous_host.ip}</span>
              </div>
            </>
          )}
        </div>
      )}

      {error && (
        <div className="card-sm border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center" style={{ height: "calc(100vh - 210px)" }}>
          <LoadingOverlay message="Generating attack graph from scan data…" />
        </div>
      ) : !selectedScan ? (
        <div className="card py-16 text-center">
          <Network size={36} className="mx-auto text-muted opacity-20 mb-3" />
          <p className="text-muted text-sm">Select a completed scan to generate the attack graph.</p>
        </div>
      ) : (
        <div className="flex gap-4" style={{ height: "calc(100vh - 210px)" }}>
          {/* Main graph (left) */}
          <div className="flex-1 min-w-0">
            <AttackGraphViewer
              elements={graphData?.elements}
              highlightedPath={highlightedPath}
            />
          </div>

          {/* Right panel */}
          <div className="w-[340px] flex-shrink-0 flex flex-col gap-4 overflow-y-auto">
            {/* Risk Analysis */}
            {analysis && (
              <div className="card flex-shrink-0">
                <h2 className="text-sm font-semibold text-primary mb-3 flex items-center gap-2">
                  <Zap size={14} className="text-yellow-400" />
                  Risk Analysis
                </h2>

                {analysis.weakest_entry && (
                  <div className="rounded-xl p-3 mb-3" style={{ background: "var(--color-bg-surface-hover)" }}>
                    <p className="text-xs font-semibold text-orange-400 mb-1">Weakest Entry Point</p>
                    <p className="text-sm font-mono text-primary">{analysis.weakest_entry.ip}</p>
                    <p className="text-xs text-muted mt-0.5">{analysis.weakest_entry.attack_vector}</p>
                    <p className="text-xs text-orange-400 mt-1">Score: {analysis.weakest_entry.score}/100</p>
                  </div>
                )}

                {analysis.recommendations?.length > 0 && (
                  <div className="space-y-2">
                    {analysis.recommendations.slice(0, 3).map((rec, i) => (
                      <RecommendationCard key={i} rec={rec} />
                    ))}
                  </div>
                )}

                <Link
                  to={`/attack-paths?scan=${selectedScan}`}
                  className="mt-3 flex items-center gap-1 text-xs text-info hover:underline"
                >
                  View all attack paths <ChevronRight size={12} />
                </Link>
              </div>
            )}

            {/* Attack Paths */}
            <div className="card flex-1 min-h-0 overflow-y-auto">
              <h2 className="text-sm font-semibold text-primary mb-3 flex items-center justify-between">
                <span>Attack Paths</span>
                <span className="badge badge-blue">{graphData?.paths?.length ?? 0}</span>
              </h2>
              <AttackPathList
                paths={graphData?.paths ?? []}
                onPathHover={setHighlightedPath}
                highlightedId={highlightedPath?.id}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatPill({ label, value }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span className="font-bold text-primary">{value}</span>
      <span className="text-muted">{label}</span>
    </div>
  );
}

function RecommendationCard({ rec }) {
  const colors = {
    CRITICAL: "text-red-400 border-red-500/30",
    HIGH:     "text-orange-400 border-orange-500/30",
    MEDIUM:   "text-yellow-400 border-yellow-500/30",
    LOW:      "text-blue-400 border-blue-500/30",
  };
  const c = colors[rec.priority] ?? colors.LOW;

  return (
    <div className={`rounded-lg px-3 py-2 border text-xs ${c}`} style={{ background: "var(--color-bg-surface)" }}>
      <p className="font-semibold mb-0.5">{rec.title}</p>
      <p className="text-muted leading-relaxed">{rec.detail}</p>
      {rec.action && (
        <p className="mt-1.5 font-medium opacity-90">→ {rec.action}</p>
      )}
    </div>
  );
}
