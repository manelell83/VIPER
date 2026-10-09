import { useEffect, useState } from "react";
import { FileText, Download, Network, Globe, Clock } from "lucide-react";
import { resultsApi, reportsApi } from "../services/api";
import { StatusBadge } from "../components/ui/Badge";
import { LoadingOverlay } from "../components/ui/Loading";

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    resultsApi.list()
      .then((res) => setScans(res.scans.filter((s) => s.status === "completed")))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-bold text-primary">Reports</h1>
        <p className="text-sm text-muted mt-1">Export scan results as PDF or JSON</p>
      </div>

      {loading ? (
        <LoadingOverlay message="Loading reports..." />
      ) : scans.length === 0 ? (
        <div className="card py-12 text-center">
          <FileText size={36} className="mx-auto text-muted opacity-30 mb-3" />
          <p className="text-muted">No completed scans to export.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <div key={scan.id} className="card-sm flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-blue-500/10 flex-shrink-0">
                {scan.type === "network" ? (
                  <Network size={16} className="text-blue-500" />
                ) : (
                  <Globe size={16} className="text-blue-500" />
                )}
              </div>

              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-primary font-mono truncate">{scan.target}</p>
                <div className="flex items-center gap-3 mt-0.5">
                  <StatusBadge status={scan.status} />
                  <span className="text-xs text-muted flex items-center gap-1">
                    <Clock size={11} />
                    {scan.started_at ? new Date(scan.started_at).toLocaleDateString() : "-"}
                  </span>
                  <span className="text-xs text-muted">{scan.hosts_count ?? 0} hosts</span>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => reportsApi.downloadJson(scan.id).catch(() => {})}
                  className="btn-secondary text-xs py-1.5 px-3"
                >
                  <Download size={13} /> JSON
                </button>
                <button
                  onClick={() => reportsApi.downloadPdf(scan.id).catch(() => {})}
                  className="btn-secondary text-xs py-1.5 px-3"
                >
                  <Download size={13} /> PDF
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
