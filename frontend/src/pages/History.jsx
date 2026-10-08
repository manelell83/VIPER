import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Network, Globe, Trash2, Eye, ArrowLeft, Download } from "lucide-react";
import { resultsApi, reportsApi } from "../services/api";
import { StatusBadge } from "../components/ui/Badge";
import { LoadingOverlay } from "../components/ui/Loading";
import ScanResults from "../components/scan/ScanResults";

export function HistoryList() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    resultsApi.list()
      .then((res) => setScans(res.scans))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const remove = async (id) => {
    if (!confirm("Delete this scan?")) return;
    await resultsApi.delete(id);
    load();
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-bold text-primary">Scan History</h1>
        <p className="text-sm text-muted mt-1">All past scan sessions</p>
      </div>

      {loading ? (
        <LoadingOverlay message="Loading history..." />
      ) : scans.length === 0 ? (
        <div className="card py-12 text-center">
          <p className="text-muted">No scans yet.</p>
          <div className="flex justify-center gap-3 mt-4">
            <Link to="/scan/network" className="btn-primary">Network Scan</Link>
            <Link to="/scan/domain" className="btn-secondary">Domain Scan</Link>
          </div>
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Target</th>
                <th>Hosts</th>
                <th>Status</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const dur = scan.completed_at && scan.started_at
                  ? Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000)
                  : null;
                return (
                  <tr key={scan.id}>
                    <td>
                      <span className="flex items-center gap-1.5 text-tertiary">
                        {scan.type === "network" ? <Network size={13} /> : <Globe size={13} />}
                        <span className="capitalize">{scan.type}</span>
                      </span>
                    </td>
                    <td className="font-mono text-xs max-w-[200px] truncate">{scan.target}</td>
                    <td className="font-medium">{scan.hosts_count ?? 0}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td className="text-xs text-muted">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"}
                    </td>
                    <td className="text-xs text-muted">
                      {dur != null ? `${dur}s` : "-"}
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <Link to={`/history/${scan.id}`} className="btn-icon" title="View Details">
                          <Eye size={14} />
                        </Link>
                        {scan.status === "completed" && (
                          <button
                            onClick={() => reportsApi.downloadJson(scan.id).catch(() => {})}
                            className="btn-icon"
                            title="Download JSON"
                          >
                            <Download size={14} />
                          </button>
                        )}
                        <button className="btn-icon" title="Delete" onClick={() => remove(scan.id)}>
                          <Trash2 size={14} className="text-danger" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ScanDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    resultsApi.get(id)
      .then(setData)
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingOverlay message="Loading scan details..." />;
  if (!data) return <p className="text-danger p-4">Scan not found.</p>;

  const { scan, hosts } = data;

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">
      <div className="flex items-center gap-3">
        <Link to="/history" className="btn-icon">
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1 className="text-xl font-bold text-primary font-mono">{scan.target}</h1>
          <p className="text-xs text-muted">{scan.type} · {scan.id.slice(0, 8)}…</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <StatusBadge status={scan.status} />
          {scan.status === "completed" && (
            <>
              <button onClick={() => reportsApi.downloadJson(scan.id).catch(() => {})} className="btn-secondary text-xs py-1.5">
                <Download size={13} /> JSON
              </button>
              <button onClick={() => reportsApi.downloadPdf(scan.id).catch(() => {})} className="btn-secondary text-xs py-1.5">
                <Download size={13} /> PDF
              </button>
              <Link to={`/topology?scan=${scan.id}`} className="btn-info text-xs py-1.5">
                View Topology
              </Link>
            </>
          )}
        </div>
      </div>

      {/* Meta */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          ["Type", scan.type],
          ["Target", scan.target],
          ["Hosts", scan.hosts_count ?? 0],
          ["Started", scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"],
        ].map(([k, v]) => (
          <div key={k} className="card-sm">
            <p className="text-xs text-muted">{k}</p>
            <p className="text-sm font-semibold text-primary truncate mt-0.5">{v}</p>
          </div>
        ))}
      </div>

      {/* Hosts */}
      <div className="card">
        <h2 className="text-sm font-semibold text-primary mb-4">
          Hosts <span className="badge badge-blue ml-1">{hosts.length}</span>
        </h2>
        <ScanResults hosts={hosts} />
      </div>
    </div>
  );
}
