import { useEffect, useState } from "react";
import { Network, RefreshCw, Wifi } from "lucide-react";
import { interfacesApi } from "../../services/api";
import { Spinner } from "../ui/Loading";

export default function InterfaceSelector({ value, onChange, disabled }) {
  const [interfaces, setInterfaces] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await interfacesApi.list();
      setInterfaces(res.interfaces);
      if (res.interfaces.length === 1 && !value) {
        onChange(res.interfaces[0].name);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-tertiary text-sm">
        <Spinner size={16} /> Detecting interfaces...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2">
        <p className="text-sm text-danger">{error}</p>
        <button className="btn-secondary text-xs py-1 px-2" onClick={load}>
          <RefreshCw size={12} /> Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="text-sm font-medium text-secondary">Network Interface</label>
        <button className="btn-icon" onClick={load} title="Refresh interfaces">
          <RefreshCw size={14} />
        </button>
      </div>

      {interfaces.length === 0 ? (
        <p className="text-sm text-muted">No active interfaces found.</p>
      ) : (
        <div className="space-y-2">
          {interfaces.map((iface) => (
            <button
              key={iface.name}
              disabled={disabled}
              onClick={() => onChange(iface.name)}
              className={`w-full text-left rounded-xl p-4 border transition-all duration-150 ${
                value === iface.name
                  ? "border-blue-500 bg-blue-500/10 ring-1 ring-blue-500"
                  : "border-[var(--color-border)] bg-[var(--color-bg-surface)] hover:border-[var(--color-border-input)] hover:bg-[var(--color-bg-surface-hover)]"
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                    value === iface.name ? "bg-blue-600" : "bg-[var(--color-bg-surface-hover)]"
                  }`}>
                    <Wifi size={15} className={value === iface.name ? "text-white" : "text-tertiary"} />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-primary">{iface.name}</p>
                    <p className="text-xs text-muted font-mono">{iface.ip}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-tertiary font-mono">{iface.subnet}</p>
                  <div className={`flex items-center gap-1 text-xs mt-0.5 ${iface.is_up ? "text-success" : "text-danger"}`}>
                    <span className={`w-1.5 h-1.5 rounded-full inline-block ${iface.is_up ? "bg-green-500" : "bg-red-500"}`} />
                    {iface.is_up ? "Active" : "Inactive"}
                  </div>
                </div>
              </div>
              {value === iface.name && (
                <div className="mt-3 pt-3 border-t border-blue-500/20 grid grid-cols-2 gap-2">
                  <div>
                    <p className="text-xs text-muted">Subnet</p>
                    <p className="text-xs font-mono text-primary">{iface.subnet}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted">Netmask</p>
                    <p className="text-xs font-mono text-primary">{iface.netmask}</p>
                  </div>
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
