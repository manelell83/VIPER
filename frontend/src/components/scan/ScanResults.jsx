import { Server, Globe, Lock, Cpu, Terminal, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import { Badge, StatusBadge } from "../ui/Badge";

export default function ScanResults({ hosts = [] }) {
  if (hosts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted gap-3">
        <Server size={32} className="opacity-30" />
        <p className="text-sm">No hosts discovered yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-2 animate-fadeIn">
      {hosts.map((host) => (
        <HostRow key={host.ip} host={host} />
      ))}
    </div>
  );
}

function HostRow({ host }) {
  const [expanded, setExpanded] = useState(false);
  const openPorts = host.ports?.filter((p) => p.state === "open") ?? [];

  return (
    <div
      className="rounded-xl overflow-hidden transition-all duration-200"
      style={{ border: "1px solid var(--color-border)", background: "var(--color-bg-surface)" }}
    >
      <button
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-[var(--color-bg-surface-hover)] transition-colors"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: "var(--accent-soft)" }}>
            <Server size={14} className="text-accent-text" />
          </div>
          <div className="text-left">
            <p className="text-sm font-semibold text-primary font-mono">{host.ip}</p>
            {host.hostname && (
              <p className="text-xs text-muted">{host.hostname}</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {host.os && (
            <div className="hidden sm:flex items-center gap-1 text-xs text-tertiary">
              <Cpu size={12} />
              {host.os.slice(0, 25)}{host.os.length > 25 ? "…" : ""}
            </div>
          )}
          {host.mac && (
            <p className="hidden md:block text-xs font-mono text-muted">{host.mac}</p>
          )}
          <Badge variant={openPorts.length > 0 ? "blue" : "gray"}>
            {openPorts.length} port{openPorts.length !== 1 ? "s" : ""}
          </Badge>
          <StatusBadge status={host.status || "up"} />
          {expanded ? <ChevronUp size={14} className="text-muted" /> : <ChevronDown size={14} className="text-muted" />}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 space-y-3 animate-fadeIn"
          style={{ borderTop: "1px solid var(--color-border)" }}>
          {/* Meta */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2">
            <InfoCell icon={Globe} label="IP" value={host.ip} mono />
            <InfoCell icon={Terminal} label="MAC" value={host.mac || "N/A"} mono />
            <InfoCell icon={Cpu} label="OS" value={host.os || "Unknown"} />
            <InfoCell label="Hostname" value={host.hostname || "N/A"} />
          </div>

          {/* Ports table */}
          {openPorts.length > 0 && (
            <div className="table-container rounded-lg overflow-hidden">
              <table className="table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {openPorts.map((port) => (
                    <tr key={`${port.port}-${port.protocol}`}>
                      <td className="font-mono font-semibold text-accent-text">{port.port}</td>
                      <td className="text-muted uppercase text-xs">{port.protocol}</td>
                      <td className="font-medium text-primary">{port.service || "-"}</td>
                      <td className="text-xs text-muted">{port.version || "-"}</td>
                      <td>
                        <Badge variant="green">open</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {openPorts.length === 0 && (
            <p className="text-sm text-muted flex items-center gap-2">
              <Lock size={13} /> No open ports found in range
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function InfoCell({ icon: Icon, label, value, mono = false }) {
  return (
    <div className="rounded-lg p-2.5" style={{ background: "var(--color-bg-surface-hover)" }}>
      <p className="text-xs text-muted mb-0.5">{label}</p>
      <p className={`text-xs font-medium text-primary truncate ${mono ? "font-mono" : ""}`}>
        {value}
      </p>
    </div>
  );
}
