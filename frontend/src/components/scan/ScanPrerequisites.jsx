import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, MinusCircle, RefreshCw } from "lucide-react";
import { interfacesApi } from "../../services/api";

/**
 * Shows what the scanner can do on the backend machine (admin rights, Npcap,
 * Nmap) and, for anything missing, what to do about it. Data comes from
 * GET /interfaces/capabilities; nothing is assumed in the browser.
 */
export default function ScanPrerequisites({ onLoaded }) {
  const [caps, setCaps] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setError(null);
    interfacesApi.capabilities()
      .then((c) => { setCaps(c); onLoaded?.(c); })
      .catch((e) => setError(e.message));
  };
  useEffect(load, []);   // eslint-disable-line react-hooks/exhaustive-deps

  if (error) {
    return <p role="alert" className="text-sm text-danger">Could not check the scanner prerequisites: {error}</p>;
  }
  if (!caps) return <p className="text-sm text-muted">Checking scanner prerequisites…</p>;

  const checks = [
    { label: "Administrator rights", ok: caps.admin },
    { label: "Npcap", ok: caps.npcap, na: caps.npcap === null },
    { label: caps.nmap ? `Nmap ${caps.nmap}` : "Nmap", ok: Boolean(caps.nmap) },
  ];

  return (
    <section aria-label="Scanner prerequisites" className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-secondary">Prerequisites</h2>
        <button type="button" className="btn-icon" onClick={load} title="Check again" aria-label="Check prerequisites again">
          <RefreshCw size={14} />
        </button>
      </div>

      <ul className="flex flex-wrap gap-2">
        {checks.map(({ label, ok, na }) => (
          <li key={label} className={`badge ${na ? "badge-gray" : ok ? "badge-green" : "badge-red"}`}>
            {na ? <MinusCircle size={12} /> : ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
            {label}{na ? " (not needed on this OS)" : ""}
          </li>
        ))}
      </ul>

      <p className="text-xs text-tertiary">
        Host discovery: <span className="text-primary font-medium">{caps.discovery_method === "arp" ? "ARP" : "ping sweep"}</span>
        {" · "}OS detection: <span className="text-primary font-medium">{caps.os_detection ? "on" : "off"}</span>
      </p>

      {caps.problems.length > 0 && (
        <ul className="space-y-2">
          {caps.problems.map((p) => (
            <li key={p.id} className="rounded-lg p-3 text-xs"
                style={{ background: "var(--surface-2)", border: "1px solid var(--line)" }}>
              <p className="font-semibold text-warning">{p.message}</p>
              <p className="text-secondary mt-1"><span className="font-medium text-primary">What to do:</span> {p.fix}</p>
              <p className="text-tertiary mt-0.5">{p.impact}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
