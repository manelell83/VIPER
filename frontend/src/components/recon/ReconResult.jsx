import { Globe, Server, Network, FileText, Shield, AlertTriangle, ExternalLink } from "lucide-react";
import ReconGraph from "./ReconGraph";

function Section({ icon: Icon, title, count, children }) {
  return (
    <div className="card space-y-3">
      <h3 className="text-sm font-semibold text-secondary flex items-center gap-2">
        <Icon size={15} className="text-tertiary" /> {title}
        {count != null && <span className="badge badge-gray">{count}</span>}
      </h3>
      {children}
    </div>
  );
}

function Field({ label, value }) {
  return (
    <div>
      <p className="text-xs text-muted">{label}</p>
      <p className="text-sm text-primary break-words">{value || "—"}</p>
    </div>
  );
}

function RecordList({ records }) {
  if (!records?.length) return <p className="text-xs text-muted">None</p>;
  return (
    <ul className="space-y-1">
      {records.map((r, i) => <li key={i} className="font-mono text-xs text-secondary break-all">{r}</li>)}
    </ul>
  );
}

export default function ReconResult({ result }) {
  if (!result) return null;
  const { whois, dns, subdomains, ips, fingerprints, graph } = result;

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Linked entity graph: domain -> subdomains -> IPs -> services */}
      <Section icon={Network} title="Entity map">
        <p className="text-xs text-tertiary -mt-1">
          How the domain links to its subdomains, IP addresses and web services. Click a node to select it.
        </p>
        <ReconGraph graph={graph} />
      </Section>

      <div className="grid md:grid-cols-2 gap-5">
        {/* Registration */}
        <Section icon={FileText} title="Registration (WHOIS / RDAP)">
          {whois?.source ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Registrar" value={whois.registrar} />
              <Field label="Owner" value={whois.owner} />
              <Field label="Created" value={whois.created} />
              <Field label="Expires" value={whois.expires} />
              <div className="col-span-2">
                <p className="text-xs text-muted">Source</p>
                <span className="badge badge-gray uppercase">{whois.source}</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-muted">No registration data available for this domain.</p>
          )}
        </Section>

        {/* IPs */}
        <Section icon={Server} title="IP addresses" count={ips?.length}>
          {ips?.length ? (
            <ul className="space-y-1.5">
              {ips.map((ip) => (
                <li key={ip.ip} className="text-sm">
                  <span className="font-mono text-primary">{ip.ip}</span>
                  {ip.ptr && <span className="text-xs text-muted ml-2">↳ {ip.ptr}</span>}
                </li>
              ))}
            </ul>
          ) : <p className="text-xs text-muted">No A/AAAA records resolved.</p>}
        </Section>
      </div>

      {/* DNS records */}
      <Section icon={Globe} title="DNS records">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {["A", "AAAA", "MX", "NS", "TXT", "CNAME"].map((t) => (
            <div key={t}>
              <p className="text-xs font-semibold text-tertiary mb-1">{t}</p>
              <RecordList records={dns?.[t]} />
            </div>
          ))}
        </div>
      </Section>

      {/* Subdomains */}
      <Section icon={Shield} title="Subdomains (Certificate Transparency)"
               count={subdomains?.available ? subdomains.list.length : undefined}>
        {subdomains?.available ? (
          subdomains.list.length ? (
            <div className="flex flex-wrap gap-2">
              {subdomains.list.map((s) => <span key={s} className="badge badge-gray font-mono">{s}</span>)}
            </div>
          ) : <p className="text-xs text-muted">No subdomains found in Certificate Transparency logs.</p>
        ) : (
          <p className="text-xs text-warning flex items-start gap-2">
            <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
            {subdomains?.error || "crt.sh was unavailable; certificate-transparency data was skipped."}
          </p>
        )}
      </Section>

      {/* HTTP fingerprints */}
      <Section icon={Server} title="Web fingerprints"
               count={fingerprints?.filter((f) => f.reachable).length}>
        <p className="text-xs text-tertiary -mt-1">
          A single page request per host (like visiting the site) — not a port scan.
        </p>
        {fingerprints?.some((f) => f.reachable) ? (
          <div className="table-container">
            <table className="table">
              <thead><tr><th>Host</th><th>Status</th><th>Server</th><th>Powered by</th><th>Title</th></tr></thead>
              <tbody>
                {fingerprints.filter((f) => f.reachable).map((f) => (
                  <tr key={f.host}>
                    <td>
                      <a href={f.url} target="_blank" rel="noreferrer"
                         className="link font-mono text-xs inline-flex items-center gap-1">
                        {f.host} <ExternalLink size={10} />
                      </a>
                    </td>
                    <td className="font-mono text-xs text-secondary">{f.status}</td>
                    <td className="text-xs text-secondary">{f.server || "—"}</td>
                    <td className="text-xs text-muted">{f.powered_by || "—"}</td>
                    <td className="text-xs text-muted max-w-[220px] truncate">{f.title || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="text-xs text-muted">No web host responded over HTTP/HTTPS.</p>}
      </Section>
    </div>
  );
}
