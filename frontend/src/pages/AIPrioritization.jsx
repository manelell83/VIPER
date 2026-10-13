import { useEffect, useState, useCallback } from "react";
import {
  RefreshCw, ChevronDown, ChevronRight, ChevronUp, Sparkles,
  Pin, PinOff, EyeOff, Eye, Cpu, FileText, Flame, Activity, ShieldCheck,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import ScoreBreakdown from "../components/prioritization/ScoreBreakdown";
import { resultsApi, prioritizationApi } from "../services/api";

function MaturityChips({ item }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {item.kev && <span className="badge badge-red"><Flame size={10} /> KEV</span>}
      {item.maturity && item.maturity !== "UNKNOWN" && (
        <span className="badge badge-gray">{item.maturity}</span>
      )}
      {item.epss != null && (
        <span className={`badge ${item.epss >= 0.5 ? "badge-red" : item.epss >= 0.1 ? "badge-yellow" : "badge-gray"}`}>
          <Activity size={10} /> EPSS {(item.epss * 100).toFixed(item.epss >= 0.1 ? 0 : 1)}%
        </span>
      )}
      <span className={`badge ${item.confirmed ? "badge-green" : "badge-yellow"}`}>
        {item.confirmed ? "Confirmed" : "Weak"}
      </span>
    </span>
  );
}

function FindingRow({ item, onPin, onDismiss }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`card ${item.dismissed ? "opacity-55" : ""}`}>
      <div className="flex items-start gap-3">
        <div className="flex flex-col items-center w-10 flex-shrink-0">
          <span className="text-xs text-muted">#{item.rank}</span>
          <span className="text-xl font-bold" style={{ color: item.score >= 70 ? "var(--danger)" : item.score >= 40 ? "#eab308" : "var(--text-tertiary)" }}>
            {Math.round(item.score)}
          </span>
          <span className="text-[9px] text-muted">/100</span>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <a href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`} target="_blank" rel="noreferrer"
               className="link font-mono text-sm">{item.cve_id}</a>
            <span className="text-xs text-muted font-mono">{item.host_ip}</span>
            {item.affected_port && <span className="text-xs text-muted font-mono">{item.affected_port}</span>}
            {item.manual_rank && <span className="badge badge-gray"><Pin size={10} /> pinned</span>}
          </div>
          <p className="text-xs text-tertiary mt-0.5 truncate">{item.affected_service || "unknown service"}</p>
          <div className="mt-1.5"><MaturityChips item={item} /></div>

          {/* AI/template explanation, clearly marked */}
          {item.explanation?.text && (
            <p className="text-xs text-secondary mt-2 flex items-start gap-1.5">
              {item.explanation.source === "ai"
                ? <Sparkles size={12} className="flex-shrink-0 mt-0.5 text-[var(--accent)]" title="AI-generated" />
                : <FileText size={12} className="flex-shrink-0 mt-0.5 text-muted" title="Deterministic template" />}
              <span>{item.explanation.text}</span>
            </p>
          )}

          <button onClick={() => setOpen((o) => !o)} className="text-xs text-muted mt-2 inline-flex items-center gap-1">
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Score breakdown (deterministic)
          </button>
          {open && <div className="mt-2"><ScoreBreakdown factors={item.factors} /></div>}
        </div>

        {/* Human-in-the-loop controls */}
        <div className="flex flex-col gap-1 flex-shrink-0">
          <button className="btn-icon" title={item.manual_rank ? "Unpin" : "Pin to top"}
                  onClick={() => onPin(item)}>
            {item.manual_rank ? <PinOff size={14} /> : <Pin size={14} />}
          </button>
          <button className="btn-icon" title={item.dismissed ? "Restore" : "Dismiss"}
                  onClick={() => onDismiss(item)}>
            {item.dismissed ? <Eye size={14} /> : <EyeOff size={14} />}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AIPrioritization() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [useLlm, setUseLlm] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    resultsApi.list().then((r) => {
      const completed = (r.scans || []).filter((s) => s.status === "completed");
      setScans(completed);
      if (completed.length) setScanId(completed[0].id);
    }).catch(() => {});
  }, []);

  const load = useCallback(() => {
    if (!scanId) return;
    setLoading(true); setError(null);
    prioritizationApi.get(scanId)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  useEffect(load, [load]);

  const generate = () => {
    setGenerating(true);
    prioritizationApi.generateNarrative(scanId, useLlm)
      .then(() => load())
      .catch((e) => setError(e.message))
      .finally(() => setGenerating(false));
  };

  const pin = (item) =>
    prioritizationApi.setOverride(scanId, item.vuln_id, { manual_rank: item.manual_rank ? null : 1 }).then(load);
  const dismiss = (item) =>
    prioritizationApi.setOverride(scanId, item.vuln_id, { dismissed: !item.dismissed }).then(load);

  const narrative = data?.narrative;
  const items = data?.items ?? [];

  return (
    <div className="max-w-5xl space-y-6 animate-fadeIn">
      <PageHeader
        eyebrow="Analysis"
        title="AI Prioritization"
        subtitle="Findings ranked most-urgent first by a transparent, deterministic score from real signals. The optional AI layer only explains — it never changes the ranking."
      />

      <div className="flex items-center justify-between flex-wrap gap-3">
        <select value={scanId} onChange={(e) => setScanId(e.target.value)} className="input-field text-sm py-1.5 w-72">
          <option value="">Select a scan…</option>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>{s.type} · {s.target} · {new Date(s.started_at).toLocaleDateString()}</option>
          ))}
        </select>
        <button className="btn-icon" onClick={load} title="Refresh"><RefreshCw size={15} className={loading ? "animate-spin" : ""} /></button>
      </div>

      {error && <div role="alert" className="card border-danger"><p className="text-sm text-danger">{error}</p></div>}

      {scanId && data && (
        <>
          {/* Executive summary + generation controls */}
          <div className="card space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h2 className="text-sm font-semibold text-secondary flex items-center gap-2">
                Executive summary
                {narrative && (
                  <span className={`badge ${narrative.source === "ai" ? "badge-accent" : "badge-gray"}`}>
                    {narrative.source === "ai" ? <><Cpu size={10} /> AI-generated</> : <><FileText size={10} /> Deterministic</>}
                  </span>
                )}
              </h2>
              <div className="flex items-center gap-2">
                <label className="text-xs text-tertiary flex items-center gap-1.5" title={data.llm_available ? "An LLM key is configured" : "No LLM key configured — will use the deterministic template"}>
                  <input type="checkbox" checked={useLlm} disabled={!data.llm_available}
                         onChange={(e) => setUseLlm(e.target.checked)} />
                  Use AI {!data.llm_available && "(no key)"}
                </label>
                <button className="btn-secondary text-xs" onClick={generate} disabled={generating}>
                  {generating ? <RefreshCw size={13} className="animate-spin" /> : <Sparkles size={13} />}
                  {narrative ? "Regenerate" : "Generate"}
                </button>
              </div>
            </div>
            {narrative?.executive_summary
              ? <p className="text-sm text-secondary leading-relaxed">{narrative.executive_summary}</p>
              : <p className="text-xs text-muted">No summary yet. Generate one (deterministic by default; AI if a key is configured).</p>}
            <p className="text-[11px] text-muted flex items-center gap-1.5">
              <ShieldCheck size={12} /> The ranking and scores are deterministic. The AI only rephrases the computed data —
              it invents no scores and does not decide. Prioritization is a decision aid, not absolute truth.
            </p>
          </div>

          {/* Ranked findings */}
          <div className="space-y-2">
            {items.length === 0
              ? <div className="card text-center text-muted text-sm py-8">No vulnerabilities to prioritize for this scan.</div>
              : items.map((item) => <FindingRow key={item.vuln_id} item={item} onPin={pin} onDismiss={dismiss} />)}
          </div>
        </>
      )}
    </div>
  );
}
