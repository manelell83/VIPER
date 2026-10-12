import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { scanApi } from "../../services/api";

/**
 * "I own this target or am authorised to scan it" checkbox, required before
 * any active scan. The statement text comes from the backend, which records
 * it verbatim with the scan (who, when, statement) and in its audit log.
 */
export default function AuthorizationConfirm({ checked, onChange, target, disabled }) {
  const [statement, setStatement] = useState("");

  useEffect(() => {
    scanApi.authorizationStatement()
      .then((r) => setStatement(r.statement))
      .catch(() => setStatement(""));
  }, []);

  return (
    <label
      className={`flex items-start gap-3 rounded-lg p-3 cursor-pointer ${disabled ? "opacity-60 cursor-not-allowed" : ""}`}
      style={{
        background: checked ? "var(--accent-soft)" : "var(--surface-2)",
        border: `1px solid ${checked ? "var(--accent-line)" : "var(--line)"}`,
      }}
    >
      <input
        type="checkbox"
        className="mt-0.5 w-4 h-4 flex-shrink-0 accent-[var(--accent)]"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled || !statement}
        aria-describedby="authorization-note"
      />
      <span className="text-sm">
        <span className="font-semibold text-primary flex items-center gap-1.5">
          <ShieldCheck size={14} className="text-accent-text" aria-hidden="true" />
          Authorization
        </span>
        <span className="block text-secondary mt-0.5">
          {statement || "Loading the authorization statement…"}
          {target && <> Target: <span className="font-mono text-primary">{target}</span>.</>}
        </span>
        <span id="authorization-note" className="block text-xs text-muted mt-1">
          Your confirmation is recorded with your username and a UTC timestamp.
        </span>
      </span>
    </label>
  );
}
