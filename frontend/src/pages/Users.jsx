import { useState } from "react";
import { UserPlus, ShieldAlert, CheckCircle2 } from "lucide-react";
import { authApi } from "../services/api";
import { getUser } from "../services/auth";
import PageHeader from "../components/ui/PageHeader";

const EMPTY = { username: "", email: "", password: "", role: "analyst" };

// Admin-only page to create accounts (POST /auth/users). The rules below
// mirror the backend validation; the backend remains the authority.
export default function Users() {
  const me = getUser();
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState(null);
  const [created, setCreated] = useState(null);
  const [saving, setSaving] = useState(false);

  if (me?.role !== "admin") {
    return (
      <div className="card flex items-center gap-3 max-w-xl">
        <ShieldAlert size={20} className="text-danger" />
        <p className="text-sm text-secondary">Only administrators can manage users.</p>
      </div>
    );
  }

  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }));
  const passwordBytes = new TextEncoder().encode(form.password).length;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setCreated(null);
    setSaving(true);
    try {
      const user = await authApi.createUser(form);
      setCreated(user);
      setForm(EMPTY);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <PageHeader
        eyebrow="Admin"
        title="Users"
        subtitle="Create accounts for the people allowed to use VIPER. There is no public sign-up."
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <form onSubmit={handleSubmit} className="card space-y-5" noValidate>
          <h2 className="section-title flex items-center gap-2"><UserPlus size={17} className="text-accent-text" /> New user</h2>

          <div className="grid gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="new-username" className="field-label">Username</label>
              <input id="new-username" className="input-field" value={form.username} onChange={set("username")}
                     autoComplete="off" required pattern="[A-Za-z0-9_.\-]{3,32}" />
              <p className="text-xs text-muted mt-1.5">3–32 letters, digits, dot, dash or underscore.</p>
            </div>
            <div>
              <label htmlFor="new-email" className="field-label">Email</label>
              <input id="new-email" type="email" className="input-field" value={form.email} onChange={set("email")}
                     autoComplete="off" required />
            </div>
            <div>
              <label htmlFor="new-password" className="field-label">Initial password</label>
              <input id="new-password" type="password" className="input-field" value={form.password}
                     onChange={set("password")} autoComplete="new-password" required minLength={10} />
              <p className={`text-xs mt-1.5 ${passwordBytes > 72 ? "text-danger" : "text-muted"}`}>
                At least 10 characters, at most 72 bytes (bcrypt limit).
              </p>
            </div>
            <div>
              <label htmlFor="new-role" className="field-label">Role</label>
              <select id="new-role" className="input-field" value={form.role} onChange={set("role")}>
                <option value="analyst">Analyst — run scans, read results</option>
                <option value="admin">Admin — also create users and delete scans</option>
              </select>
            </div>
          </div>

          {error && (
            <p role="alert" className="text-sm text-danger rounded-lg px-3 py-2"
               style={{ background: "var(--accent-soft)", border: "1px solid var(--accent-line)" }}>
              {error}
            </p>
          )}
          {created && (
            <p role="status" className="text-sm text-success flex items-center gap-2">
              <CheckCircle2 size={16} /> User <strong>{created.username}</strong> ({created.role}) created.
            </p>
          )}

          <button type="submit" className="btn-primary" disabled={saving}>
            <UserPlus size={15} /> {saving ? "Creating…" : "Create user"}
          </button>
        </form>

        <aside className="card-sm h-fit space-y-3 text-sm text-tertiary">
          <h2 className="section-title">Roles</h2>
          <p><span className="badge badge-red">admin</span> creates users and can delete scans.</p>
          <p><span className="badge badge-gray">analyst</span> runs scans and reads every result.</p>
          <p className="text-xs text-muted pt-2" style={{ borderTop: "1px solid var(--line)" }}>
            Share the initial password through a separate channel. The API does not provide a
            user list, so this page only creates accounts.
          </p>
        </aside>
      </div>
    </div>
  );
}
