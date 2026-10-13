import { Link } from "react-router-dom";
import { ArrowLeft, ShieldCheck, UserPlus, Terminal } from "lucide-react";
import AuthLayout from "../components/layout/AuthLayout";
import Logo from "../components/brand/Logo";

// There is deliberately no public sign-up form: a network scanner open to
// anyone would let anyone launch scans. Accounts are created by an admin
// (POST /auth/users, admin only) and the first admin with a CLI command.
export default function Signup() {
  return (
    <AuthLayout>
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-primary mb-10">
        <ArrowLeft size={14} /> Back to home
      </Link>
      <div className="lg:hidden mb-8"><Logo size={26} /></div>

      <p className="eyebrow">Create an account</p>
      <h1 className="page-title mt-2">Accounts are created by an administrator</h1>
      <p className="page-subtitle">
        VIPER launches network scans, so it has no open registration: only people an
        administrator trusts can use it.
      </p>

      <ol className="mt-8 space-y-4">
        <li className="card-sm flex gap-3">
          <UserPlus size={18} className="flex-shrink-0 mt-0.5 text-accent-text" aria-hidden="true" />
          <div>
            <p className="text-sm font-semibold text-primary">Ask your VIPER administrator</p>
            <p className="text-sm text-tertiary mt-0.5">
              They create your account in <span className="text-secondary">Admin → Users</span> and
              give you your username and an initial password.
            </p>
          </div>
        </li>
        <li className="card-sm flex gap-3">
          <Terminal size={18} className="flex-shrink-0 mt-0.5 text-accent-text" aria-hidden="true" />
          <div>
            <p className="text-sm font-semibold text-primary">Setting up VIPER yourself?</p>
            <p className="text-sm text-tertiary mt-0.5">Create the first administrator from the backend folder:</p>
            <code className="block mt-2 text-xs rounded-md px-3 py-2 overflow-x-auto"
                  style={{ background: "var(--input-bg)", border: "1px solid var(--line)", color: "var(--text-2)" }}>
              python -m app.create_admin --username admin --email you@example.com
            </code>
          </div>
        </li>
        <li className="card-sm flex gap-3">
          <ShieldCheck size={18} className="flex-shrink-0 mt-0.5 text-accent-text" aria-hidden="true" />
          <div>
            <p className="text-sm font-semibold text-primary">Why no sign-up form?</p>
            <p className="text-sm text-tertiary mt-0.5">
              Open registration would let anyone run scans from this server. A web
              &quot;first visitor becomes admin&quot; flow would let whoever reaches the page
              first take control, so the first admin is created from the command line.
            </p>
          </div>
        </li>
      </ol>

      <Link to="/login" className="btn-primary w-full py-3 mt-8">I have an account — sign in</Link>
    </AuthLayout>
  );
}
