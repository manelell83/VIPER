import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { LogIn, ArrowLeft } from "lucide-react";
import { authApi } from "../services/api";
import { getToken, saveSession } from "../services/auth";
import Logo from "../components/brand/Logo";
import AuthLayout from "../components/layout/AuthLayout";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  if (getToken()) return <Navigate to="/app" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { access_token, user } = await authApi.login(username, password);
      saveSession(access_token, user);
      navigate("/app", { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-primary mb-10">
        <ArrowLeft size={14} /> Back to home
      </Link>
      <div className="lg:hidden mb-8"><Logo size={26} /></div>

      <p className="eyebrow">Welcome back</p>
      <h1 className="page-title mt-2">Sign in to VIPER</h1>
      <p className="page-subtitle">Use the account an administrator created for you.</p>

      <form onSubmit={handleSubmit} className="mt-8 space-y-5" noValidate>
        <div>
          <label htmlFor="username" className="field-label">Username</label>
          <input
            id="username"
            className="input-field"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />
        </div>

        <div>
          <label htmlFor="password" className="field-label">Password</label>
          <input
            id="password"
            type="password"
            className="input-field"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>

        {error && (
          <p role="alert" className="text-sm text-danger rounded-lg px-3 py-2"
             style={{ background: "var(--accent-soft)", border: "1px solid var(--accent-line)" }}>
            {error}
          </p>
        )}

        <button type="submit" className="btn-primary w-full py-3" disabled={loading || !username || !password}>
          <LogIn size={16} />
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <p className="mt-8 text-sm text-tertiary">
        No account yet? <Link to="/signup" className="link">How to get one</Link>
      </p>
    </AuthLayout>
  );
}
