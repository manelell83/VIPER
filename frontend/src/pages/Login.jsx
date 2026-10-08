import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Shield, LogIn } from "lucide-react";
import { authApi } from "../services/api";
import { getToken, saveSession } from "../services/auth";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  if (getToken()) return <Navigate to="/" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { access_token, user } = await authApi.login(username, password);
      saveSession(access_token, user);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6" style={{ background: "var(--color-bg-body)" }}>
      <form onSubmit={handleSubmit} className="card w-full max-w-sm space-y-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-primary leading-tight">ViperV2</p>
            <p className="text-xs text-muted leading-tight">Sign in to continue</p>
          </div>
        </div>

        <div>
          <label htmlFor="username" className="text-sm font-medium text-secondary block mb-2">Username</label>
          <input
            id="username"
            className="input-field"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>

        <div>
          <label htmlFor="password" className="text-sm font-medium text-secondary block mb-2">Password</label>
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

        {error && <p className="text-sm text-danger">{error}</p>}

        <button type="submit" className="btn-primary w-full justify-center" disabled={loading}>
          <LogIn size={15} />
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
