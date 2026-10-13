import { useState, type FormEvent } from "react";
import { api } from "../api";

export default function Login({ onLogin }: { onLogin: (u: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ user: string }>("/api/login", { username, password });
      onLogin(r.user);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login stack" onSubmit={submit}>
        <div className="brand" style={{ padding: 0 }}>
          <img src="/favicon.svg" alt="" /> FSView
        </div>
        {error && <div className="alert error">{error}</div>}
        <label className="field">
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="off" autoFocus required />
        </label>
        <label className="field">
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        <button className="btn primary" type="submit" disabled={busy}>
          {busy && <span className="spinner" />} Sign in
        </button>
      </form>
    </div>
  );
}
