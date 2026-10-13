import { useEffect, useState } from "react";
import { api, setUnauthorizedHandler } from "./api";
import { useHashRoute } from "./util";
import Login from "./pages/Login";
import OverviewPage from "./pages/Overview";
import DiskPage from "./pages/Disk";
import HealthPage from "./pages/Health";
import EventsPage from "./pages/Events";
import BootPage from "./pages/Boot";
import AuditPage from "./pages/Audit";
import SettingsPage from "./pages/Settings";

const NAV = [
  { id: "overview", label: "Overview", ico: "▦" },
  { id: "health", label: "Health", ico: "♥" },
  { id: "events", label: "Events", ico: "⚡" },
  { id: "boot", label: "Boot check", short: "Boot", ico: "⏻" },
  { id: "audit", label: "Audit log", short: "Audit", ico: "☰" },
  { id: "settings", label: "Settings", ico: "⚙" },
];

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [host, setHost] = useState("");
  const route = useHashRoute();

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    api
      .get<{ user: string }>("/api/me")
      .then((r) => setUser(r.user))
      .catch(() => setUser(null));
  }, []);

  useEffect(() => {
    if (!user) return;
    api
      .get<{ helper?: { hostname: string } }>("/api/status")
      .then((s) => setHost(s.helper?.hostname ?? ""))
      .catch(() => {});
  }, [user]);

  useEffect(() => {
    document.title = host ? `FSView · ${host}` : "FSView";
  }, [host]);

  if (user === undefined) return null;
  if (user === null) return <Login onLogin={setUser} />;

  const page = route[0];
  const active = page === "disk" ? "overview" : page;
  let content;
  switch (page) {
    case "disk":
      content = <DiskPage name={route[1] ?? ""} />;
      break;
    case "health":
      content = <HealthPage />;
      break;
    case "events":
      content = <EventsPage />;
      break;
    case "boot":
      content = <BootPage />;
      break;
    case "audit":
      content = <AuditPage />;
      break;
    case "settings":
      content = <SettingsPage user={user} onLogout={() => setUser(null)} />;
      break;
    default:
      content = <OverviewPage />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <img src="/favicon.svg" alt="" /> FSView
        </div>
        <div className="host">{host}</div>
        <nav className="nav">
          {NAV.map((n) => (
            <a key={n.id} href={`#/${n.id}`} className={active === n.id ? "active" : ""}>
              <span className="ico">{n.ico}</span> {n.label}
            </a>
          ))}
        </nav>
        <div className="spacer" />
        <div className="small dim" style={{ padding: "0 8px" }}>
          Signed in as {user}
        </div>
      </aside>
      <header className="topbar">
        <div className="brand" style={{ padding: 0 }}>
          <img src="/favicon.svg" alt="" /> FSView
        </div>
        <span className="small dim">{host}</span>
      </header>
      <main className="main">{content}</main>
      <nav className="tabbar">
        {NAV.map((n) => (
          <a key={n.id} href={`#/${n.id}`} className={active === n.id ? "active" : ""}>
            <span className="ico">{n.ico}</span>
            {n.short ?? n.label}
          </a>
        ))}
      </nav>
    </div>
  );
}
