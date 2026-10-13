import { useEffect, useState } from "react";
import {
  Activity,
  FileCog,
  HardDrive,
  HeartPulse,
  LogOut,
  Menu,
  Monitor,
  Moon,
  Power,
  ScrollText,
  Settings as SettingsIcon,
  Sun,
  X,
  type LucideIcon,
} from "lucide-react";
import { api, setUnauthorizedHandler } from "./api";
import { useTheme, type ThemeChoice } from "./theme";
import { useHashRoute } from "./util";
import type { StatusInfo } from "./types";
import Login from "./pages/Login";
import OverviewPage from "./pages/Overview";
import DiskPage from "./pages/Disk";
import HealthPage from "./pages/Health";
import EventsPage from "./pages/Events";
import BootPage from "./pages/Boot";
import FstabPage from "./pages/Fstab";
import AuditPage from "./pages/Audit";
import SettingsPage from "./pages/Settings";

const GROUPS: { label: string; items: { id: string; label: string; icon: LucideIcon }[] }[] = [
  {
    label: "Monitor",
    items: [
      { id: "overview", label: "Overview", icon: HardDrive },
      { id: "health", label: "Health", icon: HeartPulse },
      { id: "events", label: "Events", icon: Activity },
      { id: "boot", label: "Boot check", icon: Power },
    ],
  },
  {
    label: "Configure",
    items: [{ id: "fstab", label: "fstab", icon: FileCog }],
  },
  {
    label: "Manage",
    items: [
      { id: "audit", label: "Audit log", icon: ScrollText },
      { id: "settings", label: "Settings", icon: SettingsIcon },
    ],
  },
];

const THEMES: [ThemeChoice, LucideIcon][] = [
  ["light", Sun],
  ["system", Monitor],
  ["dark", Moon],
];

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useTheme();
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
    const load = () =>
      api
        .get<StatusInfo>("/api/status")
        .then(setStatus)
        .catch(() => {});
    load();
    const t = setInterval(() => !document.hidden && load(), 30000);
    return () => clearInterval(t);
  }, [user]);

  const host = status?.helper?.hostname ?? "";
  useEffect(() => {
    document.title = host ? `FSView · ${host}` : "FSView";
  }, [host]);

  useEffect(() => setMenuOpen(false), [route.join("/")]);

  if (user === undefined) return null;
  if (user === null) return <Login onLogin={setUser} />;

  const logout = async () => {
    await api.post("/api/logout").catch(() => {});
    setUser(null);
  };

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
    case "fstab":
      content = <FstabPage />;
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

  const h = status?.helper;
  return (
    <div className="app">
      <aside className={`sidebar${menuOpen ? " open" : ""}`}>
        <div className="brand">
          <img src="/favicon.svg" alt="" /> FSView
          <button className="btn ghost icon sm close-menu" aria-label="Close menu" onClick={() => setMenuOpen(false)}>
            <X size={18} />
          </button>
        </div>
        {host && (
          <div className="host">
            {host}
          </div>
        )}
        <nav className="nav">
          {GROUPS.map((g) => (
            <div key={g.label} style={{ display: "contents" }}>
              <div className="group">{g.label}</div>
              {g.items.map((n) => (
                <a key={n.id} href={`#/${n.id}`} className={active === n.id ? "active" : ""}>
                  <n.icon size={17} strokeWidth={1.9} />
                  <span className="grow">{n.label}</span>
                </a>
              ))}
            </div>
          ))}
        </nav>
        <div className="foot">
          <div className="helper-status" title={status?.helper_error ?? ""}>
            {status ? (
              h ? (
                <>
                  <span className="dot ok" />
                  <span className="grow">Helper {h.version}</span>
                  <span className={`badge ${h.writes_enabled ? "warn" : "neutral"}`}>{h.writes_enabled ? "writes on" : "read-only"}</span>
                </>
              ) : (
                <>
                  <span className="dot err" />
                  <span className="grow">Helper unreachable</span>
                </>
              )
            ) : (
              <>
                <span className="dot" />
                <span className="faint">Connecting…</span>
              </>
            )}
          </div>
          <div className="me">
            <a href="#/settings" className={`me-link${active === "settings" ? " active" : ""}`}>
              <span className="avatar">{user[0]?.toUpperCase()}</span>
              <span className="me-text">
                <span className="truncate">{user}</span>
                <span className="faint" style={{ fontSize: 11.5 }}>
                  administrator
                </span>
              </span>
            </a>
            <button className="btn ghost icon sm" title="Sign out" aria-label="Sign out" onClick={logout}>
              <LogOut size={16} />
            </button>
          </div>
          <div className="theme" role="group" aria-label="Theme">
            {THEMES.map(([t, Icon]) => (
              <button key={t} className={theme === t ? "active" : ""} onClick={() => setTheme(t)} title={t} aria-label={`${t} theme`}>
                <Icon size={14} />
              </button>
            ))}
          </div>
        </div>
      </aside>
      {menuOpen && <div className="scrim" role="presentation" onClick={() => setMenuOpen(false)} />}
      <div className="content">
        <header className="topbar">
          <button className="btn ghost icon" aria-label="Menu" onClick={() => setMenuOpen(true)}>
            <Menu size={20} />
          </button>
          <img src="/favicon.svg" alt="" />
          <strong>FSView</strong>
          <span className="small dim" style={{ marginLeft: "auto", paddingRight: 8 }}>
            {host}
          </span>
        </header>
        <main className="main" key={route.join("/")}>
          {content}
        </main>
      </div>
    </div>
  );
}
