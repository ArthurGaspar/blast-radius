import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Api, BrowserTransport, DEMO, HttpTransport, type Transport } from "./api/client";
import type { Exposure, Me } from "./api/types";
import { Ctx, ErrorLine, ago, type AppCtx } from "./ui";
import { Alerts } from "./views/Alerts";
import { Inventory } from "./views/Inventory";
import { Radar } from "./views/Radar";
import { Sources } from "./views/Sources";
import { Vulnerabilities } from "./views/Vulnerabilities";
import { LEVEL_GLOW, WorldRadar, type Insets, type Layers } from "./WorldRadar";

const apiUrl = import.meta.env.VITE_API_URL as string | undefined;
const TOKEN_KEY = `blast-radius.token.${apiUrl ? "api" : "browser"}`;
const read = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k: string, v: string | null) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* storage off */ } };

const ICON: Record<string, ReactNode> = {
  radar: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><path d="M12 12l6-5" /></>,
  vulnerabilities: <><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" /><path d="M12 8v5M12 16v.5" /></>,
  inventory: <><rect x="3" y="4" width="18" height="6" rx="1.5" /><rect x="3" y="14" width="18" height="6" rx="1.5" /><path d="M7 7h.01M7 17h.01" /></>,
  alerts: <><path d="M6 16V11a6 6 0 1112 0v5l2 2H4z" /><path d="M10 20a2 2 0 004 0" /></>,
  sources: <><ellipse cx="12" cy="6" rx="8" ry="3" /><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
  signout: <><path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10" /></>,
};
const Icon = ({ name }: { name: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>{ICON[name]}</svg>
);

const VIEWS = [
  { id: "radar", label: "Radar" },
  { id: "vulnerabilities", label: "Vulns" },
  { id: "inventory", label: "Inventory" },
  { id: "alerts", label: "Alerts" },
  { id: "sources", label: "Sources" },
];

const parseHash = () => {
  const [view = "radar", ...rest] = location.hash.replace(/^#\/?/, "").split("/");
  return { view: VIEWS.some((v) => v.id === view) ? view : "radar", arg: rest.join("/") ? decodeURIComponent(rest.join("/")) : null };
};

export function App() {
  const [transport, setTransport] = useState<Transport | null>(apiUrl ? new HttpTransport(apiUrl.replace(/\/$/, "")) : null);
  const [boot, setBoot] = useState("Starting…");
  const [token, setToken] = useState(() => read(TOKEN_KEY));
  const [me, setMe] = useState<Me | null>(null);
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const [revision, setRevision] = useState(0);
  const [route, setRoute] = useState(parseHash);
  const [fresh, setFresh] = useState<string | null>(null);
  const [selectedSite, selectSite] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<Set<string> | null>(null);
  const [layers, setLayers] = useState<Layers>({ probes: true, sweep: true });
  const [width, setWidth] = useState(() => window.innerWidth);
  useEffect(() => {
    const on = () => setWidth(window.innerWidth);
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);

  useEffect(() => {
    if (transport) return;
    BrowserTransport.open(setBoot).then(setTransport, (e) => setBoot(`Couldn't start: ${e.message}`));
  }, [transport]);

  useEffect(() => {
    const on = () => { setRoute(parseHash()); setHighlight(null); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  const signOut = useCallback(() => { write(TOKEN_KEY, null); setToken(null); setMe(null); setExposure(null); }, []);
  const api = useMemo(() => (transport ? new Api(transport, () => read(TOKEN_KEY), signOut) : null), [transport, signOut]);

  useEffect(() => {
    if (!api || !token) return;
    api.me().then(setMe, () => signOut());
    api.exposure().then(setExposure, () => undefined);
    api.ingestionStatus().then((s) => setFresh(s.last?.finishedAt ?? null), () => undefined);
  }, [api, token, revision, signOut]);

  // keep the whole world in the space the docked panels leave (widths mirror styles.css)
  const drawer = 410 + 24;
  const sheetRight = (max: number) => 82 + Math.min(max, width - 82 - drawer) + 24;
  const insets: Insets = !token || !me ? { left: 24, right: 24 }
    : route.view === "radar" ? { left: 96, right: drawer }
    : route.view === "vulnerabilities" ? { left: sheetRight(620), right: route.arg ? drawer : 24 }
    : { left: sheetRight(820), right: 24 };

  const map = (
    <WorldRadar
      insets={insets}
      sites={exposure?.sites ?? []}
      selected={route.view === "radar" ? selectedSite : null}
      highlight={highlight}
      layers={layers}
      onSelect={(id) => { selectSite(id); if (id && route.view !== "radar") location.hash = "#/radar"; }}
    />
  );

  if (!api) return <div className="stage">{map}<div className="boot">{boot}</div></div>;
  if (!token) return <div className="stage">{map}<Login api={api} browser={transport instanceof BrowserTransport} onAuth={(t) => { write(TOKEN_KEY, t); setToken(t); }} /></div>;
  if (!me) return <div className="stage">{map}<div className="boot">Loading…</div></div>;

  const ctx: AppCtx = {
    api, me, revision, exposure, selectedSite, selectSite, setHighlight,
    browser: transport instanceof BrowserTransport ? transport : null,
    bump: () => setRevision((r) => r + 1),
    go: (hash) => { location.hash = hash; },
  };
  const e = exposure;

  return (
    <Ctx.Provider value={ctx}>
      <div className="stage">
        {map}
        <div className="overlay">
          <nav className="rail glass" aria-label="Sections">
            <div className="logo" aria-hidden>
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="#5fe0c0" strokeOpacity=".5" />
                <circle cx="12" cy="12" r="5.5" stroke="#5fe0c0" strokeOpacity=".3" />
                <path d="M12 12L19.5 6.5" stroke="#5fe0c0" strokeWidth="1.6" />
                <circle cx="16" cy="15.5" r="2.2" fill="#ff2e4d" />
              </svg>
            </div>
            {VIEWS.map((v) => (
              <a key={v.id} href={`#/${v.id}`} aria-current={route.view === v.id ? "page" : undefined}>
                <Icon name={v.id} />
                {v.label}
                {v.id === "alerts" && me.unread > 0 && <span className="badge">{me.unread > 99 ? "99+" : me.unread}</span>}
              </a>
            ))}
            <span className="spacer" />
            <button className="navbtn" onClick={signOut} title={`Signed in as ${me.user.displayName}`}><Icon name="signout" />Sign out</button>
          </nav>

          <header className="statusbar glass">
            <span className="brand hide-sm">BLAST RADIUS</span>
            <span className="sep" />
            <div className="kpi">
              <span className="k">Exposure</span>
              <span className="v" style={{ color: e ? LEVEL_GLOW[e.level] : undefined }}>{e?.level.toUpperCase() ?? "—"}</span>
            </div>
            <div className="kpi"><span className="k">Sites</span><span className="v">{e?.totals.sites ?? "—"}</span></div>
            <div className="kpi hide-sm"><span className="k">Reaching you</span><span className="v">{e?.totals.vulnerabilities ?? "—"}</span></div>
            <div className="kpi hide-sm"><span className="k">Severe</span><span className="v" style={{ color: e?.totals.severe ? "var(--severe)" : undefined }}>{e?.totals.severe ?? "—"}</span></div>
            <div className="kpi"><span className="k">Exploited</span><span className="v" style={{ color: e?.totals.kev ? "var(--severe)" : undefined }}>{e?.totals.kev ?? "—"}</span></div>
            <span className="spacer" />
            <span className="clock hide-sm" title="Last ingestion run">{transport instanceof BrowserTransport ? "browser · " : ""}synced {ago(fresh)}</span>
            <Clock />
          </header>

          {route.view === "radar" && <Radar layers={layers} setLayers={setLayers} />}
          {route.view === "vulnerabilities" && <Vulnerabilities selected={route.arg} />}
          {route.view === "inventory" && <Inventory />}
          {route.view === "alerts" && <Alerts />}
          {route.view === "sources" && <Sources />}
        </div>
      </div>
    </Ctx.Provider>
  );
}

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const id = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(id); }, []);
  return <span className="clock">{now.toISOString().slice(11, 19)} UTC</span>;
}

function Login({ api, browser, onAuth }: { api: Api; browser: boolean; onAuth: (token: string) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState(browser ? DEMO.username : "");
  const [password, setPassword] = useState(browser ? DEMO.password : "");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const res = mode === "login" ? await api.login(username, password) : await api.register(username, displayName || username, password);
      onAuth(res.token);
    } catch (err) { setError((err as Error).message); }
  };
  return (
    <div className="login-wrap">
      <form className="glass login" onSubmit={submit}>
        <div className="panel-head">
          <h1 style={{ fontFamily: "var(--mono)", letterSpacing: "0.18em", fontSize: 14 }}>BLAST RADIUS</h1>
          <span className="spacer" />
          <button type="button" className="btn small ghost" onClick={() => setMode(mode === "login" ? "register" : "login")}>{mode === "login" ? "New account" : "Sign in instead"}</button>
        </div>
        <div className="panel-body">
          <p className="dim" style={{ margin: 0 }}>Which of your sites does each published vulnerability reach? NVD and GitHub advisories, merged, matched against your inventory, and ranked with CISA KEV and EPSS.</p>
          {browser && mode === "login" && <div className="note">This build runs in your browser. The demo account is filled in: 70 sites running AI and infrastructure software.</div>}
          <label className="field"><span>Username</span><input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
          {mode === "register" && <label className="field"><span>Display name</span><input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={60} /></label>}
          <label className="field"><span>Password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={mode === "register" ? 10 : undefined} />{mode === "register" && <small>At least 10 characters</small>}</label>
          <ErrorLine error={error} />
          <button className="btn primary">{mode === "login" ? "Sign in" : "Create account"}</button>
        </div>
      </form>
    </div>
  );
}
