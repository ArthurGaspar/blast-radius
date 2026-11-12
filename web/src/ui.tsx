import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { Api, BrowserTransport } from "./api/client";
import type { Exposure, Level, Me } from "./api/types";

export interface AppCtx {
  api: Api;
  browser: BrowserTransport | null;
  me: Me;
  revision: number;
  bump: () => void;
  go: (hash: string) => void;
  /** Exposure drives the map behind every view. */
  exposure: Exposure | null;
  selectedSite: string | null;
  selectSite: (id: string | null) => void;
  /** Sites to light up on the map (e.g. those an open vulnerability reaches); null shows all normally. */
  setHighlight: (ids: Set<string> | null) => void;
}
export const Ctx = createContext<AppCtx | null>(null);
export const useApp = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("outside provider");
  return c;
};

/** Loads on mount and whenever the app revision changes (every mutation bumps it). */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const { revision } = useApp();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);
  useEffect(() => {
    const mine = ++seq.current;
    fn().then((d) => { if (mine === seq.current) { setData(d); setError(null); } }, (e) => { if (mine === seq.current) setError(e.message); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision, ...deps]);
  return { data, error };
}

export function useAction() {
  const { bump } = useApp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async (fn: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await fn(); bump(); return true; } catch (e) { setError((e as Error).message); return false; } finally { setBusy(false); }
  }, [bump]);
  return { run, busy, error, setError };
}

export const LEVEL_VAR: Record<Level, string> = {
  clear: "var(--clear)", low: "var(--low)", elevated: "var(--elevated)", high: "var(--high)", severe: "var(--severe)",
};

export const Lvl = ({ level }: { level: Level }) => <span className={`lvl lvl-${level}`}>{level}</span>;

export const Score = ({ score, level }: { score: number; level: Level }) =>
  <span className="score" style={{ ["--c" as string]: LEVEL_VAR[level] }} title={`Danger ${score.toFixed(1)} of 10`}>{score.toFixed(1)}</span>;

export const Sev = ({ s }: { s: string | null }) => <span className={`sev sev-${s ?? "none"}`}>{s ?? "unknown"}</span>;

export const Kev = ({ title }: { title?: string }) => <span className="kev" title={title ?? "Listed in CISA's Known Exploited Vulnerabilities catalog"}>EXPLOITED</span>;

export function Epss({ p }: { p: number | null }) {
  if (p == null) return <span className="faint">—</span>;
  const color = p >= 0.5 ? "var(--severe)" : p >= 0.1 ? "var(--high)" : p >= 0.01 ? "var(--elevated)" : "var(--ink-3)";
  return (
    <span className="epss" title="EPSS: probability of exploitation in the next 30 days (FIRST)">
      <i style={{ ["--p" as string]: `${Math.max(2, p * 100)}%`, ["--c" as string]: color }} />
      {(p * 100).toFixed(p < 0.01 ? 2 : 1)}%
    </span>
  );
}

export function ago(iso: string | null | undefined) {
  if (!iso) return "never";
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400 * 1.5) return `${Math.round(s / 3600)} h ago`;
  if (s < 86400 * 60) return `${Math.round(s / 86400)} days ago`;
  return new Date(iso).toLocaleDateString();
}

export const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : "—");

export const ErrorLine = ({ error }: { error: string | null | undefined }) => (error ? <div className="error" role="alert">{error}</div> : null);

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>{o.label}</button>)}
    </div>
  );
}
