import { useMemo, useState } from "react";
import type { Level } from "../api/types";
import { catalog } from "../engine/engine";
import { Epss, Kev, LEVEL_VAR, Lvl, Score, useApp, useLoad } from "../ui";
import { LEVEL_GLOW, type Layers } from "../WorldRadar";

const LEVELS: Level[] = ["severe", "high", "elevated", "low", "clear"];

export function Radar({ layers, setLayers }: { layers: Layers; setLayers: (l: Layers) => void }) {
  const { exposure, selectedSite, selectSite } = useApp();
  const [keyOpen, setKeyOpen] = useState(true);
  if (!exposure) return null;
  const site = exposure.sites.find((s) => s.id === selectedSite) ?? null;
  const threats = site ? exposure.threats.filter((t) => t.assets.some((a) => a.siteId === site.id)) : exposure.threats;

  return (
    <>
      <section className="layers glass" aria-label="Map key">
        <div className="card-title" style={{ marginBottom: keyOpen ? 6 : 0 }}>
          What you're seeing
          <span style={{ flex: 1 }} />
          <button className="btn small ghost" onClick={() => setKeyOpen(!keyOpen)} aria-expanded={keyOpen}>{keyOpen ? "Hide" : "Show"}</button>
        </div>
        {keyOpen && (
          <>
            <div className="keyrow">
              <svg width="22" height="22" viewBox="0 0 22 22"><circle cx="11" cy="11" r="5" fill={LEVEL_GLOW.severe} /><circle cx="11" cy="11" r="9" fill="none" stroke={LEVEL_GLOW.severe} strokeOpacity=".4" /></svg>
              <div>
                <b>Sites <span className="real">REAL</span></b>
                <small>Places in your inventory. Color is the worst vulnerability that matches the software installed there, from NVD and GitHub data. Size is how many products run there.</small>
              </div>
              <span />
            </div>
            <div className="keyrow">
              <svg width="22" height="22" viewBox="0 0 22 22"><path d="M2 18 Q 10 2 20 8" stroke="#ff9f2e" fill="none" strokeWidth="1.4" /><circle cx="20" cy="8" r="2" fill="#ff9f2e" /></svg>
              <div>
                <b>Probe traces <span className="sim">SIMULATED</span></b>
                <small>Animation only, not observed traffic. Their rate follows the KEV status and EPSS score of what each site runs.</small>
              </div>
              <button className="switch" role="switch" aria-checked={layers.probes} aria-label="Show probe traces" onClick={() => setLayers({ ...layers, probes: !layers.probes })} />
            </div>
            <div className="keyrow">
              <svg width="22" height="22" viewBox="0 0 22 22"><path d="M11 11 L21 4" stroke="#5fe0c0" strokeWidth="1.4" /><path d="M11 11 L21 4 A 12 12 0 0 0 14 0 Z" fill="#5fe0c0" fillOpacity=".2" /></svg>
              <div>
                <b>Sweep</b>
                <small>Decoration. Sites flash and show their name as it passes.</small>
              </div>
              <button className="switch" role="switch" aria-checked={layers.sweep} aria-label="Show sweep" onClick={() => setLayers({ ...layers, sweep: !layers.sweep })} />
            </div>
            <div className="legend" style={{ marginTop: 8 }}>
              {LEVELS.slice().reverse().map((l) => <span key={l} style={{ ["--c" as string]: LEVEL_GLOW[l] }}>{l}</span>)}
            </div>
          </>
        )}
      </section>

      {site ? <SiteDrawer siteId={site.id} onClose={() => selectSite(null)} /> : <Overview threats={threats} />}
    </>
  );
}

type Threats = NonNullable<ReturnType<typeof useApp>["exposure"]>["threats"];

function Overview({ threats }: { threats: Threats }) {
  const [tab, setTab] = useState<"sites" | "threats">("sites");
  return (
    <aside className="drawer glass" aria-label="Overview">
      <div className="panel-head" style={{ paddingBottom: 10 }}>
        <div className="seg" role="tablist">
          <button role="tab" aria-pressed={tab === "sites"} onClick={() => setTab("sites")}>Sites</button>
          <button role="tab" aria-pressed={tab === "threats"} onClick={() => setTab("threats")}>Top threats</button>
        </div>
      </div>
      {tab === "sites" ? <SiteList /> : <ThreatList threats={threats} />}
    </aside>
  );
}

function ThreatList({ threats }: { threats: Threats }) {
  const { go } = useApp();
  return (
    <>
      <div className="panel-head" style={{ paddingTop: 10 }}><span className="faint">Ranked by danger across all sites</span><span className="spacer" /><span className="faint">{threats.length}</span></div>
      <div className="scroll">
        {threats.slice(0, 40).map((t) => (
          <div key={t.id} className="threatrow" onClick={() => go(`#/vulnerabilities/${t.id}`)}>
            <Score score={t.score} level={t.level} />
            <div className="row" style={{ gap: 8, minWidth: 0 }}>
              <span className="id">{t.id}</span>
              {t.kev && <Kev />}
              <span className="faint nowrap" style={{ fontSize: 12 }}>{t.assets.length} {t.assets.length === 1 ? "asset" : "assets"}</span>
            </div>
            <Epss p={t.epss} />
            <div className="t">{t.title}</div>
          </div>
        ))}
        {threats.length === 0 && <div className="empty">Nothing known reaches your sites.</div>}
      </div>
    </>
  );
}

function SiteList() {
  const { exposure, selectSite } = useApp();
  const [level, setLevel] = useState<Level | null>(null);
  const [q, setQ] = useState("");
  const sites = exposure!.sites;
  const counts = useMemo(() => Object.fromEntries(LEVELS.map((l) => [l, sites.filter((s) => s.level === l).length])), [sites]);
  const shown = sites
    .filter((s) => !level || s.level === level)
    .filter((s) => !q || s.name.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return (
    <>
      <div className="panel-head" style={{ paddingTop: 10 }}>
        <span className="faint">{shown.length} of {sites.length} sites</span>
        <input type="search" placeholder="Find a site" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Find a site" />
        <div className="chips">
          {LEVELS.map((l) => (
            <button key={l} className="chip" style={{ ["--c" as string]: LEVEL_GLOW[l] }} aria-pressed={level === l} onClick={() => setLevel(level === l ? null : l)}>
              {l} <span className="n">{counts[l]}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="scroll sitelist">
        {shown.map((s) => (
          <button key={s.id} className="siteitem" onClick={() => selectSite(s.id)}>
            <b>{s.name}</b>
            <Lvl level={s.level} />
            <small>{s.assets} products · {s.affected} confirmed{s.possible ? ` · ${s.possible} possible` : ""}{s.kev ? ` · ${s.kev} exploited` : ""}{s.top ? ` · worst ${s.top.id}` : ""}</small>
          </button>
        ))}
      </div>
    </>
  );
}

function SiteDrawer({ siteId, onClose }: { siteId: string; onClose: () => void }) {
  const { api, exposure, go } = useApp();
  const assets = useLoad(() => api.assets());
  const scoped = useLoad(() => api.exposure(siteId), [siteId]);
  const site = exposure!.sites.find((s) => s.id === siteId)!;
  const here = (assets.data ?? []).filter((a) => a.siteId === siteId).sort((a, b) => b.maxScore - a.maxScore);
  const threats = scoped.data?.threats ?? [];
  const worstFor = (assetId: string) => threats.find((t) => t.assets.some((a) => a.assetId === assetId));

  return (
    <aside className="drawer glass" aria-label={site.name}>
      <div className="panel-head">
        <div style={{ minWidth: 0 }}>
          <h1>{site.name}</h1>
          <div className="faint" style={{ fontSize: 12 }}>{site.kind === "cloud" ? "Cloud region" : site.kind === "datacenter" ? "Data center" : "Office"} · {site.lat.toFixed(2)}, {site.lon.toFixed(2)}</div>
        </div>
        <span className="spacer" />
        <button className="btn small ghost" onClick={onClose} aria-label="Back to all sites">✕</button>
      </div>
      <div className="scroll">
        <div className="panel-body">
          <div className="bigscore" style={{ ["--c" as string]: LEVEL_VAR[site.level] }}>
            <span className="v">{site.score.toFixed(1)}</span>
            <Lvl level={site.level} />
          </div>
          <div className="dim" style={{ marginTop: 6 }}>
            {site.affected} vulnerabilities confirmed by version{site.possible ? `, ${site.possible} possible` : ""}{site.kev ? `, ${site.kev} exploited in the wild` : ""}.
          </div>
        </div>

        <div className="section">
          <h3>Software installed here</h3>
          {here.map((a) => {
            const worst = worstFor(a.id);
            const product = catalog.products.find((p) => p.key === a.productKey);
            return (
              <div key={a.id} className="assetrow">
                <div>
                  <b>{a.label}</b> <span className="mono faint">{a.version || "version unknown"}</span>
                  {product && a.label !== product.name && <div className="faint" style={{ fontSize: 12 }}>{product.name}</div>}
                </div>
                <Lvl level={a.level} />
                <div className="faint" style={{ fontSize: 12, gridColumn: "1 / -1" }}>
                  {a.affected || a.possible
                    ? <>{a.affected} confirmed{a.possible ? `, ${a.possible} possible` : ""}{worst && <> · worst <a href={`#/vulnerabilities/${worst.id}`}>{worst.id}</a></>}</>
                    : "No known vulnerability matches this version"}
                </div>
              </div>
            );
          })}
          {assets.data && here.length === 0 && <div className="faint">Nothing tracked here yet.</div>}
        </div>

        <div className="section">
          <h3>Why it's this color{threats.length > 8 ? ` · top 8 of ${threats.length}` : ""}</h3>
          <div className="stack" style={{ gap: 6 }}>
            {threats.slice(0, 8).map((t) => {
              const a = t.assets.find((x) => x.siteId === siteId)!;
              return (
                <button key={t.id} className="matchrow" style={{ ["--c" as string]: LEVEL_VAR[t.level] }} onClick={() => go(`#/vulnerabilities/${t.id}`)}>
                  <div className="row" style={{ gap: 8 }}><Score score={a.score} level={t.level} /><span className="id">{t.id}</span>{t.kev && <Kev />}<span className="spacer" /><Epss p={t.epss} /></div>
                  <div className="dim">{t.title}</div>
                  <div className="faint" style={{ fontSize: 12 }}>{a.label}: {a.explanation}</div>
                </button>
              );
            })}
            {threats.length === 0 && <div className="faint">Every product here is on a version with no known vulnerabilities.</div>}
          </div>
        </div>
      </div>
    </aside>
  );
}
