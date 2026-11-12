import { useState, type FormEvent } from "react";
import type { Asset, Site } from "../api/types";
import { catalog } from "../engine/engine";
import { ErrorLine, Lvl, useAction, useApp, useLoad } from "../ui";

export function Inventory() {
  const { api } = useApp();
  const sites = useLoad(() => api.sites());
  const assets = useLoad(() => api.assets());
  const [adding, setAdding] = useState(false);

  return (
    <section className="sheet glass"><div className="scroll"><div className="stack sheet-body">
      <div className="head">
        <h1>Inventory</h1>
        <span className="dim">{sites.data?.length ?? 0} sites · {assets.data?.length ?? 0} assets</span>
        <span className="spacer" />
        <button className="btn primary" onClick={() => setAdding(true)}>Add site</button>
      </div>
      <div className="note">Changing the inventory recalculates exposure immediately and quietly. Alerts are only raised when new data from the sources changes what reaches you.</div>
      {adding && <SiteForm onDone={() => setAdding(false)} />}
      <ErrorLine error={sites.error ?? assets.error} />
      {(sites.data ?? []).map((s) => <SiteCard key={s.id} site={s} assets={(assets.data ?? []).filter((a) => a.siteId === s.id)} />)}
      {sites.data?.length === 0 && !adding && <div className="panel empty">No sites yet.</div>}
    </div></div></section>
  );
}

function SiteForm({ site, onDone }: { site?: Site; onDone: () => void }) {
  const { api } = useApp();
  const { run, busy, error } = useAction();
  const [name, setName] = useState(site?.name ?? "");
  const [kind, setKind] = useState<string>(site?.kind ?? "office");
  const [preset, setPreset] = useState(site?.presetKey ?? (site ? "" : "sao-paulo"));
  const [lat, setLat] = useState(String(site?.lat ?? ""));
  const [lon, setLon] = useState(String(site?.lon ?? ""));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = preset ? { name, kind, presetKey: preset } : { name, kind, lat: Number(lat), lon: Number(lon) };
    run(() => api.saveSite(site?.id ?? null, body as Partial<Site>)).then((ok) => ok && onDone());
  };
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-head"><h2>{site ? "Edit site" : "New site"}</h2></div>
      <div className="panel-body stack">
        <div className="row" style={{ alignItems: "end" }}>
          <label className="field" style={{ flex: "2 1 200px" }}><span>Name</span><input type="text" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required placeholder="e.g. Inference cluster" /></label>
          <label className="field" style={{ flex: "1 1 140px" }}><span>Kind</span>
            <select value={kind} onChange={(e) => setKind(e.target.value)}><option value="office">Office</option><option value="datacenter">Data center</option><option value="cloud">Cloud region</option></select>
          </label>
          <label className="field" style={{ flex: "2 1 220px" }}><span>Location</span>
            <select value={preset} onChange={(e) => setPreset(e.target.value)}>
              {catalog.sitePresets.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
              <option value="">Coordinates…</option>
            </select>
          </label>
          {!preset && <>
            <label className="field" style={{ flex: "0 1 100px" }}><span>Latitude</span><input type="number" step="0.01" min={-90} max={90} value={lat} onChange={(e) => setLat(e.target.value)} required /></label>
            <label className="field" style={{ flex: "0 1 100px" }}><span>Longitude</span><input type="number" step="0.01" min={-180} max={180} value={lon} onChange={(e) => setLon(e.target.value)} required /></label>
          </>}
        </div>
        <ErrorLine error={error} />
        <div className="row"><button className="btn primary" disabled={busy}>Save site</button><button type="button" className="btn ghost" onClick={onDone}>Cancel</button></div>
      </div>
    </form>
  );
}

function SiteCard({ site, assets }: { site: Site; assets: Asset[] }) {
  const { api, selectSite } = useApp();
  const { run, busy, error } = useAction();
  const [editing, setEditing] = useState(false);
  const [adding, setAdding] = useState(false);
  const worst = assets.reduce((m, a) => (a.maxScore > m.maxScore ? a : m), { maxScore: 0, level: "clear" } as Pick<Asset, "maxScore" | "level">);

  if (editing) return <SiteForm site={site} onDone={() => setEditing(false)} />;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2 style={{ textTransform: "none", letterSpacing: 0, fontSize: 14, color: "var(--ink)" }}>{site.name}</h2>
        <span className="faint">{site.kind === "cloud" ? "cloud region" : site.kind} · {catalog.sitePresets.find((p) => p.key === site.presetKey)?.label ?? `${site.lat.toFixed(2)}, ${site.lon.toFixed(2)}`}</span>
        <Lvl level={worst.level} />
        <span className="spacer" />
        <button className="btn small ghost" onClick={() => { selectSite(site.id); location.hash = "#/radar"; }}>Show on map</button>
        <button className="btn small" onClick={() => setAdding(true)}>Add software</button>
        <button className="btn small ghost" onClick={() => setEditing(true)}>Edit</button>
        <button className="btn small ghost danger" disabled={busy} onClick={() => confirm(`Delete ${site.name} and its ${assets.length} assets?`) && run(() => api.deleteSite(site.id))}>Delete</button>
      </div>
      <ErrorLine error={error} />
      {adding && <AssetForm siteId={site.id} onDone={() => setAdding(false)} />}
      <div className="table-scroll">
        <table className="data">
          <thead><tr><th>Software</th><th>Version</th><th>Identity</th><th>Exposure</th><th /></tr></thead>
          <tbody>{assets.map((a) => <AssetRow key={a.id} asset={a} />)}</tbody>
        </table>
        {assets.length === 0 && !adding && <div className="empty">Nothing tracked here yet.</div>}
      </div>
    </section>
  );
}

function AssetRow({ asset }: { asset: Asset }) {
  const { api } = useApp();
  const { run, busy, error } = useAction();
  const [version, setVersion] = useState(asset.version);
  const dirty = version.trim() !== asset.version;
  const save = () => run(() => api.saveAsset(asset.id, { siteId: asset.siteId, productKey: asset.productKey, label: asset.label, version, ecosystem: asset.ecosystem, package: asset.package, cpeVendor: asset.cpeVendor, cpeProduct: asset.cpeProduct }));
  return (
    <tr>
      <td><b>{asset.label}</b>{asset.productKey && asset.label !== catalog.products.find((p) => p.key === asset.productKey)?.name && <div className="faint">{catalog.products.find((p) => p.key === asset.productKey)?.name}</div>}</td>
      <td>
        <form className="row" style={{ gap: 4, flexWrap: "nowrap" }} onSubmit={(e) => { e.preventDefault(); save(); }}>
          <input type="text" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="unknown" style={{ width: 110, fontFamily: "var(--mono)" }} aria-label={`${asset.label} version`} />
          {dirty && <button className="btn small primary" disabled={busy}>Save</button>}
        </form>
        <ErrorLine error={error} />
      </td>
      <td className="mono faint" style={{ fontSize: 12 }}>
        {asset.ecosystem && <div>{asset.ecosystem}/{asset.package}</div>}
        {asset.cpeVendor && <div>cpe {asset.cpeVendor}:{asset.cpeProduct}</div>}
      </td>
      <td>
        <Lvl level={asset.level} />
        <div className="faint" style={{ fontSize: 12 }}>{asset.affected} affected{asset.possible ? ` · ${asset.possible} possible` : ""}</div>
      </td>
      <td className="r">
        <button className="btn small ghost danger" disabled={busy} onClick={() => run(() => api.deleteAsset(asset.id))}>Remove</button>
      </td>
    </tr>
  );
}

function AssetForm({ siteId, onDone }: { siteId: string; onDone: () => void }) {
  const { api } = useApp();
  const { run, busy, error } = useAction();
  const [productKey, setProductKey] = useState(catalog.products[0].key);
  const [version, setVersion] = useState("");
  const [label, setLabel] = useState("");
  const [eco, setEco] = useState("pip");
  const [pkg, setPkg] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const custom = productKey === "";
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = custom
      ? { siteId, label, version, ecosystem: pkg ? eco : null, package: pkg || null, cpeVendor: vendor || null, cpeProduct: product || null }
      : { siteId, productKey, version, label };
    run(() => api.saveAsset(null, body)).then((ok) => ok && onDone());
  };
  return (
    <form className="panel-body stack" style={{ background: "var(--panel-2)", borderBottom: "1px solid var(--line)" }} onSubmit={submit}>
      <div className="row" style={{ alignItems: "end" }}>
        <label className="field" style={{ flex: "2 1 220px" }}><span>Software</span>
          <select value={productKey} onChange={(e) => setProductKey(e.target.value)}>
            <optgroup label="AI and ML">{catalog.products.filter((p) => p.category === "ai").map((p) => <option key={p.key} value={p.key}>{p.name} · {p.description}</option>)}</optgroup>
            <optgroup label="Infrastructure">{catalog.products.filter((p) => p.category === "infra").map((p) => <option key={p.key} value={p.key}>{p.name} · {p.description}</option>)}</optgroup>
            <option value="">Something else (enter its identity)…</option>
          </select>
        </label>
        <label className="field" style={{ flex: "1 1 120px" }}><span>Version</span><input type="text" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="unknown" className="mono" /></label>
        <label className="field" style={{ flex: "1 1 160px" }}><span>Label</span><input type="text" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} placeholder="optional" /></label>
      </div>
      {custom && (
        <div className="row" style={{ alignItems: "end" }}>
          <label className="field" style={{ flex: "0 1 120px" }}><span>Ecosystem</span>
            <select value={eco} onChange={(e) => setEco(e.target.value)}>{["pip", "npm", "go", "maven", "nuget", "rubygems", "rust", "composer"].map((x) => <option key={x}>{x}</option>)}</select>
          </label>
          <label className="field" style={{ flex: "1 1 160px" }}><span>Package</span><input type="text" value={pkg} onChange={(e) => setPkg(e.target.value)} placeholder="e.g. fastapi" /></label>
          <span className="faint">and/or</span>
          <label className="field" style={{ flex: "1 1 120px" }}><span>CPE vendor</span><input type="text" value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="e.g. tiangolo" /></label>
          <label className="field" style={{ flex: "1 1 120px" }}><span>CPE product</span><input type="text" value={product} onChange={(e) => setProduct(e.target.value)} placeholder="e.g. fastapi" /></label>
        </div>
      )}
      {custom && <small className="faint">Custom identities are added to the watch list; the next sync fetches their advisories.</small>}
      <ErrorLine error={error} />
      <div className="row"><button className="btn primary" disabled={busy}>Add</button><button type="button" className="btn ghost" onClick={onDone}>Cancel</button></div>
    </form>
  );
}
