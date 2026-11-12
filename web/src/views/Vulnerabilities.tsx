import { useEffect, useState } from "react";
import { catalog } from "../engine/engine";
import { Epss, ErrorLine, Kev, LEVEL_VAR, Lvl, Score, Sev, day, useApp, useLoad } from "../ui";

const PAGE = 50;

export function Vulnerabilities({ selected }: { selected: string | null }) {
  const { api, go } = useApp();
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [product, setProduct] = useState("");
  const [kev, setKev] = useState(false);
  const [matched, setMatched] = useState(true);
  const [sort, setSort] = useState("published");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const id = setTimeout(() => { setQuery(q); setPage(0); }, 250);
    return () => clearTimeout(id);
  }, [q]);

  const list = useLoad(() => api.vulnerabilities({ q: query, severity, product, kev, matched, sort, page, size: PAGE }), [query, severity, product, kev, matched, sort, page]);
  const reset = (fn: () => void) => { fn(); setPage(0); };
  const total = list.data?.total ?? 0;

  return (
    <>
      <section className="sheet narrow glass" aria-label="Vulnerabilities">
        <div className="panel-head">
          <h1>Vulnerabilities</h1>
          <span className="faint num">{total.toLocaleString("en-US")} match</span>
          <span className="spacer" />
          <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={matched} onChange={(e) => reset(() => setMatched(e.target.checked))} /> Reaching my sites</label>
          <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={kev} onChange={(e) => reset(() => setKev(e.target.checked))} /> Exploited</label>
        </div>
        <div className="panel-head" style={{ paddingTop: 10 }}>
          <input type="search" placeholder="CVE, GHSA id or text" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: "1 1 200px", width: "auto" }} aria-label="Search" />
          <select value={product} onChange={(e) => reset(() => setProduct(e.target.value))} style={{ width: "auto" }} aria-label="Product">
            <option value="">All products</option>
            {catalog.products.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
          </select>
          <select value={severity} onChange={(e) => reset(() => setSeverity(e.target.value))} style={{ width: "auto" }} aria-label="Severity">
            <option value="">Any severity</option>
            <option value="critical">Critical</option>
            <option value="critical,high">High and up</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={sort} onChange={(e) => reset(() => setSort(e.target.value))} style={{ width: "auto" }} aria-label="Sort">
            <option value="published">Newest</option>
            <option value="cvss">CVSS</option>
            <option value="epss">EPSS</option>
          </select>
        </div>
        <ErrorLine error={list.error} />
        <div className="scroll">
          <table className="data">
            <thead><tr><th>Vulnerability</th><th>Severity</th><th className="r">CVSS</th><th>EPSS</th><th className="hide-sm">Published</th><th className="r">Mine</th></tr></thead>
            <tbody>
              {(list.data?.items ?? []).map((v) => (
                <tr key={v.id} className="clickable" aria-selected={v.id === selected || v.aliases.includes(selected ?? "")} onClick={() => go(`#/vulnerabilities/${v.id}`)}>
                  <td>
                    <div className="row" style={{ gap: 6 }}><span className="id">{v.id}</span>{v.kev && <Kev />}{v.sources.length === 2 && <span className="tag" title="Reported by both NVD and GitHub; merged">NVD+GH</span>}</div>
                    <div className="dim" style={{ maxWidth: 440 }}>{v.title}</div>
                  </td>
                  <td><Sev s={v.severity} /></td>
                  <td className="r mono">{v.cvss?.toFixed(1) ?? "—"}</td>
                  <td><Epss p={v.epss} /></td>
                  <td className="hide-sm mono faint nowrap">{day(v.published)}</td>
                  <td className="r num">{v.matched ? <b>{v.matched}</b> : <span className="faint">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {list.data && list.data.items.length === 0 && <div className="empty">No vulnerabilities match these filters.</div>}
        </div>
        <div className="row" style={{ padding: "10px 16px", borderTop: "1px solid var(--line)" }}>
          <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span className="faint num">{total === 0 ? 0 : page * PAGE + 1}–{Math.min(total, (page + 1) * PAGE)} of {total.toLocaleString("en-US")}</span>
          <button className="btn small" disabled={(page + 1) * PAGE >= total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </section>
      {selected && <Detail id={selected} />}
    </>
  );
}

function Detail({ id }: { id: string }) {
  const { api, go, setHighlight, selectSite } = useApp();
  const d = useLoad(() => api.vulnerability(id), [id]);
  const v = d.data;

  // light up the sites this vulnerability reaches
  useEffect(() => {
    setHighlight(v ? new Set(v.matches.map((m) => m.siteId)) : null);
    return () => setHighlight(null);
  }, [v, setHighlight]);

  if (d.error) return <aside className="drawer glass"><div className="panel-body"><ErrorLine error={d.error} /></div></aside>;
  if (!v) return <aside className="drawer glass"><div className="empty">Loading…</div></aside>;
  const bySource = (s: string) => v.ranges.filter((r) => r.source === s);
  const sites = new Set(v.matches.map((m) => m.siteId)).size;

  return (
    <aside className="drawer glass" aria-label={v.id}>
      <div className="panel-head">
        <span className="id" style={{ fontSize: 15 }}>{v.id}</span>
        {v.kev && <Kev />}
        {v.withdrawn && <span className="tag">withdrawn</span>}
        <span className="spacer" />
        <button className="btn small ghost" onClick={() => go("#/vulnerabilities")} aria-label="Close">✕</button>
      </div>
      <div className="scroll">
        <div className="panel-body stack">
          {v.redirected && <div className="note">{v.requested} was merged into this record: both describe the same vulnerability.</div>}
          <div style={{ fontSize: 15, fontWeight: 600, lineHeight: 1.35 }}>{v.title}</div>
          <dl className="facts">
            <dt>Severity</dt><dd><Sev s={v.severity} /> {v.cvss != null && <span className="mono">CVSS {v.cvss.toFixed(1)}</span>} <span className="faint">from {v.cvssSource === "nvd" ? "NVD" : v.cvssSource === "ghsa" ? "GitHub" : "—"}</span></dd>
            <dt>Exploitation</dt><dd><Epss p={v.epss} />{v.epssPercentile != null && <span className="faint"> · percentile {(v.epssPercentile * 100).toFixed(1)}</span>}</dd>
            <dt>Sources</dt><dd>{v.sources.map((s) => (s === "nvd" ? "NVD" : "GitHub")).join(" + ")}</dd>
            <dt>Aliases</dt><dd className="mono">{v.aliases.join(", ")}</dd>
            <dt>Published</dt><dd className="mono">{day(v.published)} <span className="faint">· modified {day(v.modified)}</span></dd>
            {v.cwes.length > 0 && <><dt>Weakness</dt><dd className="mono">{v.cwes.join(", ")}</dd></>}
          </dl>
        </div>

        {v.kev && (
          <div className="section" style={{ background: "rgba(255,46,77,0.07)" }}>
            <h3 style={{ color: "#ff6b80" }}>Known exploited · CISA KEV</h3>
            <dl className="facts">
              <dt>Added</dt><dd className="mono">{v.kev.added}</dd>
              <dt>Due</dt><dd className="mono">{v.kev.due ?? "—"}</dd>
              <dt>Ransomware</dt><dd>{v.kev.ransomware ? <b style={{ color: "#ff6b80" }}>Known use in campaigns</b> : "Not known"}</dd>
              {v.kev.action && <><dt>Action</dt><dd>{v.kev.action}</dd></>}
            </dl>
          </div>
        )}

        <div className="section">
          <h3>Reaches {v.matches.length} of your assets{sites ? ` at ${sites} ${sites === 1 ? "site" : "sites"} (lit on the map)` : ""}</h3>
          {v.matches.length === 0 && <div className="faint">None of your assets match the affected versions.</div>}
          <div className="stack" style={{ gap: 6 }}>
            {v.matches.map((m) => (
              <button key={m.assetId} className="matchrow" style={{ ["--c" as string]: LEVEL_VAR[m.level] }} onClick={() => { selectSite(m.siteId); go("#/radar"); }}>
                <div className="row" style={{ gap: 8 }}><Score score={m.score} level={m.level} /><b>{m.label}</b><span className="mono faint">{m.version || "version unknown"}</span><span className="spacer" /><Lvl level={m.level} /></div>
                <div className="dim">{m.site} · {m.status === "possible" ? "possibly affected" : "affected"}{m.fixedIn ? <> · fixed in <span className="mono">{m.fixedIn}</span></> : ""}</div>
                <div className="faint" style={{ fontSize: 12 }}>{m.explanation}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="section">
          <h3>Affected versions by source</h3>
          {["nvd", "ghsa"].map((s) => bySource(s).length > 0 && (
            <div key={s} style={{ marginBottom: 10 }}>
              <div className="faint" style={{ fontSize: 12, marginBottom: 4 }}>{s === "nvd" ? "NVD (CPE)" : "GitHub (package)"}</div>
              {bySource(s).slice(0, 12).map((r, i) => (
                <div key={i} className="row mono" style={{ gap: 12, fontSize: 12, padding: "3px 0" }}><span>{r.identity}</span><span className="dim">{r.versions}</span>{r.fixed && <span className="faint">fix {r.fixed}</span>}</div>
              ))}
              {bySource(s).length > 12 && <div className="faint">+{bySource(s).length - 12} more</div>}
            </div>
          ))}
        </div>

        {v.description && <div className="section"><h3>Description</h3><div className="desc">{v.description}</div></div>}
        {v.cvssVector && <div className="section"><h3>CVSS vector</h3><code style={{ wordBreak: "break-all" }}>{v.cvssVector}</code></div>}
        <div className="section">
          <h3>References</h3>
          <div className="stack" style={{ gap: 4 }}>
            {v.references.slice(0, 10).map((r) => <a key={r.url} href={r.url} target="_blank" rel="noreferrer" style={{ wordBreak: "break-all", fontSize: 12 }}>{r.url}</a>)}
          </div>
        </div>
      </div>
    </aside>
  );
}
