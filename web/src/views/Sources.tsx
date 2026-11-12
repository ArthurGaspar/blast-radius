import { useEffect, useState } from "react";
import { ErrorLine, ago, useAction, useApp, useLoad } from "../ui";

const SOURCE_NAME: Record<string, string> = { nvd: "NVD", ghsa: "GitHub", kev: "CISA KEV", epss: "FIRST EPSS" };

export function Sources() {
  const { api, browser } = useApp();
  const status = useLoad(() => api.ingestionStatus());
  const { run, busy, error } = useAction();
  const [progress, setProgress] = useState<{ source: string; target: string; done: number; total: number } | null>(null);

  useEffect(() => {
    if (!browser) return;
    browser.onProgress = (p) => setProgress(p.source === "done" ? null : p);
    return () => { browser.onProgress = null; };
  }, [browser]);

  const s = status.data;
  const last = s?.last;
  return (
    <section className="sheet glass wide"><div className="scroll"><div className="stack sheet-body">
      <div className="head">
        <h1>Sources</h1>
        <span className="dim">last sync {ago(last?.finishedAt)}</span>
        <span className="spacer" />
        <button className="btn primary" disabled={busy || s?.running} onClick={() => run(() => api.runIngestion())}>{busy ? "Syncing…" : "Sync now"}</button>
      </div>
      {busy && progress && (
        <div className="panel panel-body stack" style={{ gap: 6 }}>
          <div className="row"><b>{SOURCE_NAME[progress.source] ?? progress.source}</b><span className="mono faint">{progress.target}</span><span className="spacer" /><span className="faint num">{progress.done}/{progress.total}</span></div>
          <div className="progress"><i style={{ width: `${(progress.done / progress.total) * 100}%` }} /></div>
          {browser && <small className="faint">NVD allows 5 requests per 30 seconds without an API key, so a full pass takes a couple of minutes. Later syncs only fetch what changed.</small>}
        </div>
      )}
      <ErrorLine error={error ?? status.error} />
      {last && last.errors.length > 0 && <div className="error">{last.errors.join(" · ")}</div>}

      {s && (
        <div className="panel">
          <div className="stats">
            <div className="stat"><div className="k">Vulnerabilities</div><div className="v num">{s.totals.vulnerabilities.toLocaleString("en-US")}</div></div>
            <div className="stat"><div className="k">In both NVD and GitHub</div><div className="v num">{s.totals.both}</div></div>
            <div className="stat"><div className="k">Only NVD · only GitHub</div><div className="v num">{s.totals.nvdOnly} · {s.totals.ghsaOnly}</div></div>
            <div className="stat"><div className="k">Exploited (KEV)</div><div className="v num red">{s.totals.kev}</div></div>
            <div className="stat"><div className="k">Identifiers tracked</div><div className="v num">{s.totals.aliases.toLocaleString("en-US")}</div></div>
          </div>
        </div>
      )}

      {last && (
        <section className="panel">
          <div className="panel-head"><h2>Last run</h2><span className="spacer" /><span className="faint mono">{last.batchId.slice(0, 8)}</span></div>
          <div className="panel-body">
            <span className="mono">{last.fetched.toLocaleString("en-US")}</span> records fetched → <span className="mono">{last.created}</span> new,{" "}
            <span className="mono">{last.updated}</span> updated, <span className="mono">{last.linked}</span> joined a record from the other source,{" "}
            <span className="mono">{last.merged}</span> duplicates merged or re-keyed · <span className="mono">{last.kevMarked}</span> KEV changes ·{" "}
            <span className="mono">{last.epssScored}</span> EPSS scores · <span className="mono">{last.notifications}</span> alerts
          </div>
        </section>
      )}

      <section className="panel">
        <div className="panel-head"><h2>Per source and product</h2></div>
        <div className="table-scroll">
          <table className="data">
            <thead><tr><th>Source</th><th>Target</th><th className="r">Fetched</th><th className="r">New</th><th className="r">Updated</th><th className="r">Linked</th><th className="r">Merged</th><th>When</th></tr></thead>
            <tbody>
              {(s?.targets ?? []).map((t) => (
                <tr key={`${t.source}|${t.target}`}>
                  <td>{SOURCE_NAME[t.source] ?? t.source}</td>
                  <td className="mono">{t.target}{t.error && <div style={{ color: "var(--severe)", fontFamily: "var(--font)", fontSize: 12 }}>{t.error}</div>}</td>
                  <td className="r num">{t.fetched}</td><td className="r num">{t.created}</td><td className="r num">{t.updated}</td><td className="r num">{t.linked}</td><td className="r num">{t.merged}</td>
                  <td className="faint nowrap">{ago(t.finishedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2>How it works</h2></div>
        <div className="panel-body stack" style={{ maxWidth: 860 }}>
          <div><b>Sources.</b> NVD (per product, by CPE), the GitHub Advisory Database (per package), CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS scores. {browser ? "This build calls them directly from your browser." : "The API polls them on a schedule."}</div>
          <div><b>Deduplication.</b> NVD and GitHub often describe the same flaw. Records are joined by any shared identifier (CVE or GHSA). A GitHub advisory that only gets its CVE later is re-keyed and merged into the CVE record. GitHub's summary is used as the title; NVD's description and CVSS win; each source keeps its own version ranges.</div>
          <div><b>Matching.</b> Each asset is compared with every range for its package or CPE. Versions are compared across ecosystems (pre-releases, OpenSSL letter suffixes, OpenSSH patch levels). A range with bounds beats one without: NVD sometimes names a product with no versions at all, which can't confirm anything about a specific install. Such matches, assets with no version, and date-shaped versions that can't be compared with release numbers are “possibly affected”.</div>
          <div><b>Alerts.</b> Raised when ingestion finds something new: a new exposure, a vulnerability added to KEV, or a severity increase. Only matches backed by a version range, or by an asset whose version you haven't recorded, raise alerts; a source listing no versions doesn't. Editing the inventory recalculates exposure without alerting.</div>
          <div><b>Danger.</b> CVSS, plus 2 if the vulnerability is in KEV, plus 3 × EPSS, capped at 10; × 0.6 when the version is unknown. ≥ 9 severe, ≥ 7 high, ≥ 4 elevated.</div>
          <div><b>The map.</b> Site colors are this exposure. The probe traces are a visual simulation; their rate follows the KEV status and EPSS of what each site runs. They don't represent observed traffic.</div>
        </div>
      </section>
    </div></div></section>
  );
}
