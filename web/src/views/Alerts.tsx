import { useState, type FormEvent } from "react";
import type { Subscription } from "../api/types";
import { catalog } from "../engine/engine";
import { ErrorLine, Seg, Sev, ago, useAction, useApp, useLoad } from "../ui";

const REASON: Record<string, { label: string; color: string }> = {
  kev_added: { label: "Now exploited", color: "var(--severe)" },
  severity_raised: { label: "Severity raised", color: "var(--high)" },
  new_exposure: { label: "New exposure", color: "var(--elevated)" },
};

export function Alerts() {
  const [tab, setTab] = useState<"inbox" | "subscriptions" | "deliveries">("inbox");
  return (
    <section className="sheet glass"><div className="scroll"><div className="stack sheet-body">
      <div className="head">
        <h1>Alerts</h1>
        <Seg label="Section" value={tab} onChange={setTab} options={[{ value: "inbox", label: "Inbox" }, { value: "subscriptions", label: "Subscriptions" }, { value: "deliveries", label: "Webhook log" }]} />
      </div>
      {tab === "inbox" && <InboxView />}
      {tab === "subscriptions" && <SubscriptionsView />}
      {tab === "deliveries" && <DeliveriesView />}
    </div></div></section>
  );
}

function InboxView() {
  const { api, go } = useApp();
  const [unread, setUnread] = useState(true);
  const inbox = useLoad(() => api.notifications(unread), [unread]);
  const { run, busy } = useAction();
  return (
    <section className="panel">
      <div className="panel-head">
        <Seg label="Filter" value={unread ? "unread" : "all"} onChange={(v) => setUnread(v === "unread")} options={[{ value: "unread", label: `Unread ${inbox.data?.unread ?? ""}` }, { value: "all", label: "All" }]} />
        <span className="spacer" />
        <button className="btn small" disabled={busy || !inbox.data?.unread} onClick={() => run(() => api.readAll())}>Mark all read</button>
      </div>
      {(inbox.data?.items ?? []).map((n) => (
        <div key={n.id} className={`inbox-item${n.readAt ? " read" : ""}`} style={{ ["--c" as string]: REASON[n.reason].color }}>
          <div style={{ paddingLeft: 2 }}>
            <div className="row" style={{ gap: 8 }}>
              <span className="tag" style={{ color: REASON[n.reason].color, borderColor: "currentColor" }}>{REASON[n.reason].label}</span>
              <a href={`#/vulnerabilities/${n.vulnerabilityId}`} onClick={() => !n.readAt && api.read(n.id)}><b>{n.title}</b></a>
            </div>
            <div className="dim">{n.detail}</div>
            <div className="faint" style={{ fontSize: 12 }}>via “{n.subscription}” · <Sev s={n.severity} /></div>
          </div>
          <div className="stack" style={{ justifyItems: "end", gap: 4 }}>
            <span className="faint nowrap" style={{ fontSize: 12 }}>{ago(n.createdAt)}</span>
            {!n.readAt && <button className="btn small ghost" onClick={async () => { await api.read(n.id); go(`#/vulnerabilities/${n.vulnerabilityId}`); }}>Open</button>}
          </div>
        </div>
      ))}
      {inbox.data && inbox.data.items.length === 0 && <div className="empty">{unread ? "Nothing unread." : "No alerts yet."}</div>}
    </section>
  );
}

function SubscriptionsView() {
  const { api } = useApp();
  const subs = useLoad(() => api.subscriptions());
  const [editing, setEditing] = useState<Subscription | "new" | null>(null);
  return (
    <>
      <div className="row"><button className="btn primary" onClick={() => setEditing("new")}>New subscription</button><span className="faint">Each subscription gets at most one alert per vulnerability and reason.</span></div>
      {editing && <SubscriptionForm sub={editing === "new" ? null : editing} onDone={() => setEditing(null)} />}
      {(subs.data ?? []).map((s) => <SubscriptionCard key={s.id} sub={s} onEdit={() => setEditing(s)} />)}
    </>
  );
}

function SubscriptionCard({ sub, onEdit }: { sub: Subscription; onEdit: () => void }) {
  const { api, browser } = useApp();
  const preview = useLoad(() => api.preview(sub.id), [sub.id]);
  const sites = useLoad(() => api.sites());
  const { run, busy, error } = useAction();
  const [test, setTest] = useState<string | null>(null);
  const scope = sub.scope === "site" ? `site: ${sites.data?.find((s) => s.id === sub.scopeSiteId)?.name ?? "…"}` : sub.scope === "product" ? `product: ${catalog.products.find((p) => p.key === sub.scopeProductKey)?.name}` : "all sites";
  return (
    <section className="panel">
      <div className="panel-head">
        <b>{sub.name}</b>
        {!sub.active && <span className="tag">paused</span>}
        <span className="spacer" />
        <button className="btn small ghost" onClick={onEdit}>Edit</button>
        <button className="btn small ghost danger" disabled={busy} onClick={() => confirm(`Delete “${sub.name}”?`) && run(() => api.deleteSubscription(sub.id))}>Delete</button>
      </div>
      <div className="panel-body stack">
        <div className="row" style={{ gap: 6 }}>
          <span className="tag">{scope}</span>
          <span className="tag">{sub.minSeverity}+</span>
          {sub.kevOnly && <span className="tag">exploited only</span>}
          {sub.minEpss > 0 && <span className="tag">EPSS ≥ {(sub.minEpss * 100).toFixed(0)}%</span>}
          {sub.keyword && <span className="tag">“{sub.keyword}”</span>}
          {sub.webhookUrl && <span className="tag">webhook {new URL(sub.webhookUrl).host}</span>}
        </div>
        {preview.data && (
          <div className="dim">
            Against today's exposure this would cover <b>{preview.data.vulnerabilities}</b> vulnerabilities on {preview.data.matches} asset matches
            {preview.data.sample.length > 0 && <>: {preview.data.sample.map((x, i) => <span key={x.id}>{i > 0 && ", "}<a href={`#/vulnerabilities/${x.id}`} className="mono">{x.id}</a></span>)}</>}
          </div>
        )}
        {sub.webhookUrl && (
          <div className="row">
            <button className="btn small" disabled={busy} onClick={() => run(async () => { const d = await api.testWebhook(sub.id); setTest(`${d.outcome}${d.httpStatus ? ` (HTTP ${d.httpStatus})` : ""}${d.error ? `: ${d.error}` : ""}`); })}>Send test webhook</button>
            {test && <span className="faint">{test}</span>}
            {browser && !test && <span className="faint">The browser build records webhooks without sending them.</span>}
          </div>
        )}
        <ErrorLine error={error} />
      </div>
    </section>
  );
}

function SubscriptionForm({ sub, onDone }: { sub: Subscription | null; onDone: () => void }) {
  const { api } = useApp();
  const sites = useLoad(() => api.sites());
  const { run, busy, error } = useAction();
  const [name, setName] = useState(sub?.name ?? "");
  const [scope, setScope] = useState(sub?.scope ?? "all");
  const [siteId, setSiteId] = useState(sub?.scopeSiteId ?? "");
  const [productKey, setProductKey] = useState(sub?.scopeProductKey ?? catalog.products[0].key);
  const [minSeverity, setMinSeverity] = useState(sub?.minSeverity ?? "high");
  const [kevOnly, setKevOnly] = useState(sub?.kevOnly ?? false);
  const [minEpss, setMinEpss] = useState(sub?.minEpss ?? 0);
  const [keyword, setKeyword] = useState(sub?.keyword ?? "");
  const [webhookUrl, setWebhookUrl] = useState(sub?.webhookUrl ?? "");
  const [active, setActive] = useState(sub?.active ?? true);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    run(() => api.saveSubscription(sub?.id ?? null, {
      name, scope, scopeSiteId: scope === "site" ? siteId || sites.data?.[0]?.id : null, scopeProductKey: scope === "product" ? productKey : null,
      minSeverity, kevOnly, minEpss, keyword: keyword || null, webhookUrl: webhookUrl || null, active,
    })).then((ok) => ok && onDone());
  };
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-head"><h2>{sub ? "Edit subscription" : "New subscription"}</h2></div>
      <div className="panel-body stack">
        <div className="grid2">
          <label className="field"><span>Name</span><input type="text" value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} /></label>
          <label className="field"><span>Scope</span>
            <select value={scope} onChange={(e) => setScope(e.target.value as Subscription["scope"])}><option value="all">All sites</option><option value="site">One site</option><option value="product">One product</option></select>
          </label>
          {scope === "site" && <label className="field"><span>Site</span><select value={siteId} onChange={(e) => setSiteId(e.target.value)}>{(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
          {scope === "product" && <label className="field"><span>Product</span><select value={productKey} onChange={(e) => setProductKey(e.target.value)}>{catalog.products.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}</select></label>}
          <label className="field"><span>Minimum severity</span>
            <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>{["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}</select>
          </label>
          <label className="field"><span>Minimum EPSS: {(minEpss * 100).toFixed(0)}%</span><input type="range" min={0} max={1} step={0.01} value={minEpss} onChange={(e) => setMinEpss(Number(e.target.value))} /></label>
          <label className="field"><span>Keyword</span><input type="text" value={keyword} onChange={(e) => setKeyword(e.target.value)} maxLength={60} placeholder="optional, e.g. deserialization" /></label>
          <label className="field"><span>Webhook</span><input type="url" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} placeholder="https://… (optional)" /><small>Public https endpoints only; private and metadata addresses are refused.</small></label>
        </div>
        <div className="row">
          <label className="row" style={{ gap: 5 }}><input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> Only vulnerabilities exploited in the wild</label>
          <label className="row" style={{ gap: 5 }}><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Active</label>
        </div>
        <ErrorLine error={error} />
        <div className="row"><button className="btn primary" disabled={busy}>Save</button><button type="button" className="btn ghost" onClick={onDone}>Cancel</button></div>
      </div>
    </form>
  );
}

function DeliveriesView() {
  const { api } = useApp();
  const list = useLoad(() => api.deliveries());
  return (
    <section className="panel">
      <div className="table-scroll">
        <table className="data">
          <thead><tr><th>When</th><th>URL</th><th>Outcome</th><th className="r">Time</th></tr></thead>
          <tbody>
            {(list.data ?? []).map((d) => (
              <tr key={d.id}>
                <td className="nowrap faint">{ago(d.createdAt)}</td>
                <td className="mono" style={{ wordBreak: "break-all" }}>{d.url}</td>
                <td><b style={{ color: d.outcome === "delivered" ? "var(--clear)" : d.outcome === "skipped" ? "var(--ink-2)" : "var(--severe)" }}>{d.outcome}</b>{d.httpStatus ? <span className="faint"> HTTP {d.httpStatus}</span> : null}{d.error && <div className="faint" style={{ fontSize: 12 }}>{d.error}</div>}</td>
                <td className="r mono faint">{d.durationMs} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
        {list.data?.length === 0 && <div className="empty">No webhook deliveries yet.</div>}
      </div>
    </section>
  );
}
