// In-browser stand-in for the ASP.NET Core API, used by the GitHub Pages build. Same routes, status codes, error
// codes and response shapes; shared/contract/scenario.json runs against both. Mutating requests work on a copy of
// the state that is only kept if the handler succeeds.

import catalogData from "@shared/catalog.json";
import {
  type AffectedRange, best, cpeKey, dangerLevel, dangerScore, describe, hasBounds, identityKey, type MatchStatus, packageKey,
  severityRank,
} from "./matching";
import { type Advisory, absorb, apply, emptyVulnerability, fromGhsa, fromNvd, preferredId, rekey, type Vulnerability } from "./merge";
import { type Fetcher, Sources, type SourceConfig, DEFAULT_SOURCES, SourceError } from "./sources";

export interface Product {
  key: string; name: string; category: string; description: string;
  ghsa?: { ecosystem: string; package: string }; cpe?: { vendor: string; product: string };
}
export const catalog = catalogData as unknown as {
  version: number; severities: string[]; dangerLevels: { code: string; label: string; min: number }[];
  products: Product[]; sitePresets: { key: string; label: string; country: string; lat: number; lon: number }[];
};

interface User { id: string; username: string; displayName: string; passwordHash: string; createdAt: string }
interface Site { id: string; userId: string; name: string; kind: string; presetKey: string | null; lat: number; lon: number; createdAt: string }
interface Asset {
  id: string; userId: string; siteId: string; productKey: string | null; label: string; ecosystem: string | null; package: string | null;
  cpeVendor: string | null; cpeProduct: string | null; version: string; createdAt: string;
}
interface MatchRow {
  id: string; userId: string; assetId: string; vulnerabilityId: string; status: "affected" | "possible"; basis: Basis; explanation: string;
  fixedIn: string | null; score: number; firstSeen: string;
}
interface Subscription {
  id: string; userId: string; name: string; scope: string; scopeSiteId: string | null; scopeProductKey: string | null;
  minSeverity: string; kevOnly: boolean; minEpss: number; keyword: string | null; webhookUrl: string | null; active: boolean; createdAt: string;
}
interface NotificationRow {
  id: string; userId: string; subscriptionId: string; vulnerabilityId: string; assetId: string | null; reason: string;
  title: string; detail: string; createdAt: string; readAt: string | null;
}
interface Delivery {
  id: string; userId: string; subscriptionId: string; notificationId: string | null; url: string; outcome: string;
  httpStatus: number | null; error: string | null; durationMs: number; createdAt: string;
}
export interface IngestionRun {
  id: string; batchId: string; source: string; target: string; trigger: string; startedAt: string; finishedAt: string | null;
  fetched: number; created: number; updated: number; linked: number; merged: number; unchanged: number; error: string | null;
}
export interface IngestionSummary {
  batchId: string; startedAt: string; finishedAt: string; fetched: number; created: number; updated: number; linked: number;
  merged: number; kevMarked: number; epssScored: number; notifications: number; errors: string[];
}

export interface State {
  version: 1;
  users: User[];
  sites: Site[];
  assets: Asset[];
  vulns: Record<string, Vulnerability>;
  aliases: Record<string, string>;
  matches: MatchRow[];
  subscriptions: Subscription[];
  notifications: NotificationRow[];
  deliveries: Delivery[];
  runs: IngestionRun[];
  sync: Record<string, string>;
  sessions: Record<string, string>;
  last: IngestionSummary | null;
}

export const emptyState = (): State => ({
  version: 1, users: [], sites: [], assets: [], vulns: {}, aliases: {}, matches: [], subscriptions: [], notifications: [],
  deliveries: [], runs: [], sync: {}, sessions: {}, last: null,
});

export interface Response { status: number; body: any }
export type Progress = (p: { source: string; target: string; done: number; total: number }) => void;

class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}
const notFound = (what: string) => new ApiError(404, "not-found", `${what} not found`);
const invalid = (msg: string) => new ApiError(400, "validation", msg);
const conflict = (code: string, msg: string) => new ApiError(409, code, msg);

const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const uuid = () => crypto.randomUUID();
const SEVERITIES = ["none", "low", "medium", "high", "critical"];
const products = new Map(catalog.products.map((p) => [p.key, p]));

const assetKeys = (a: Asset) => {
  const keys: string[] = [];
  if (a.ecosystem && a.package) keys.push(packageKey(a.ecosystem, a.package));
  if (a.cpeVendor && a.cpeProduct) keys.push(cpeKey(a.cpeVendor, a.cpeProduct));
  return keys;
};

/** CVE ids upper case; GHSA ids keep a lower-case body. */
export const normalizeId = (raw: string) => {
  const t = raw.trim();
  return t.toLowerCase().startsWith("ghsa-") ? "GHSA-" + t.slice(5).toLowerCase() : t.toUpperCase();
};

/** Same rules as WebhookGuard.CheckSyntax. DNS can't be checked from a browser, and the browser build doesn't send. */
export function checkWebhook(url: string): string | null {
  let u: URL;
  try { u = new URL(url); } catch { return "Webhook URL must be an absolute http(s) URL"; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "Webhook URL must be an absolute http(s) URL";
  if (u.protocol === "http:") return "Webhook URL must use https";
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host === "::1" || host.startsWith("127.")) return "Webhook URL can't point at this server";
  const v4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)?.slice(1).map(Number);
  if (v4) {
    const [a, b, c] = v4;
    const priv = a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && c === 0))) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
    if (priv) return "Webhook URL can't point at a private or reserved address";
  }
  if (/^(fc|fd|fe8|fe9|fea|feb|ff)/.test(host) && host.includes(":")) return "Webhook URL can't point at a private or reserved address";
  return null;
}

/** Not a security boundary (the data never leaves this browser); it only avoids storing plain passwords. */
async function hashPassword(password: string, salt: string) {
  const data = new TextEncoder().encode(`${salt}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

type Handler = (c: { params: string[]; body: any; query: URLSearchParams; userId: string }) => Promise<any> | any;
interface Route { method: string; pattern: RegExp; auth: boolean; status?: number; handler: Handler; mutates: boolean }

export interface EngineOptions {
  fetcher: Fetcher;
  live: boolean;
  sources?: Partial<SourceConfig>;
  manualCooldownMinutes?: number;
  now?: () => Date;
}

export class Engine {
  state: State;
  running = false;
  onProgress: Progress | null = null;
  private routes: Route[] = [];
  private lastManual = 0;
  private now: () => Date;

  constructor(state: State, private options: EngineOptions) {
    this.state = state;
    this.now = options.now ?? (() => new Date());
    this.defineRoutes();
  }

  private iso() { return this.now().toISOString(); }

  async handle(method: string, url: string, body?: unknown, token?: string | null): Promise<Response> {
    const [path, qs] = url.split("?");
    const route = this.routes.find((r) => r.method === method && r.pattern.test(path));
    if (!route) return { status: 404, body: { status: 404, code: "not-found", detail: "No such route" } };
    const params = (path.match(route.pattern) ?? []).slice(1);
    let userId = "";
    if (route.auth) {
      const id = token ? this.state.sessions[token] : undefined;
      if (!id || !this.state.users.some((u) => u.id === id)) return { status: 401, body: null };
      userId = id;
    }
    const snapshot = route.mutates ? structuredClone(this.state) : null;
    try {
      const result = await route.handler({ params, body: body ?? null, query: new URLSearchParams(qs ?? ""), userId });
      const status = route.status ?? 200;
      return { status, body: status === 204 ? null : JSON.parse(JSON.stringify(result ?? null)) };
    } catch (e) {
      if (snapshot) this.state = snapshot;
      if (e instanceof ApiError) return { status: e.status, body: { status: e.status, detail: e.message, code: e.code } };
      throw e;
    }
  }

  private on(method: string, path: string, handler: Handler, opts: { status?: number; auth?: boolean; mutates?: boolean } = {}) {
    const pattern = new RegExp("^" + path.replace(/:\w+/g, "([^/]+)") + "$");
    this.routes.push({ method, pattern, handler, auth: opts.auth ?? true, status: opts.status, mutates: opts.mutates ?? method !== "GET" });
  }

  private defineRoutes() {
    this.on("POST", "/api/auth/register", (c) => this.register(c.body), { status: 201, auth: false });
    this.on("POST", "/api/auth/login", (c) => this.login(c.body), { auth: false });
    this.on("GET", "/api/me", (c) => this.me(c.userId));
    this.on("GET", "/api/catalog", () => catalog, { auth: false });

    this.on("GET", "/api/sites", (c) => this.mine(this.state.sites, c.userId).sort(byCreated).map(siteView));
    this.on("POST", "/api/sites", (c) => this.createSite(c.userId, c.body), { status: 201 });
    this.on("PUT", "/api/sites/:id", (c) => this.updateSite(c.userId, c.params[0], c.body));
    this.on("DELETE", "/api/sites/:id", (c) => this.deleteSite(c.userId, c.params[0]), { status: 204 });
    this.on("GET", "/api/assets", (c) => this.listAssets(c.userId, c.query.get("siteId")));
    this.on("POST", "/api/assets", (c) => this.createAsset(c.userId, c.body), { status: 201 });
    this.on("PUT", "/api/assets/:id", (c) => this.updateAsset(c.userId, c.params[0], c.body));
    this.on("DELETE", "/api/assets/:id", (c) => this.deleteAsset(c.userId, c.params[0]), { status: 204 });

    this.on("GET", "/api/exposure", (c) => this.exposure(c.userId, c.query.get("site")));
    this.on("GET", "/api/vulnerabilities", (c) => this.listVulns(c.userId, c.query));
    this.on("GET", "/api/vulnerabilities/:id", (c) => this.vulnDetail(c.userId, decodeURIComponent(c.params[0])));

    this.on("GET", "/api/subscriptions", (c) => this.mine(this.state.subscriptions, c.userId).sort(byCreated));
    this.on("POST", "/api/subscriptions", (c) => this.createSubscription(c.userId, c.body), { status: 201 });
    this.on("PUT", "/api/subscriptions/:id", (c) => this.updateSubscription(c.userId, c.params[0], c.body));
    this.on("DELETE", "/api/subscriptions/:id", (c) => this.deleteSubscription(c.userId, c.params[0]), { status: 204 });
    this.on("GET", "/api/subscriptions/:id/preview", (c) => this.preview(c.userId, c.params[0]));
    this.on("POST", "/api/subscriptions/:id/test", (c) => this.testWebhook(c.userId, c.params[0]));
    this.on("GET", "/api/notifications", (c) => this.notifications(c.userId, c.query));
    this.on("POST", "/api/notifications/read-all", (c) => this.readAll(c.userId));
    this.on("POST", "/api/notifications/:id/read", (c) => this.read(c.userId, c.params[0]), { status: 204 });
    this.on("GET", "/api/deliveries", (c) => this.mine(this.state.deliveries, c.userId).sort((a, b) => ordinal(b.createdAt, a.createdAt)).slice(0, 100).map(deliveryView));

    this.on("GET", "/api/ingestion/status", () => this.status());
    this.on("GET", "/api/ingestion/runs", (c) => [...this.state.runs].sort((a, b) => ordinal(b.startedAt, a.startedAt)).slice(0, Number(c.query.get("limit") ?? 100)));
    this.on("POST", "/api/ingestion/run", () => this.manualRun(), { mutates: false });
  }

  private mine<T extends { userId: string }>(rows: T[], userId: string) { return rows.filter((r) => r.userId === userId); }

  // ---------------------------------------------------------------- auth

  private async register(body: any) {
    const errors: string[] = [];
    const username = String(body?.username ?? "");
    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) errors.push("username must be 3-32 letters, digits or _");
    const displayName = String(body?.displayName ?? "").trim();
    if (!displayName || displayName.length > 60) errors.push("displayName must be 1-60 characters");
    const password = String(body?.password ?? "");
    if (password.length < 10 || password.length > 128) errors.push("password must be 10-128 characters");
    if (errors.length) throw invalid(errors.join("; "));
    if (this.state.users.some((u) => u.username.toLowerCase() === username.toLowerCase()))
      throw conflict("auth.username-taken", "That username is already registered");
    const salt = uuid();
    const user: User = { id: uuid(), username, displayName, passwordHash: `${salt}$${await hashPassword(password, salt)}`, createdAt: this.iso() };
    this.state.users.push(user);
    return this.session(user);
  }

  private async login(body: any) {
    const u = this.state.users.find((x) => x.username.toLowerCase() === String(body?.username ?? "").toLowerCase());
    const [salt, hash] = u ? u.passwordHash.split("$") : ["", ""];
    if (!u || (await hashPassword(String(body?.password ?? ""), salt)) !== hash)
      throw new ApiError(401, "auth.bad-credentials", "Username or password is wrong");
    return this.session(u);
  }

  private session(u: User) {
    const token = `local.${uuid()}`;
    this.state.sessions[token] = u.id;
    return { token, user: { id: u.id, username: u.username, displayName: u.displayName } };
  }

  private me(userId: string) {
    const u = this.state.users.find((x) => x.id === userId)!;
    return {
      user: { id: u.id, username: u.username, displayName: u.displayName },
      sites: this.mine(this.state.sites, userId).length,
      assets: this.mine(this.state.assets, userId).length,
      unread: this.state.notifications.filter((n) => n.userId === userId && !n.readAt).length,
    };
  }

  // ---------------------------------------------------------------- inventory

  private applySite(site: Site, body: any) {
    const name = String(body?.name ?? "").trim();
    if (!name || name.length > 80) throw invalid("name must be 1-80 characters");
    if (!["office", "datacenter", "cloud"].includes(body?.kind)) throw invalid("kind must be office, datacenter or cloud");
    site.name = name;
    site.kind = body.kind;
    if (body?.presetKey != null) {
      const p = catalog.sitePresets.find((x) => x.key === body.presetKey);
      if (!p) throw invalid(`Unknown location preset ${body.presetKey}`);
      site.presetKey = p.key; site.lat = p.lat; site.lon = p.lon;
    } else {
      const lat = body?.lat, lon = body?.lon;
      if (typeof lat !== "number" || typeof lon !== "number" || lat < -90 || lat > 90 || lon < -180 || lon > 180)
        throw invalid("Pick a location preset or give lat (-90..90) and lon (-180..180)");
      site.presetKey = null; site.lat = lat; site.lon = lon;
    }
  }

  private createSite(userId: string, body: any) {
    if (this.mine(this.state.sites, userId).length >= 200) throw conflict("site.limit", "Up to 200 sites per account");
    const site: Site = { id: uuid(), userId, name: "", kind: "office", presetKey: null, lat: 0, lon: 0, createdAt: this.iso() };
    this.applySite(site, body);
    this.state.sites.push(site);
    return siteView(site);
  }

  private ownSite(userId: string, id: string) {
    const s = this.state.sites.find((x) => x.id === id && x.userId === userId);
    if (!s) throw notFound("Site");
    return s;
  }

  private updateSite(userId: string, id: string, body: any) {
    const s = this.ownSite(userId, id);
    this.applySite(s, body);
    return siteView(s);
  }

  private deleteSite(userId: string, id: string) {
    this.ownSite(userId, id);
    if (this.state.subscriptions.some((s) => s.userId === userId && s.scopeSiteId === id))
      throw conflict("site.has-subscriptions", "Subscriptions are scoped to this site; change or delete them first");
    this.state.assets = this.state.assets.filter((a) => a.siteId !== id);
    this.state.sites = this.state.sites.filter((s) => s.id !== id);
    this.recompute(userId);
  }

  private applyAsset(asset: Asset, body: any, userId: string) {
    if (!body?.siteId || !this.state.sites.some((s) => s.id === body.siteId && s.userId === userId)) throw invalid("siteId must be one of your sites");
    const version = String(body?.version ?? "").trim();
    if (version.length > 40) throw invalid("version must be at most 40 characters");
    const label = String(body?.label ?? "").trim();
    if (body?.productKey != null) {
      const p = products.get(body.productKey);
      if (!p) throw invalid(`Unknown product ${body.productKey}`);
      asset.productKey = p.key;
      asset.ecosystem = p.ghsa?.ecosystem ?? null; asset.package = p.ghsa?.package ?? null;
      asset.cpeVendor = p.cpe?.vendor ?? null; asset.cpeProduct = p.cpe?.product ?? null;
      asset.label = label || p.name;
    } else {
      const has = (k: string) => typeof body?.[k] === "string" && body[k].trim() !== "";
      const hasPkg = has("ecosystem") && has("package");
      const hasCpe = has("cpeVendor") && has("cpeProduct");
      if (!hasPkg && !hasCpe) throw invalid("Pick a catalog product, or give ecosystem + package and/or CPE vendor + product");
      asset.productKey = null;
      asset.ecosystem = hasPkg ? body.ecosystem.trim().toLowerCase() : null;
      asset.package = hasPkg ? body.package.trim() : null;
      asset.cpeVendor = hasCpe ? body.cpeVendor.trim().toLowerCase() : null;
      asset.cpeProduct = hasCpe ? body.cpeProduct.trim().toLowerCase() : null;
      asset.label = label || (asset.package ?? asset.cpeProduct!);
    }
    if (asset.label.length > 80) throw invalid("label must be at most 80 characters");
    asset.siteId = body.siteId;
    asset.version = version;
  }

  private matchCounts(userId: string) {
    const out = new Map<string, { affected: number; possible: number; max: number }>();
    for (const m of this.state.matches) {
      if (m.userId !== userId) continue;
      const c = out.get(m.assetId) ?? { affected: 0, possible: 0, max: 0 };
      if (m.status === "affected") c.affected++; else c.possible++;
      c.max = Math.max(c.max, m.score);
      out.set(m.assetId, c);
    }
    return out;
  }

  private assetView(a: Asset, counts: Map<string, { affected: number; possible: number; max: number }>) {
    const c = counts.get(a.id) ?? { affected: 0, possible: 0, max: 0 };
    return {
      id: a.id, siteId: a.siteId, productKey: a.productKey, label: a.label, version: a.version, ecosystem: a.ecosystem,
      package: a.package, cpeVendor: a.cpeVendor, cpeProduct: a.cpeProduct, createdAt: a.createdAt,
      affected: c.affected, possible: c.possible, maxScore: c.max, level: dangerLevel(c.max),
    };
  }

  private listAssets(userId: string, siteId: string | null) {
    const counts = this.matchCounts(userId);
    return this.mine(this.state.assets, userId).filter((a) => !siteId || a.siteId === siteId).sort(byCreated).map((a) => this.assetView(a, counts));
  }

  private createAsset(userId: string, body: any) {
    if (this.mine(this.state.assets, userId).length >= 500) throw conflict("asset.limit", "Up to 500 assets per account");
    const asset: Asset = { id: uuid(), userId, siteId: "", productKey: null, label: "", ecosystem: null, package: null, cpeVendor: null, cpeProduct: null, version: "", createdAt: this.iso() };
    this.applyAsset(asset, body, userId);
    this.state.assets.push(asset);
    this.recompute(userId);
    return this.assetView(asset, this.matchCounts(userId));
  }

  private ownAsset(userId: string, id: string) {
    const a = this.state.assets.find((x) => x.id === id && x.userId === userId);
    if (!a) throw notFound("Asset");
    return a;
  }

  private updateAsset(userId: string, id: string, body: any) {
    const a = this.ownAsset(userId, id);
    this.applyAsset(a, body, userId);
    this.recompute(userId);
    return this.assetView(a, this.matchCounts(userId));
  }

  private deleteAsset(userId: string, id: string) {
    this.ownAsset(userId, id);
    this.state.assets = this.state.assets.filter((a) => a.id !== id);
    this.recompute(userId);
  }

  // ---------------------------------------------------------------- exposure

  static evaluateAsset(asset: Asset, v: Vulnerability): { status: MatchStatus; range: AffectedRange; explanation: string; basis: Basis } | null {
    if (v.withdrawn) return null;
    const keys = new Set(assetKeys(asset));
    const { status, range } = best(v.ranges.filter((r) => keys.has(identityKey(r))), asset.version);
    return status === "none" ? null : { status, range: range!, explanation: explain(asset, range!, status), basis: basisOf(asset, range!, status) };
  }

  /** Recomputes matches for one user or everyone; keeps FirstSeen, removes stale rows. */
  private recompute(userId: string | null) {
    const assets = this.state.assets.filter((a) => !userId || a.userId === userId);
    const byKey = new Map<string, Vulnerability[]>();
    for (const v of Object.values(this.state.vulns)) {
      if (v.withdrawn) continue;
      for (const key of new Set(v.ranges.map(identityKey))) {
        const list = byKey.get(key) ?? [];
        list.push(v);
        byKey.set(key, list);
      }
    }
    const existing = new Map(this.state.matches.filter((m) => !userId || m.userId === userId).map((m) => [`${m.assetId}|${m.vulnerabilityId}`, m]));
    const keep = new Set<string>();
    const now = this.iso();
    for (const asset of assets) {
      const seen = new Set<string>();
      for (const key of assetKeys(asset))
        for (const v of byKey.get(key) ?? []) {
          if (seen.has(v.id)) continue;
          seen.add(v.id);
          const found = Engine.evaluateAsset(asset, v);
          if (!found) continue;
          const pair = `${asset.id}|${v.id}`;
          keep.add(pair);
          const score = dangerScore(v.cvssScore, v.severity, v.kev, v.epss, found.status);
          const status = found.status === "affected" ? "affected" : "possible";
          const m = existing.get(pair);
          if (m) { m.status = status; m.basis = found.basis; m.explanation = found.explanation; m.fixedIn = found.range.fixed ?? null; m.score = score; }
          else this.state.matches.push({ id: uuid(), userId: asset.userId, assetId: asset.id, vulnerabilityId: v.id, status, basis: found.basis, explanation: found.explanation, fixedIn: found.range.fixed ?? null, score, firstSeen: now });
        }
    }
    this.state.matches = this.state.matches.filter((m) => (userId && m.userId !== userId) || keep.has(`${m.assetId}|${m.vulnerabilityId}`));
  }

  private exposure(userId: string, only: string | null = null) {
    const sites = this.mine(this.state.sites, userId);
    const assets = this.mine(this.state.assets, userId);
    const matches = this.mine(this.state.matches, userId);
    const assetById = new Map(assets.map((a) => [a.id, a]));
    const siteById = new Map(sites.map((s) => [s.id, s]));
    const groups = new Map<string, MatchRow[]>();
    for (const m of matches) if (!only || assetById.get(m.assetId)!.siteId === only) groups.set(m.vulnerabilityId, [...(groups.get(m.vulnerabilityId) ?? []), m]);
    const threats = [...groups.entries()].map(([id, grp]) => {
      const v = this.state.vulns[id];
      const score = Math.max(...grp.map((m) => m.score));
      return {
        id: v.id, title: v.title, severity: v.severity, cvss: v.cvssScore, kev: v.kev, kevAdded: v.kevAdded, epss: v.epss, score,
        level: dangerLevel(score),
        assets: [...grp].sort((a, b) => b.score - a.score).map((m) => {
          const a = assetById.get(m.assetId)!;
          return { assetId: m.assetId, label: a.label, version: a.version, siteId: a.siteId, site: siteById.get(a.siteId)!.name, status: m.status, basis: m.basis, explanation: m.explanation, fixedIn: m.fixedIn, score: m.score };
        }),
      };
    }).sort((a, b) => b.score - a.score || (b.epss ?? 0) - (a.epss ?? 0) || ordinal(a.id, b.id));

    const siteViews = [...sites].sort(byCreated).map((s) => {
      const here = matches.filter((m) => assetById.get(m.assetId)!.siteId === s.id);
      const score = here.length ? Math.max(...here.map((m) => m.score)) : 0;
      const top = [...here].sort((a, b) => b.score - a.score)[0];
      const distinct = (pred: (m: MatchRow) => boolean) => new Set(here.filter(pred).map((m) => m.vulnerabilityId)).size;
      return {
        id: s.id, name: s.name, kind: s.kind, lat: s.lat, lon: s.lon, score, level: dangerLevel(score),
        assets: assets.filter((a) => a.siteId === s.id).length,
        affected: distinct((m) => m.status === "affected"),
        possible: distinct((m) => m.status === "possible"),
        kev: distinct((m) => this.state.vulns[m.vulnerabilityId].kev),
        exploitPressure: here.length ? Math.max(...here.map((m) => (this.state.vulns[m.vulnerabilityId].kev ? 1 : 0) + (this.state.vulns[m.vulnerabilityId].epss ?? 0))) : 0,
        top: top ? { id: top.vulnerabilityId, title: this.state.vulns[top.vulnerabilityId].title, score: top.score } : null,
      };
    });
    const overall = siteViews.length ? Math.max(...siteViews.map((s) => s.score)) : 0;
    return {
      generatedAt: this.iso(), score: overall, level: dangerLevel(overall),
      totals: {
        sites: sites.length, assets: assets.length, vulnerabilities: threats.length,
        affected: threats.filter((t) => t.assets.some((a) => a.status === "affected")).length,
        kev: threats.filter((t) => t.kev).length,
        severe: threats.filter((t) => t.level === "severe").length,
      },
      sites: siteViews,
      threats: threats.slice(0, 100),
    };
  }

  private listVulns(userId: string, q: URLSearchParams) {
    const page = Math.max(Number(q.get("page") ?? 0), 0);
    const size = Math.min(Math.max(Number(q.get("size") ?? 50), 1), 200);
    let rows = Object.values(this.state.vulns).filter((v) => !v.withdrawn);
    const term = q.get("q")?.trim();
    if (term) {
      const aliasHit = this.state.aliases[normalizeId(term)];
      const lower = term.toLowerCase();
      rows = rows.filter((v) => v.id === aliasHit || v.title.toLowerCase().includes(lower) || v.description.toLowerCase().includes(lower));
    }
    const severity = q.get("severity");
    if (severity) { const allowed = severity.split(","); rows = rows.filter((v) => allowed.includes(v.severity)); }
    if (q.get("kev") === "true") rows = rows.filter((v) => v.kev);
    const minEpss = q.get("minEpss");
    if (minEpss) rows = rows.filter((v) => v.epss != null && v.epss >= Number(minEpss));
    const product = q.get("product");
    if (product) {
      const p = products.get(product);
      if (!p) throw invalid(`Unknown product ${product}`);
      const keys = productKeys(p).map((k) => `|${k}|`);
      rows = rows.filter((v) => keys.some((k) => v.identityIndex.includes(k)));
    }
    const mine = this.mine(this.state.matches, userId);
    if (q.get("matched") === "true") { const ids = new Set(mine.map((m) => m.vulnerabilityId)); rows = rows.filter((v) => ids.has(v.id)); }
    const nullsLast = <T,>(get: (v: Vulnerability) => T | null) => (a: Vulnerability, b: Vulnerability) => {
      const x = get(a), y = get(b);
      if (x == null || y == null) return x == null && y == null ? ordinal(b.id, a.id) : x == null ? 1 : -1;
      return x < y ? 1 : x > y ? -1 : ordinal(b.id, a.id);
    };
    const sort = q.get("sort");
    rows.sort(sort === "cvss" ? nullsLast((v) => v.cvssScore) : sort === "epss" ? nullsLast((v) => v.epss) : nullsLast((v) => v.published));
    const counts = new Map<string, number>();
    for (const m of mine) counts.set(m.vulnerabilityId, (counts.get(m.vulnerabilityId) ?? 0) + 1);
    return {
      items: rows.slice(page * size, page * size + size).map((v) => ({
        id: v.id, title: v.title, severity: v.severity, cvss: v.cvssScore, kev: v.kev, epss: v.epss, published: v.published,
        modified: v.modified, sources: v.sources, aliases: v.aliases, matched: counts.get(v.id) ?? 0,
      })),
      page, size, total: rows.length,
    };
  }

  private vulnDetail(userId: string, id: string) {
    const key = normalizeId(id);
    const v = this.state.vulns[this.state.aliases[key] ?? key];
    if (!v) throw notFound("Vulnerability");
    const matches = this.mine(this.state.matches, userId).filter((m) => m.vulnerabilityId === v.id).sort((a, b) => b.score - a.score);
    return {
      id: v.id, requested: key, redirected: key !== v.id, title: v.title, description: v.description, severity: v.severity,
      cvss: v.cvssScore, cvssVector: v.cvssVector, cvssSource: v.cvssSource, published: v.published, modified: v.modified,
      withdrawn: v.withdrawn, sources: v.sources, aliases: v.aliases, cwes: v.cwes,
      kev: v.kev ? { added: v.kevAdded, due: v.kevDue, ransomware: v.kevRansomware, action: v.kevAction } : null,
      epss: v.epss, epssPercentile: v.epssPercentile,
      ranges: v.ranges.map((r) => ({ source: r.source, identity: r.cpeVendor ? `${r.cpeVendor}:${r.cpeProduct}` : `${r.ecosystem}/${r.package}`, versions: describe(r), fixed: r.fixed ?? null })),
      references: v.references.slice(0, 40),
      matches: matches.map((m) => {
        const a = this.state.assets.find((x) => x.id === m.assetId)!;
        return { assetId: m.assetId, label: a.label, version: a.version, siteId: a.siteId, site: this.state.sites.find((s) => s.id === a.siteId)!.name, status: m.status, basis: m.basis, explanation: m.explanation, fixedIn: m.fixedIn, score: m.score, level: dangerLevel(m.score), firstSeen: m.firstSeen };
      }),
    };
  }

  // ---------------------------------------------------------------- alerts

  private applySubscription(s: Subscription, body: any, userId: string) {
    const name = String(body?.name ?? "").trim();
    if (!name || name.length > 80) throw invalid("name must be 1-80 characters");
    const scope = body?.scope ?? "all";
    if (!["all", "site", "product"].includes(scope)) throw invalid("scope must be all, site or product");
    s.scopeSiteId = null; s.scopeProductKey = null;
    if (scope === "site") {
      if (!this.state.sites.some((x) => x.id === body?.scopeSiteId && x.userId === userId)) throw invalid("scopeSiteId must be one of your sites");
      s.scopeSiteId = body.scopeSiteId;
    }
    if (scope === "product") {
      if (!products.has(body?.scopeProductKey)) throw invalid("scopeProductKey must be a catalog product");
      s.scopeProductKey = body.scopeProductKey;
    }
    const min = body?.minSeverity ?? "high";
    if (!SEVERITIES.includes(min)) throw invalid("minSeverity must be none, low, medium, high or critical");
    const epss = body?.minEpss ?? 0;
    if (typeof epss !== "number" || epss < 0 || epss > 1) throw invalid("minEpss must be between 0 and 1");
    const keyword = typeof body?.keyword === "string" && body.keyword.trim() ? body.keyword.trim() : null;
    if (keyword && keyword.length > 60) throw invalid("keyword must be at most 60 characters");
    const hook = typeof body?.webhookUrl === "string" && body.webhookUrl.trim() ? body.webhookUrl.trim() : null;
    if (hook) { const problem = checkWebhook(hook); if (problem) throw new ApiError(422, "webhook.rejected", problem); }
    Object.assign(s, { name, scope, minSeverity: min, kevOnly: !!body?.kevOnly, minEpss: epss, keyword, webhookUrl: hook, active: body?.active ?? true });
  }

  private createSubscription(userId: string, body: any) {
    if (this.mine(this.state.subscriptions, userId).length >= 50) throw conflict("subscription.limit", "Up to 50 subscriptions per account");
    const s: Subscription = { id: uuid(), userId, name: "", scope: "all", scopeSiteId: null, scopeProductKey: null, minSeverity: "high", kevOnly: false, minEpss: 0, keyword: null, webhookUrl: null, active: true, createdAt: this.iso() };
    this.applySubscription(s, body, userId);
    this.state.subscriptions.push(s);
    return s;
  }

  private ownSubscription(userId: string, id: string) {
    const s = this.state.subscriptions.find((x) => x.id === id && x.userId === userId);
    if (!s) throw notFound("Subscription");
    return s;
  }

  private updateSubscription(userId: string, id: string, body: any) {
    const s = this.ownSubscription(userId, id);
    this.applySubscription(s, body, userId);
    return s;
  }

  private deleteSubscription(userId: string, id: string) {
    this.ownSubscription(userId, id);
    this.state.subscriptions = this.state.subscriptions.filter((s) => s.id !== id);
  }

  private preview(userId: string, id: string) {
    const s = { ...this.ownSubscription(userId, id), active: true };
    const hits = this.mine(this.state.matches, userId).map((m) => {
      const asset = this.state.assets.find((a) => a.id === m.assetId)!;
      return { asset, site: this.state.sites.find((x) => x.id === asset.siteId)!, v: this.state.vulns[m.vulnerabilityId], basis: m.basis };
    }).filter((e) => passes(s, e.asset, e.v, e.basis));
    const sample: { id: string; title: string; asset: string; site: string }[] = [];
    for (const h of [...hits].sort((a, b) => severityRank(b.v.severity) - severityRank(a.v.severity) || ordinal(a.v.id, b.v.id)))
      if (!sample.some((x) => x.id === h.v.id) && sample.length < 5) sample.push({ id: h.v.id, title: h.v.title, asset: h.asset.label, site: h.site.name });
    return { matches: hits.length, vulnerabilities: new Set(hits.map((h) => h.v.id)).size, sample };
  }

  private testWebhook(userId: string, id: string) {
    const s = this.ownSubscription(userId, id);
    if (!s.webhookUrl) throw invalid("This subscription has no webhook");
    return deliveryView(this.recordSkippedDelivery(s, null));
  }

  /** The browser build can't send webhooks to arbitrary hosts (CORS); it logs what the API would have sent. */
  private recordSkippedDelivery(s: Subscription, notificationId: string | null): Delivery {
    const d: Delivery = {
      id: uuid(), userId: s.userId, subscriptionId: s.id, notificationId, url: s.webhookUrl!, outcome: "skipped", httpStatus: null,
      error: "Webhooks are sent by the API server; this browser build only records them", durationMs: 0, createdAt: this.iso(),
    };
    this.state.deliveries.push(d);
    return d;
  }

  private notifications(userId: string, q: URLSearchParams) {
    const page = Math.max(Number(q.get("page") ?? 0), 0);
    const size = Math.min(Math.max(Number(q.get("size") ?? 50), 1), 200);
    const unreadOnly = q.get("unread") === "true";
    const rows = this.mine(this.state.notifications, userId).filter((n) => !unreadOnly || !n.readAt)
      .sort((a, b) => ordinal(b.createdAt, a.createdAt) || ordinal(a.vulnerabilityId, b.vulnerabilityId));
    return {
      unread: this.state.notifications.filter((n) => n.userId === userId && !n.readAt).length,
      total: rows.length, page, size,
      items: rows.slice(page * size, page * size + size).map((n) => ({
        id: n.id, reason: n.reason, title: n.title, detail: n.detail, vulnerabilityId: n.vulnerabilityId, assetId: n.assetId,
        createdAt: n.createdAt, readAt: n.readAt,
        subscription: this.state.subscriptions.find((s) => s.id === n.subscriptionId)?.name ?? "(deleted)",
        severity: this.state.vulns[n.vulnerabilityId]?.severity ?? null, kev: this.state.vulns[n.vulnerabilityId]?.kev ?? false,
      })),
    };
  }

  private read(userId: string, id: string) {
    const n = this.state.notifications.find((x) => x.id === id && x.userId === userId);
    if (!n) throw notFound("Notification");
    n.readAt ??= this.iso();
  }

  private readAll(userId: string) {
    const now = this.iso();
    let marked = 0;
    for (const n of this.state.notifications) if (n.userId === userId && !n.readAt) { n.readAt = now; marked++; }
    return { marked };
  }

  // ---------------------------------------------------------------- ingestion

  private status() {
    const vulns = Object.values(this.state.vulns);
    const live = vulns.filter((v) => !v.withdrawn);
    const latest = [...this.state.runs].sort((a, b) => ordinal(b.startedAt, a.startedAt));
    const lastBatch = latest[0]?.batchId;
    const seen = new Set<string>();
    const targets = latest.filter((r) => { const k = `${r.source}|${r.target}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => ordinal(a.source, b.source) || ordinal(a.target, b.target))
      .map((r) => ({ source: r.source, target: r.target, startedAt: r.startedAt, finishedAt: r.finishedAt, fetched: r.fetched, created: r.created, updated: r.updated, linked: r.linked, merged: r.merged, unchanged: r.unchanged, error: r.error, current: r.batchId === lastBatch }));
    return {
      running: this.running, nextScheduled: null, last: this.state.last,
      totals: {
        vulnerabilities: live.length,
        nvdOnly: live.filter((v) => v.sources.join() === "nvd").length,
        ghsaOnly: live.filter((v) => v.sources.join() === "ghsa").length,
        both: live.filter((v) => v.sources.length === 2).length,
        kev: vulns.filter((v) => v.kev).length,
        withEpss: vulns.filter((v) => v.epss != null).length,
        aliases: Object.keys(this.state.aliases).length,
        withdrawn: vulns.filter((v) => v.withdrawn).length,
      },
      targets,
    };
  }

  private async manualRun() {
    if (this.running) throw conflict("ingestion.running", "A run is already in progress");
    const cooldown = (this.options.manualCooldownMinutes ?? 10) * 60_000;
    const since = Date.now() - this.lastManual;
    if (this.lastManual && since < cooldown) throw new ApiError(429, "ingestion.cooldown", `Manual runs are limited; try again in ${Math.ceil((cooldown - since) / 60_000)} min`);
    this.lastManual = Date.now();
    return this.ingest("manual");
  }

  /** One batch, as IngestionService.RunAsync: fetch, deduplicate, enrich, recompute exposure, notify. */
  async ingest(trigger: string): Promise<IngestionSummary> {
    this.running = true;
    try {
      const sources = new Sources(this.options.fetcher, { ...DEFAULT_SOURCES, ...this.options.sources }, this.options.live);
      const batchId = uuid();
      const startedAt = this.iso();
      const ctx: RunContext = { remap: new Map(), created: 0, updated: 0, linked: 0, merged: 0, errors: [] };
      let fetched = 0;
      const before = this.snapshot();
      const { cpes, packages } = this.watched();
      const total = cpes.length + packages.length + 2;
      let done = 0;

      for (const [vendor, product] of cpes) {
        const key = `nvd:${cpeKey(vendor, product)}`;
        const run = this.startRun(batchId, "nvd", `${vendor}:${product}`, trigger);
        this.onProgress?.({ source: "nvd", target: run.target, done: done++, total });
        try {
          const now = this.iso();
          for await (const cve of sources.nvd(vendor, product, this.state.sync[key] ?? null, now)) { run.fetched++; count(run, this.upsert(fromNvd(cve), ctx)); }
          this.state.sync[key] = now;
        } catch (e) {
          run.error = errorText(e);
          ctx.errors.push(`NVD ${vendor}:${product}: ${run.error}`);
        }
        fetched += run.fetched;
        run.finishedAt = this.iso();
      }
      for (const [ecosystem, pkg] of packages) {
        const key = `ghsa:${packageKey(ecosystem, pkg)}`;
        const run = this.startRun(batchId, "ghsa", `${ecosystem}/${pkg}`, trigger);
        this.onProgress?.({ source: "ghsa", target: run.target, done: done++, total });
        try {
          const now = this.iso();
          for await (const a of sources.ghsa(ecosystem, pkg, this.state.sync[key] ?? null)) { run.fetched++; count(run, this.upsert(fromGhsa(a), ctx)); }
          this.state.sync[key] = now;
        } catch (e) {
          run.error = errorText(e);
          ctx.errors.push(`GitHub ${ecosystem}/${pkg}: ${run.error}`);
        }
        fetched += run.fetched;
        run.finishedAt = this.iso();
      }

      this.onProgress?.({ source: "kev", target: "catalog", done: done++, total });
      const kevMarked = await this.enrichKev(sources, batchId, trigger, ctx);
      this.onProgress?.({ source: "epss", target: "scored CVEs", done: done++, total });
      const epssScored = await this.enrichEpss(sources, batchId, trigger, ctx);
      this.repoint(ctx);
      this.recompute(null);
      const notifications = this.notify(this.diff(before, ctx));
      const summary: IngestionSummary = {
        batchId, startedAt, finishedAt: this.iso(), fetched, created: ctx.created, updated: ctx.updated, linked: ctx.linked,
        merged: ctx.merged, kevMarked, epssScored, notifications, errors: ctx.errors,
      };
      this.state.last = summary;
      this.state.runs = this.state.runs.slice(-600);
      this.onProgress?.({ source: "done", target: "", done: total, total });
      return summary;
    } finally {
      this.running = false;
    }
  }

  private watched() {
    const cpes = new Map<string, [string, string]>();
    const packages = new Map<string, [string, string]>();
    for (const p of catalog.products) {
      if (p.cpe) cpes.set(`${p.cpe.vendor}|${p.cpe.product}`, [p.cpe.vendor, p.cpe.product]);
      if (p.ghsa) packages.set(`${p.ghsa.ecosystem}|${p.ghsa.package}`, [p.ghsa.ecosystem, p.ghsa.package]);
    }
    for (const a of this.state.assets) {
      if (a.productKey) continue;
      if (a.cpeVendor && a.cpeProduct) cpes.set(`${a.cpeVendor}|${a.cpeProduct}`, [a.cpeVendor, a.cpeProduct]);
      if (a.ecosystem && a.package) packages.set(`${a.ecosystem}|${a.package}`, [a.ecosystem, a.package]);
    }
    const sortPairs = (m: Map<string, [string, string]>) => [...m.values()].sort((x, y) => ordinal(x[0], y[0]) || ordinal(x[1], y[1]));
    return { cpes: sortPairs(cpes), packages: sortPairs(packages) };
  }

  private startRun(batchId: string, source: string, target: string, trigger: string): IngestionRun {
    const run: IngestionRun = { id: uuid(), batchId, source, target, trigger, startedAt: this.iso(), finishedAt: null, fetched: 0, created: 0, updated: 0, linked: 0, merged: 0, unchanged: 0, error: null };
    this.state.runs.push(run);
    return run;
  }

  private upsert(a: Advisory, ctx: RunContext): Outcome {
    const now = this.iso();
    const hitIds = [...new Set(a.aliases.map((x) => this.state.aliases[x]).filter((x): x is string => !!x))];
    let v: Vulnerability;
    let outcome: Outcome = "unchanged";
    if (hitIds.length === 0) {
      v = emptyVulnerability(preferredId(a.aliases), now);
      this.state.vulns[v.id] = v;
      outcome = "created";
      ctx.created++;
    } else {
      const hits = hitIds.map((id) => this.state.vulns[id]).sort((x, y) => (x.id.startsWith("CVE-") ? 0 : 1) - (y.id.startsWith("CVE-") ? 0 : 1) || ordinal(x.id, y.id));
      v = hits[0];
      for (const other of hits.slice(1)) {
        absorb(v, other);
        this.retire(other, v, ctx);
        outcome = "merged";
        ctx.merged++;
      }
    }
    const linked = outcome === "unchanged" && !v.sources.includes(a.source);
    const changed = apply(v, a, now);
    const preferred = preferredId(v.aliases);
    if (preferred !== v.id) {
      const moved = rekey(v, preferred);
      this.state.vulns[preferred] = moved;
      this.retire(v, moved, ctx);
      v = moved;
      if (outcome !== "created") { outcome = "merged"; ctx.merged++; }
    }
    for (const alias of v.aliases) this.state.aliases[alias] = v.id;
    if (outcome === "unchanged" && linked) { outcome = "linked"; ctx.linked++; }
    else if (outcome === "unchanged" && changed) { outcome = "updated"; ctx.updated++; }
    return outcome;
  }

  private retire(old: Vulnerability, into: Vulnerability, ctx: RunContext) {
    ctx.remap.set(old.id, into.id);
    for (const alias of old.aliases) this.state.aliases[alias] = into.id;
    if (old.id !== into.id) delete this.state.vulns[old.id];
  }

  private async enrichKev(sources: Sources, batchId: string, trigger: string, ctx: RunContext) {
    const run = this.startRun(batchId, "kev", "catalog", trigger);
    let marked = 0;
    try {
      const entries = await sources.kev();
      run.fetched = entries.length;
      const listed = new Set<string>();
      for (const e of entries) {
        const id = this.state.aliases[e.cve];
        if (!id) continue;
        const v = this.state.vulns[id];
        listed.add(v.id);
        const changed = !v.kev || v.kevAdded !== e.added || v.kevDue !== e.due || v.kevRansomware !== e.ransomware;
        Object.assign(v, { kev: true, kevAdded: e.added, kevDue: e.due, kevRansomware: e.ransomware, kevAction: e.action });
        if (changed) { run.updated++; marked++; } else run.unchanged++;
      }
      for (const v of Object.values(this.state.vulns))
        if (v.kev && !listed.has(v.id)) { Object.assign(v, { kev: false, kevAdded: null, kevDue: null, kevRansomware: false, kevAction: null }); run.updated++; }
    } catch (e) {
      run.error = errorText(e);
      ctx.errors.push(`KEV: ${run.error}`);
    }
    run.finishedAt = this.iso();
    return marked;
  }

  private async enrichEpss(sources: Sources, batchId: string, trigger: string, ctx: RunContext) {
    const run = this.startRun(batchId, "epss", "scored CVEs", trigger);
    let scored = 0;
    try {
      const cves = Object.keys(this.state.vulns).filter((id) => id.startsWith("CVE-")).sort(ordinal);
      const scores = await sources.epss(cves);
      run.fetched = scores.size;
      for (const [cve, s] of scores) {
        const v = this.state.vulns[cve];
        if (!v) continue;
        if (v.epss === s.epss && v.epssPercentile === s.percentile) { run.unchanged++; continue; }
        v.epss = s.epss; v.epssPercentile = s.percentile;
        run.updated++; scored++;
      }
    } catch (e) {
      run.error = errorText(e);
      ctx.errors.push(`EPSS: ${run.error}`);
    }
    run.finishedAt = this.iso();
    return scored;
  }

  private resolve(id: string, ctx: RunContext) {
    while (ctx.remap.has(id)) id = ctx.remap.get(id)!;
    return id;
  }

  /** Notifications on retired records move to their successor; duplicates collapse. */
  private repoint(ctx: RunContext) {
    if (ctx.remap.size === 0) return;
    const seen = new Set(this.state.notifications.filter((n) => !ctx.remap.has(n.vulnerabilityId)).map((n) => `${n.subscriptionId}|${n.vulnerabilityId}|${n.reason}`));
    this.state.notifications = this.state.notifications.filter((n) => {
      if (!ctx.remap.has(n.vulnerabilityId)) return true;
      const to = this.resolve(n.vulnerabilityId, ctx);
      const key = `${n.subscriptionId}|${to}|${n.reason}`;
      if (seen.has(key)) return false;
      seen.add(key);
      n.vulnerabilityId = to;
      return true;
    });
    this.state.matches = this.state.matches.filter((m) => !ctx.remap.has(m.vulnerabilityId));
  }

  private snapshot() {
    const pairs = new Set(this.state.matches.map((m) => `${m.assetId}|${m.vulnerabilityId}`));
    const state = new Map<string, { kev: boolean; severity: string }>();
    for (const m of this.state.matches) {
      const v = this.state.vulns[m.vulnerabilityId];
      if (v) state.set(v.id, { kev: v.kev, severity: v.severity });
    }
    return { pairs, state };
  }

  private diff(before: ReturnType<Engine["snapshot"]>, ctx: RunContext): ExposureEvent[] {
    const pairsBefore = new Set([...before.pairs].map((p) => { const [a, v] = p.split("|"); return `${a}|${this.resolve(v, ctx)}`; }));
    const stateBefore = new Map<string, { kev: boolean; severity: string }>();
    for (const [id, s] of before.state) {
      const to = this.resolve(id, ctx);
      const prev = stateBefore.get(to);
      stateBefore.set(to, prev ? { kev: prev.kev || s.kev, severity: severityRank(prev.severity) >= severityRank(s.severity) ? prev.severity : s.severity } : s);
    }
    const events: ExposureEvent[] = [];
    for (const m of [...this.state.matches].sort((a, b) => ordinal(a.vulnerabilityId, b.vulnerabilityId))) {
      const asset = this.state.assets.find((a) => a.id === m.assetId);
      const site = asset && this.state.sites.find((s) => s.id === asset.siteId);
      if (!asset || !site) continue;
      const v = this.state.vulns[m.vulnerabilityId];
      if (!pairsBefore.has(`${m.assetId}|${m.vulnerabilityId}`)) { events.push({ reason: "new_exposure", userId: m.userId, asset, site, v, basis: m.basis }); continue; }
      const was = stateBefore.get(v.id);
      if (!was) continue;
      if (v.kev && !was.kev) events.push({ reason: "kev_added", userId: m.userId, asset, site, v, basis: m.basis });
      if (severityRank(v.severity) > severityRank(was.severity)) events.push({ reason: "severity_raised", userId: m.userId, asset, site, v, basis: m.basis });
    }
    return events;
  }

  private notify(events: ExposureEvent[]) {
    if (events.length === 0) return 0;
    const now = this.iso();
    const seen = new Set(this.state.notifications.map((n) => `${n.subscriptionId}|${n.vulnerabilityId}|${n.reason}`));
    const created: { sub: Subscription; n: NotificationRow }[] = [];
    for (const e of events)
      for (const s of this.state.subscriptions.filter((x) => x.userId === e.userId && x.active && passes(x, e.asset, e.v, e.basis))) {
        const key = `${s.id}|${e.v.id}|${e.reason}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const { title, detail } = describeEvent(e);
        const n: NotificationRow = { id: uuid(), userId: e.userId, subscriptionId: s.id, vulnerabilityId: e.v.id, assetId: e.asset.id, reason: e.reason, title, detail, createdAt: now, readAt: null };
        this.state.notifications.push(n);
        created.push({ sub: s, n });
      }
    const hooked = new Map<string, { sub: Subscription; n: NotificationRow }>();
    for (const c of created) if (c.sub.webhookUrl && !hooked.has(c.sub.id)) hooked.set(c.sub.id, c);
    for (const c of hooked.values()) this.recordSkippedDelivery(c.sub, c.n.id);
    return created.length;
  }

  /** Loads a snapshot written by `dotnet run -- snapshot` as one ingestion batch, so it notifies like any other. */
  importSnapshot(snapshot: any) {
    const before = this.snapshot();
    const ctx: RunContext = { remap: new Map(), created: 0, updated: 0, linked: 0, merged: 0, errors: [] };
    const now = this.iso();
    for (const raw of snapshot.vulnerabilities) {
      const v: Vulnerability = {
        ...emptyVulnerability(raw.id, now), ...raw, cvssScore: raw.cvss ?? null,
        published: raw.published ? new Date(raw.published).toISOString() : null, modified: raw.modified ? new Date(raw.modified).toISOString() : null,
        references: raw.references ?? [], ingestedAt: now, updatedAt: now,
      };
      delete (v as any).cvss;
      v.identityIndex = "|" + [...new Set(v.ranges.map(identityKey))].sort(ordinal).map((k) => k + "|").join("");
      this.state.vulns[v.id] = v;
      for (const a of v.aliases) this.state.aliases[a] = v.id;
      ctx.created++;
    }
    const batchId = uuid();
    for (const r of snapshot.runs ?? [])
      this.state.runs.push({ id: uuid(), batchId, source: r.source, target: r.target, trigger: "snapshot", startedAt: snapshot.generatedAt, finishedAt: snapshot.generatedAt, fetched: r.fetched, created: r.created, updated: r.updated, linked: r.linked ?? 0, merged: r.merged, unchanged: 0, error: r.error ?? null });
    const at = new Date(snapshot.generatedAt).toISOString();
    for (const p of catalog.products) {
      if (p.cpe) this.state.sync[`nvd:${cpeKey(p.cpe.vendor, p.cpe.product)}`] = at;
      if (p.ghsa) this.state.sync[`ghsa:${packageKey(p.ghsa.ecosystem, p.ghsa.package)}`] = at;
    }
    this.recompute(null);
    const notifications = this.notify(this.diff(before, ctx));
    this.state.last = { ...snapshot.summary, batchId, notifications, errors: [] };
  }
}

type Outcome = "created" | "updated" | "linked" | "merged" | "unchanged";
interface RunContext { remap: Map<string, string>; created: number; updated: number; linked: number; merged: number; errors: string[] }
interface ExposureEvent { reason: string; userId: string; asset: Asset; site: Site; v: Vulnerability; basis: Basis }

/** What a verdict rests on; only "range" and "no-version" raise alerts. Mirrors Match.Basis in the API. */
type Basis = "range" | "no-version" | "no-bounds" | "incomparable";
const basisOf = (asset: Asset, r: AffectedRange, status: MatchStatus): Basis =>
  status === "affected" ? "range" : r.exact == null && !hasBounds(r) ? "no-bounds" : !asset.version ? "no-version" : "incomparable";

function count(run: IngestionRun, o: Outcome) {
  if (o === "created") run.created++;
  else if (o === "updated") run.updated++;
  else if (o === "linked") run.linked++;
  else if (o === "merged") run.merged++;
  else run.unchanged++;
}

const errorText = (e: unknown) => (e instanceof SourceError ? e.message : e instanceof TypeError ? "Network error (offline or blocked)" : String(e));

const byCreated = (a: { createdAt: string }, b: { createdAt: string }) => ordinal(a.createdAt, b.createdAt);

const siteView = (s: Site) => ({ id: s.id, name: s.name, kind: s.kind, presetKey: s.presetKey, lat: s.lat, lon: s.lon, createdAt: s.createdAt });

const deliveryView = (d: Delivery) => ({ id: d.id, subscriptionId: d.subscriptionId, notificationId: d.notificationId, url: d.url, outcome: d.outcome, httpStatus: d.httpStatus, error: d.error, durationMs: d.durationMs, createdAt: d.createdAt });

export const productKeys = (p: Product) => {
  const keys: string[] = [];
  if (p.ghsa) keys.push(packageKey(p.ghsa.ecosystem, p.ghsa.package));
  if (p.cpe) keys.push(cpeKey(p.cpe.vendor, p.cpe.product));
  return keys;
};

function explain(asset: Asset, r: AffectedRange, status: MatchStatus) {
  const who = r.source === "nvd" ? `NVD cpe ${r.cpeVendor}:${r.cpeProduct}` : `GitHub ${r.ecosystem}/${r.package}`;
  if (!hasBounds(r) && r.exact == null) return `${who} names the product without version bounds`;
  if (status === "possible" && !asset.version) return `Version unknown; ${who} lists ${describe(r)}`;
  if (status === "possible") return `${asset.version} can't be compared with ${describe(r)} (${who})`;
  return `${asset.version} is in ${describe(r)} (${who})`;
}

function passes(s: Subscription, asset: Asset, v: Vulnerability, basis: Basis) {
  if (!s.active) return false;
  // a source that lists no versions, or versions in another scheme, says nothing about this install
  if (basis === "no-bounds" || basis === "incomparable") return false;
  if (s.scope === "site" && s.scopeSiteId !== asset.siteId) return false;
  if (s.scope === "product" && s.scopeProductKey !== asset.productKey) return false;
  if (severityRank(v.severity) < severityRank(s.minSeverity)) return false;
  if (s.kevOnly && !v.kev) return false;
  if ((v.epss ?? 0) < s.minEpss) return false;
  if (s.keyword) {
    const k = s.keyword.toLowerCase();
    if (!v.title.toLowerCase().includes(k) && !v.description.toLowerCase().includes(k) && !v.id.toLowerCase().includes(k)) return false;
  }
  return true;
}

function describeEvent(e: ExposureEvent) {
  const where = `${e.asset.label} at ${e.site.name}`;
  if (e.reason === "kev_added")
    return { title: `${e.v.id} is being exploited in the wild`, detail: `CISA added it to KEV${e.v.kevAdded ? ` on ${e.v.kevAdded}` : ""}. It reaches ${where}.${e.v.kevDue ? ` Federal due date ${e.v.kevDue}.` : ""}` };
  if (e.reason === "severity_raised") return { title: `${e.v.id} is now ${e.v.severity}`, detail: `${e.v.title} · reaches ${where}` };
  return { title: `${e.v.id} reaches ${where}`, detail: e.v.title };
}
