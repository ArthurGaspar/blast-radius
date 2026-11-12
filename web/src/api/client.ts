import { Engine, emptyState, type Progress, type State } from "../engine/engine";
import { liveFetcher } from "../engine/sources";
import { seedDemo } from "./demo";
export { DEMO } from "./demo";
import type {
  Asset, Delivery, Exposure, Inbox, IngestionStatus, IngestionSummary, Me, Page, Preview, Site, Subscription, UserView, VulnDetail, VulnRow,
} from "./types";

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

interface Raw { status: number; body: any }

export interface Transport {
  readonly mode: "browser" | "api";
  send(method: string, path: string, body: unknown, token: string | null): Promise<Raw>;
}

export class HttpTransport implements Transport {
  readonly mode = "api" as const;
  constructor(readonly base: string) {}
  async send(method: string, path: string, body: unknown, token: string | null): Promise<Raw> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      const res = await fetch(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null };
    } catch {
      return { status: 0, body: { code: "network", detail: `Can't reach the API at ${this.base}` } };
    }
  }
}

// ------------------------------------------------------------------ browser build


const DB = "blast-radius";
const STORE = "state";
const KEY = "v2"; // bump when the demo inventory changes

function idb<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T | undefined> {
  return new Promise((resolve) => {
    let open: IDBOpenDBRequest;
    try { open = indexedDB.open(DB, 1); } catch { resolve(undefined); return; }
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => resolve(undefined);
    open.onsuccess = () => {
      const tx = open.result.transaction(STORE, mode);
      const req = run(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(undefined);
      tx.oncomplete = () => open.result.close();
    };
  });
}

/** The engine in this tab. State lives in IndexedDB (it outgrows localStorage); first visit seeds from the snapshot. */
export class BrowserTransport implements Transport {
  readonly mode = "browser" as const;
  private constructor(readonly engine: Engine, readonly snapshotAt: string | null) {}

  static async open(onStatus: (text: string) => void): Promise<BrowserTransport> {
    const saved = await idb<State>("readonly", (s) => s.get(KEY));
    const engine = new Engine(saved ?? emptyState(), { fetcher: liveFetcher, live: true, manualCooldownMinutes: 10 });
    if (!saved) {
      onStatus("Loading the vulnerability snapshot…");
      const snapshot = await (await fetch(`${import.meta.env.BASE_URL}data/snapshot.json`)).json();
      onStatus("Setting up the demo inventory…");
      await seedDemo(engine, snapshot);
      engine.importSnapshot(snapshot);
      await idb("readwrite", (s) => s.put(engine.state, KEY));
    }
    return new BrowserTransport(engine, engine.state.last?.finishedAt ?? null);
  }

  async send(method: string, path: string, body: unknown, token: string | null): Promise<Raw> {
    const res = await this.engine.handle(method, path, body, token);
    if (method !== "GET") await idb("readwrite", (s) => s.put(this.engine.state, KEY));
    return res;
  }

  set onProgress(fn: Progress | null) { this.engine.onProgress = fn; }

  async reset() { await idb("readwrite", (s) => s.delete(KEY)); }
}

// ------------------------------------------------------------------ typed calls

export class Api {
  constructor(readonly transport: Transport, private token: () => string | null, private onUnauthorized: () => void) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.transport.send(method, path, body, this.token());
    if (res.status === 401 && this.token()) this.onUnauthorized();
    if (res.status === 0 || res.status >= 400) throw new ApiError(res.status, res.body?.code ?? "error", res.body?.detail ?? `Request failed (${res.status})`);
    return res.body as T;
  }

  register = (username: string, displayName: string, password: string) => this.call<{ token: string; user: UserView }>("POST", "/api/auth/register", { username, displayName, password });
  login = (username: string, password: string) => this.call<{ token: string; user: UserView }>("POST", "/api/auth/login", { username, password });
  me = () => this.call<Me>("GET", "/api/me");

  sites = () => this.call<Site[]>("GET", "/api/sites");
  saveSite = (id: string | null, body: Partial<Site>) => this.call<Site>(id ? "PUT" : "POST", id ? `/api/sites/${id}` : "/api/sites", body);
  deleteSite = (id: string) => this.call<void>("DELETE", `/api/sites/${id}`);
  assets = () => this.call<Asset[]>("GET", "/api/assets");
  saveAsset = (id: string | null, body: Record<string, unknown>) => this.call<Asset>(id ? "PUT" : "POST", id ? `/api/assets/${id}` : "/api/assets", body);
  deleteAsset = (id: string) => this.call<void>("DELETE", `/api/assets/${id}`);

  exposure = (site?: string) => this.call<Exposure>("GET", site ? `/api/exposure?site=${site}` : "/api/exposure");
  vulnerabilities = (q: Record<string, string | number | boolean | undefined>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== "" && v !== false) p.set(k, String(v));
    return this.call<Page<VulnRow>>("GET", `/api/vulnerabilities?${p}`);
  };
  vulnerability = (id: string) => this.call<VulnDetail>("GET", `/api/vulnerabilities/${encodeURIComponent(id)}`);

  subscriptions = () => this.call<Subscription[]>("GET", "/api/subscriptions");
  saveSubscription = (id: string | null, body: Record<string, unknown>) => this.call<Subscription>(id ? "PUT" : "POST", id ? `/api/subscriptions/${id}` : "/api/subscriptions", body);
  deleteSubscription = (id: string) => this.call<void>("DELETE", `/api/subscriptions/${id}`);
  preview = (id: string) => this.call<Preview>("GET", `/api/subscriptions/${id}/preview`);
  testWebhook = (id: string) => this.call<Delivery>("POST", `/api/subscriptions/${id}/test`);
  notifications = (unread: boolean, page = 0) => this.call<Inbox>("GET", `/api/notifications?unread=${unread}&page=${page}&size=50`);
  read = (id: string) => this.call<void>("POST", `/api/notifications/${id}/read`);
  readAll = () => this.call<{ marked: number }>("POST", "/api/notifications/read-all");
  deliveries = () => this.call<Delivery[]>("GET", "/api/deliveries");

  ingestionStatus = () => this.call<IngestionStatus>("GET", "/api/ingestion/status");
  runIngestion = () => this.call<IngestionSummary>("POST", "/api/ingestion/run?wait=true");
}
