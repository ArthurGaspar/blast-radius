// Port of BlastRadius.Api/Ingestion/Sources.cs. The browser calls the same public APIs directly: NVD, the GitHub
// Advisory Database, the cisagov/kev-data mirror and FIRST EPSS all send CORS headers.

export interface SourceConfig {
  nvdBaseUrl: string;
  nvdApiKey?: string;
  githubBaseUrl: string;
  githubToken?: string;
  kevUrl: string;
  epssBaseUrl: string;
}

export const DEFAULT_SOURCES: SourceConfig = {
  nvdBaseUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  githubBaseUrl: "https://api.github.com",
  kevUrl: "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
  epssBaseUrl: "https://api.first.org/data/v1/epss",
};

export interface Fetched { status: number; json: any; link: string | null; retryAfter: number | null }

/** Fetches JSON. Live in the browser; recorded fixtures in tests. */
export type Fetcher = (url: string, headers?: Record<string, string>) => Promise<Fetched>;

export const liveFetcher: Fetcher = async (url, headers) => {
  const res = await fetch(url, { headers });
  const retry = Number(res.headers.get("Retry-After"));
  return {
    status: res.status,
    json: res.ok ? await res.json() : null,
    link: res.headers.get("Link"),
    retryAfter: Number.isFinite(retry) && retry > 0 ? retry : null,
  };
};

/** Same file layout as FixtureHandler.cs: nvd/<vendor>_<product>.json, ghsa/<eco>/<pkg>.json, kev.json, epss.json. */
export function fixtureFetcher(load: (path: string) => any | undefined): Fetcher {
  return async (url) => {
    const u = new URL(url);
    const q = u.searchParams;
    const ok = (json: any): Fetched => ({ status: 200, json, link: null, retryAfter: null });
    if (u.hostname.includes("nvd.nist.gov")) {
      const parts = (q.get("virtualMatchString") ?? "").split(":");
      return ok(load(`nvd/${parts[3]}_${parts[4]}.json`) ?? { resultsPerPage: 0, startIndex: 0, totalResults: 0, vulnerabilities: [] });
    }
    if (u.pathname.endsWith("/advisories")) {
      return ok(load(`ghsa/${q.get("ecosystem")}/${(q.get("affects") ?? "").replaceAll("/", "_")}.json`) ?? []);
    }
    if (u.pathname.endsWith("known_exploited_vulnerabilities.json")) return ok(load("kev.json") ?? { vulnerabilities: [] });
    if (u.hostname.includes("first.org")) {
      const wanted = new Set((q.get("cve") ?? "").split(","));
      const all = load("epss.json")?.data ?? [];
      return ok({ data: all.filter((r: any) => wanted.has(r.cve)) });
    }
    return { status: 404, json: null, link: null, retryAfter: null };
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class SourceError extends Error {}

export class Sources {
  private lastNvd = 0;

  constructor(private fetcher: Fetcher, private config: SourceConfig, private live: boolean) {}

  /** NVD allows 5 requests per 30 s without a key (50 with one), counted across all queries. */
  private get nvdGapMs() {
    return !this.live ? 0 : this.config.nvdApiKey ? 700 : 6500;
  }

  private async nvdRequest(url: string): Promise<Fetched> {
    for (let attempt = 1; ; attempt++) {
      const wait = this.lastNvd + this.nvdGapMs - Date.now();
      if (wait > 0) await sleep(wait);
      const res = await this.fetcher(url, this.config.nvdApiKey ? { apiKey: this.config.nvdApiKey } : undefined);
      this.lastNvd = Date.now();
      if (![403, 429, 503].includes(res.status) || attempt === 4) return res;
      this.lastNvd = Date.now() + (res.retryAfter ?? 10 * attempt) * 1000;
    }
  }

  async *nvd(vendor: string, product: string, since: string | null, now: string): AsyncGenerator<any> {
    let start = 0;
    for (;;) {
      let url = `${this.config.nvdBaseUrl}?virtualMatchString=cpe:2.3:a:${encodeURIComponent(vendor)}:${encodeURIComponent(product)}&resultsPerPage=2000&startIndex=${start}`;
      if (since && Date.parse(now) - Date.parse(since) < 119 * 86_400_000)
        url += `&lastModStartDate=${since}&lastModEndDate=${now}`;
      const res = await this.nvdRequest(url);
      if (res.status !== 200) throw new SourceError(`HTTP ${res.status}`);
      const vulns: any[] = res.json.vulnerabilities ?? [];
      for (const v of vulns) yield v.cve;
      start += vulns.length;
      if (vulns.length === 0 || start >= res.json.totalResults) return;
    }
  }

  /** since: only advisories published or updated since then (GitHub filters by day; one day of overlap is kept). */
  async *ghsa(ecosystem: string, pkg: string, since: string | null): AsyncGenerator<any> {
    let url: string | null = `${this.config.githubBaseUrl}/advisories?ecosystem=${encodeURIComponent(ecosystem)}&affects=${encodeURIComponent(pkg)}&per_page=100`;
    if (since) url += "&modified=" + encodeURIComponent(">=" + new Date(Date.parse(since) - 86_400_000).toISOString().slice(0, 10));
    const headers: Record<string, string> = { Accept: "application/vnd.github+json" };
    if (this.config.githubToken) headers.Authorization = `Bearer ${this.config.githubToken}`;
    while (url) {
      const res = await this.fetcher(url, headers);
      if (res.status !== 200) throw new SourceError(res.status === 403 || res.status === 429 ? "GitHub rate limit reached (60 requests/hour without a token)" : `HTTP ${res.status}`);
      for (const a of res.json) yield a;
      url = nextLink(res.link);
    }
  }

  async kev(): Promise<{ cve: string; added: string | null; due: string | null; ransomware: boolean; action: string | null }[]> {
    const res = await this.fetcher(this.config.kevUrl);
    if (res.status !== 200) throw new SourceError(`HTTP ${res.status}`);
    return (res.json.vulnerabilities ?? []).map((v: any) => ({
      cve: v.cveID, added: v.dateAdded ?? null, due: v.dueDate ?? null,
      ransomware: v.knownRansomwareCampaignUse === "Known", action: v.requiredAction ?? null,
    }));
  }

  async epss(cves: string[]): Promise<Map<string, { epss: number; percentile: number }>> {
    const out = new Map<string, { epss: number; percentile: number }>();
    for (let i = 0; i < cves.length; i += 100) {
      const chunk = cves.slice(i, i + 100);
      const res = await this.fetcher(`${this.config.epssBaseUrl}?cve=${chunk.join(",")}&limit=100`);
      if (res.status !== 200) throw new SourceError(`HTTP ${res.status}`);
      for (const row of res.json.data ?? []) out.set(row.cve, { epss: Number(row.epss), percentile: Number(row.percentile) });
    }
    return out;
  }
}

function nextLink(link: string | null): string | null {
  if (!link) return null;
  for (const part of link.split(",")) {
    const [url, rel] = part.split(";");
    if (rel?.trim() === 'rel="next"') return url.trim().replace(/^<|>$/g, "");
  }
  return null;
}
