// Port of BlastRadius.Api/Ingestion (Advisory, Normalize, Merge). Same rules:
//  - identity: the CVE when any source names one, else the GHSA id; every identifier becomes an alias
//  - title: GitHub's summary, else the first sentence of the description
//  - description and CVSS: NVD wins; GitHub fills gaps
//  - ranges: each source owns its own; a withdrawn GitHub advisory drops only GitHub's
//  - dates: earliest published, latest modified; references and CWEs: union

import { type AffectedRange, describe, identityKey, rangeFromGhsa, rangeFromNvd, severityFromScore, severityRank } from "./matching";

export interface Reference { url: string; source?: string | null }

export interface Vulnerability {
  id: string;
  title: string;
  titleSource: "ghsa" | "derived";
  description: string;
  severity: string;
  cvssScore: number | null;
  cvssVector: string | null;
  cvssSource: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: boolean;
  kev: boolean;
  kevAdded: string | null;
  kevDue: string | null;
  kevRansomware: boolean;
  kevAction: string | null;
  epss: number | null;
  epssPercentile: number | null;
  sources: string[];
  aliases: string[];
  cwes: string[];
  ranges: AffectedRange[];
  references: Reference[];
  identityIndex: string;
  ingestedAt: string;
  updatedAt: string;
}

export interface Advisory {
  source: "nvd" | "ghsa";
  sourceId: string;
  aliases: string[];
  title: string | null;
  description: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  severity: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: boolean;
  cwes: string[];
  ranges: AffectedRange[];
  references: Reference[];
}

const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** NVD timestamps carry no zone and are UTC. */
export function isoDate(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw) return null;
  const withZone = /[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : raw + "Z";
  const t = Date.parse(withZone);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

const sameRange = (a: AffectedRange, b: AffectedRange) =>
  a.source === b.source && identityKey(a) === identityKey(b) && describe(a) === describe(b) && (a.fixed ?? null) === (b.fixed ?? null);

function pushUnique(list: AffectedRange[], r: AffectedRange) {
  if (!list.some((x) => sameRange(x, r))) list.push(r);
}

export function fromNvd(cve: any): Advisory {
  const id: string = cve.id;
  const description = (cve.descriptions ?? []).find((d: any) => d.lang === "en")?.value ?? null;
  let score: number | null = null, vector: string | null = null, severity: string | null = null;
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = cve.metrics?.[key];
    if (!list?.length) continue;
    const pick = list.find((m: any) => m.type === "Primary") ?? list[0];
    score = pick.cvssData.baseScore;
    vector = pick.cvssData.vectorString ?? null;
    severity = severityFromScore(score!);
    break;
  }
  const cwes: string[] = [];
  for (const w of cve.weaknesses ?? []) for (const d of w.description ?? []) if (d.value?.startsWith("CWE-") && !cwes.includes(d.value)) cwes.push(d.value);
  const ranges: AffectedRange[] = [];
  for (const config of cve.configurations ?? [])
    for (const node of config.nodes ?? [])
      for (const cm of node.cpeMatch ?? []) {
        if (!cm.vulnerable) continue;
        const r = rangeFromNvd(cm.criteria, cm.versionStartIncluding, cm.versionStartExcluding, cm.versionEndIncluding, cm.versionEndExcluding);
        if (r) pushUnique(ranges, r);
      }
  const references: Reference[] = [];
  for (const r of cve.references ?? []) if (!references.some((x) => x.url === r.url)) references.push({ url: r.url, source: "nvd" });
  return {
    source: "nvd", sourceId: id, aliases: [id], title: null, description, cvssScore: score, cvssVector: vector, severity,
    published: isoDate(cve.published), modified: isoDate(cve.lastModified), withdrawn: cve.vulnStatus === "Rejected",
    cwes, ranges, references,
  };
}

export function fromGhsa(a: any): Advisory {
  const ghsa: string = a.ghsa_id;
  const aliases = [ghsa];
  for (const i of a.identifiers ?? []) if (!aliases.includes(i.value)) aliases.push(i.value);
  if (typeof a.cve_id === "string" && !aliases.includes(a.cve_id)) aliases.push(a.cve_id);
  let score: number | null = null, vector: string | null = null;
  for (const key of ["cvss_v4", "cvss_v3"]) {
    const s = a.cvss_severities?.[key];
    if (typeof s?.score === "number" && s.score > 0) { score = s.score; vector = s.vector_string ?? null; break; }
  }
  let severity: string | null = a.severity ?? null;
  severity = severity === "moderate" ? "medium" : severity === "unknown" ? null : severity;
  const ranges: AffectedRange[] = [];
  if (Array.isArray(a.vulnerabilities))
    for (const v of a.vulnerabilities) {
      if (!v.package || typeof v.package !== "object") continue;
      pushUnique(ranges, rangeFromGhsa(v.package.ecosystem, v.package.name, v.vulnerable_version_range, typeof v.first_patched_version === "string" ? v.first_patched_version : null));
    }
  const cwes: string[] = [];
  for (const c of a.cwes ?? []) if (c.cwe_id && !cwes.includes(c.cwe_id)) cwes.push(c.cwe_id);
  const references: Reference[] = [];
  if (typeof a.html_url === "string") references.push({ url: a.html_url, source: "ghsa" });
  for (const url of a.references ?? []) if (typeof url === "string" && !references.some((x) => x.url === url)) references.push({ url, source: "ghsa" });
  return {
    source: "ghsa", sourceId: ghsa, aliases, title: a.summary ?? null, description: a.description ?? null,
    cvssScore: score, cvssVector: vector, severity: score != null ? severityFromScore(score) : severity,
    published: isoDate(a.published_at), modified: isoDate(a.updated_at), withdrawn: typeof a.withdrawn_at === "string",
    cwes, ranges, references,
  };
}

export const cveOf = (a: Advisory) => a.aliases.find((x) => x.startsWith("CVE-")) ?? null;

export function preferredId(aliases: string[]): string {
  const sorted = [...aliases].sort(ordinal);
  return sorted.find((a) => a.startsWith("CVE-")) ?? sorted.find((a) => a.startsWith("GHSA-")) ?? aliases[0];
}

export function emptyVulnerability(id: string, now: string): Vulnerability {
  return {
    id, title: "", titleSource: "derived", description: "", severity: "none", cvssScore: null, cvssVector: null, cvssSource: null,
    published: null, modified: null, withdrawn: false, kev: false, kevAdded: null, kevDue: null, kevRansomware: false, kevAction: null,
    epss: null, epssPercentile: null, sources: [], aliases: [], cwes: [], ranges: [], references: [], identityIndex: "|",
    ingestedAt: now, updatedAt: now,
  };
}

const trim = (s: string, max: number) => (s.length <= max ? s : s.slice(0, max - 1).trimEnd() + "…");

export function firstSentence(text: string): string {
  if (!text || !text.trim()) return "";
  let t = text.trim();
  const dot = t.indexOf(". ");
  if (dot > 0 && dot < 200) t = t.slice(0, dot + 1);
  return trim(t, 160);
}

const rangeKey = (r: AffectedRange) => `${r.source}|${identityKey(r)}|${describe(r)}|${r.fixed ?? ""}`;
export const sortRanges = (ranges: AffectedRange[]) => ranges.sort((x, y) => ordinal(rangeKey(x), rangeKey(y)));

export const indexOf = (ranges: AffectedRange[]) =>
  "|" + [...new Set(ranges.map(identityKey))].sort(ordinal).map((k) => k + "|").join("");

function fingerprint(v: Vulnerability) {
  return JSON.stringify([v.title, v.titleSource, v.description, v.severity, v.cvssScore, v.cvssVector, v.cvssSource, v.published,
    v.modified, v.withdrawn, v.sources, v.aliases, v.cwes, v.ranges.map(rangeKey), v.references.map((r) => r.url)]);
}

/** Folds one source's advisory into a canonical record. Returns true when anything changed. */
export function apply(v: Vulnerability, a: Advisory, now: string): boolean {
  const before = fingerprint(v);
  for (const alias of a.aliases) if (!v.aliases.includes(alias)) v.aliases.push(alias);
  v.aliases.sort(ordinal);
  if (!v.sources.includes(a.source)) { v.sources.push(a.source); v.sources.sort(ordinal); }

  v.ranges = v.ranges.filter((r) => r.source !== a.source);
  if (!a.withdrawn) for (const r of a.ranges) pushUnique(v.ranges, r);
  sortRanges(v.ranges);
  v.withdrawn = a.withdrawn && v.ranges.length === 0 && v.sources.every((s) => s === a.source);

  if (a.source === "nvd") {
    if (a.description?.trim()) v.description = a.description;
    if (a.cvssScore != null) { v.cvssScore = a.cvssScore; v.cvssVector = a.cvssVector; v.cvssSource = "nvd"; }
  } else {
    if (a.title?.trim()) { v.title = trim(a.title, 300); v.titleSource = "ghsa"; }
    if (!v.description.trim() && a.description?.trim()) v.description = a.description;
    if (a.cvssScore != null && v.cvssSource !== "nvd") { v.cvssScore = a.cvssScore; v.cvssVector = a.cvssVector; v.cvssSource = "ghsa"; }
  }
  if (v.titleSource !== "ghsa") { v.title = firstSentence(v.description); v.titleSource = "derived"; }
  v.severity = v.cvssScore != null ? severityFromScore(v.cvssScore) : a.severity ?? v.severity;

  if (a.published && (!v.published || a.published < v.published)) v.published = a.published;
  if (a.modified && (!v.modified || a.modified > v.modified)) v.modified = a.modified;
  for (const c of a.cwes) if (!v.cwes.includes(c)) v.cwes.push(c);
  for (const r of a.references) if (!v.references.some((x) => x.url === r.url)) v.references.push(r);
  v.identityIndex = indexOf(v.ranges);

  const changed = fingerprint(v) !== before;
  if (changed) v.updatedAt = now;
  return changed;
}

/** Merges a duplicate canonical record into target. */
export function absorb(target: Vulnerability, other: Vulnerability) {
  for (const a of other.aliases) if (!target.aliases.includes(a)) target.aliases.push(a);
  target.aliases.sort(ordinal);
  for (const s of other.sources) if (!target.sources.includes(s)) target.sources.push(s);
  target.sources.sort(ordinal);
  for (const r of other.ranges) pushUnique(target.ranges, r);
  sortRanges(target.ranges);
  for (const r of other.references) if (!target.references.some((x) => x.url === r.url)) target.references.push(r);
  for (const c of other.cwes) if (!target.cwes.includes(c)) target.cwes.push(c);
  if (target.titleSource !== "ghsa" && other.titleSource === "ghsa") { target.title = other.title; target.titleSource = "ghsa"; }
  if (!target.description.trim()) target.description = other.description;
  if (target.titleSource !== "ghsa") target.title = firstSentence(target.description);
  if (target.cvssSource !== "nvd" && other.cvssScore != null && (other.cvssSource === "nvd" || target.cvssScore == null)) {
    target.cvssScore = other.cvssScore; target.cvssVector = other.cvssVector; target.cvssSource = other.cvssSource;
  }
  if (target.cvssScore != null) target.severity = severityFromScore(target.cvssScore);
  else if (severityRank(other.severity) > severityRank(target.severity)) target.severity = other.severity;
  if (other.published && (!target.published || other.published < target.published)) target.published = other.published;
  if (other.modified && (!target.modified || other.modified > target.modified)) target.modified = other.modified;
  target.withdrawn = target.withdrawn && other.withdrawn;
  target.kev ||= other.kev;
  target.kevAdded ??= other.kevAdded;
  target.kevDue ??= other.kevDue;
  target.kevRansomware ||= other.kevRansomware;
  target.kevAction ??= other.kevAction;
  target.epss ??= other.epss;
  target.epssPercentile ??= other.epssPercentile;
  target.identityIndex = indexOf(target.ranges);
}

export const rekey = (v: Vulnerability, id: string): Vulnerability => structuredClone({ ...v, id });
