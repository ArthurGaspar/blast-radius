// Port of BlastRadius.Api/Matching (VersionComparer, AffectedRange, Identity, Danger).
// shared/vectors.json pins both implementations to the same answers.

export type MatchStatus = "none" | "possible" | "affected";
const STATUS_ORDER: MatchStatus[] = ["none", "possible", "affected"];
export const statusRank = (s: MatchStatus) => STATUS_ORDER.indexOf(s);

// ------------------------------------------------------------------ versions

const enum Kind { Pre = 0, End = 1, Number = 2, Post = 3 }
interface Token { kind: Kind; num: number; rank: number; text: string }

const PRE_RANKS: Record<string, number> = {
  dev: 0, snapshot: 0, a: 1, alpha: 1, b: 2, beta: 2, pre: 3, preview: 3, m: 3, c: 4, rc: 4, cr: 4,
};
const POST_WORDS = new Set(["post", "p", "patch", "pl", "r", "rev"]);
const NEUTRAL = new Set(["final", "ga", "release", "stable"]);
const END: Token = { kind: Kind.End, num: 0, rank: 0, text: "" };

function tokenize(raw: string): Token[] {
  let s = raw.trim().toLowerCase();
  const plus = s.indexOf("+");
  if (plus >= 0) s = s.slice(0, plus);
  if (s.length > 1 && s[0] === "v" && /\d/.test(s[1])) s = s.slice(1);
  const matches = [...s.matchAll(/\d+|[a-z]+/g)];
  const tokens: Token[] = [];
  matches.forEach((m, i) => {
    const text = m[0];
    if (/\d/.test(text[0])) {
      const n = Number(text);
      tokens.push({ kind: Kind.Number, num: Number.isSafeInteger(n) ? n : Number.MAX_SAFE_INTEGER, rank: 0, text });
      return;
    }
    if (NEUTRAL.has(text)) return;
    const last = i === matches.length - 1;
    const prev = matches[i - 1];
    const afterNumber = i > 0 && /\d/.test(prev[0][0]) && prev.index! + prev[0].length === m.index;
    if (text.length === 1 && last && afterNumber) tokens.push({ kind: Kind.Post, num: 0, rank: 0, text });
    else if (POST_WORDS.has(text)) tokens.push({ kind: Kind.Post, num: 0, rank: 0, text });
    else tokens.push({ kind: Kind.Pre, num: 0, rank: PRE_RANKS[text] ?? 0, text });
  });
  return tokens;
}

const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function compareTokens(x: Token, y: Token): number {
  if (x.kind === Kind.End && y.kind === Kind.Number && y.num === 0) return 0;
  if (y.kind === Kind.End && x.kind === Kind.Number && x.num === 0) return 0;
  if (x.kind !== y.kind) return x.kind < y.kind ? -1 : 1;
  switch (x.kind) {
    case Kind.Number: return x.num < y.num ? -1 : x.num > y.num ? 1 : 0;
    case Kind.Pre: return x.rank !== y.rank ? (x.rank < y.rank ? -1 : 1) : ordinal(x.text, y.text);
    case Kind.Post: return ordinal(x.text, y.text);
    default: return 0;
  }
}

export function compareVersions(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const c = compareTokens(ta[i] ?? END, tb[i] ?? END);
    if (c !== 0) return c;
  }
  return 0;
}

// ------------------------------------------------------------------ identity

export const normalizePackage = (ecosystem: string, name: string) => {
  const n = name.trim().toLowerCase();
  return ecosystem.trim().toLowerCase() === "pip" ? n.replace(/[-_.]+/g, "-") : n;
};
export const packageKey = (ecosystem: string, name: string) =>
  `pkg:${ecosystem.trim().toLowerCase()}:${normalizePackage(ecosystem, name)}`;
export const cpeKey = (vendor: string, product: string) =>
  `cpe:${vendor.trim().toLowerCase()}:${product.trim().toLowerCase()}`;

// ------------------------------------------------------------------ ranges

export interface AffectedRange {
  source: "nvd" | "ghsa";
  cpeVendor?: string | null;
  cpeProduct?: string | null;
  ecosystem?: string | null;
  package?: string | null;
  exact?: string | null;
  startIncluding?: string | null;
  startExcluding?: string | null;
  endIncluding?: string | null;
  endExcluding?: string | null;
  fixed?: string | null;
}

export const identityKey = (r: AffectedRange) =>
  r.cpeVendor ? cpeKey(r.cpeVendor, r.cpeProduct!) : packageKey(r.ecosystem!, r.package!);

export const hasBounds = (r: AffectedRange) =>
  r.startIncluding != null || r.startExcluding != null || r.endIncluding != null || r.endExcluding != null;

/** NVD sometimes uses release dates as versions; a date and a release number can't be ordered. */
const isDate = (s: string) => /^\d{4}-\d{2}-\d{2}$/.test(s.trim());
const comparable = (a: string, b: string) => isDate(a) === isDate(b);

export function evaluate(r: AffectedRange, version: string | null | undefined): MatchStatus {
  if (!version || !version.trim()) return "possible";
  // NVD sometimes names a product with no versions at all: that says nothing about a known version
  if (r.exact == null && !hasBounds(r)) return "none";
  if (r.exact != null) return comparable(version, r.exact) ? (compareVersions(version, r.exact) === 0 ? "affected" : "none") : "possible";
  // A bound that excludes the version settles it; a bound in another scheme (a date against 3.17.2) can't confirm it.
  let unsure = false;
  const check = (bound: string | null | undefined, excludes: (c: number) => boolean): boolean => {
    if (bound == null) return false;
    if (!comparable(version, bound)) { unsure = true; return false; }
    return excludes(compareVersions(version, bound));
  };
  if (check(r.startIncluding, (c) => c < 0)) return "none";
  if (check(r.startExcluding, (c) => c <= 0)) return "none";
  if (check(r.endIncluding, (c) => c > 0)) return "none";
  if (check(r.endExcluding, (c) => c >= 0)) return "none";
  return unsure ? "possible" : "affected";
}

/** Across all ranges for one product: specific statements beat unbounded ones, then "affected" beats "possible". */
export function best(ranges: AffectedRange[], version: string | null | undefined): { status: MatchStatus; range: AffectedRange | null } {
  const specific = ranges.filter((r) => r.exact != null || hasBounds(r));
  let out: { status: MatchStatus; range: AffectedRange | null } = { status: "none", range: null };
  for (const r of specific.length ? specific : ranges) {
    const s = evaluate(r, version);
    if (statusRank(s) > statusRank(out.status)) out = { status: s, range: r };
    if (s === "affected") break;
  }
  return out;
}

export function describe(r: AffectedRange): string {
  if (r.exact != null) return "= " + r.exact;
  if (!hasBounds(r)) return "all versions";
  const parts: string[] = [];
  if (r.startIncluding != null) parts.push(">= " + r.startIncluding);
  if (r.startExcluding != null) parts.push("> " + r.startExcluding);
  if (r.endIncluding != null) parts.push("<= " + r.endIncluding);
  if (r.endExcluding != null) parts.push("< " + r.endExcluding);
  return parts.join(", ");
}

/** GitHub's vulnerable_version_range: ">= 2.49.0, < 2.55.0", "= 1.2.0", "< 0.17.1". */
export function rangeFromGhsa(ecosystem: string, pkg: string, range: string | null | undefined, firstPatched: string | null | undefined): AffectedRange {
  const r: AffectedRange = { source: "ghsa", ecosystem, package: pkg, exact: null, startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, fixed: firstPatched?.trim() ? firstPatched : null };
  for (const raw of (range ?? "").split(",")) {
    const part = raw.trim();
    if (!part) continue;
    const [op, value] =
      part.startsWith(">=") ? [">=", part.slice(2)] : part.startsWith("<=") ? ["<=", part.slice(2)]
      : part.startsWith(">") ? [">", part.slice(1)] : part.startsWith("<") ? ["<", part.slice(1)]
      : part.startsWith("=") ? ["=", part.slice(1)] : ["=", part];
    const v = value.trim();
    if (op === ">=") r.startIncluding = v;
    else if (op === ">") r.startExcluding = v;
    else if (op === "<=") r.endIncluding = v;
    else if (op === "<") r.endExcluding = v;
    else r.exact = v;
  }
  return r;
}

/** An NVD cpeMatch. A concrete CPE version (plus update, e.g. openssh 9.7 p1 → "9.7p1") is an exact match. */
export function rangeFromNvd(criteria: string, si?: string | null, se?: string | null, ei?: string | null, ee?: string | null): AffectedRange | null {
  const f = criteria.split(":");
  if (f.length < 7 || f[0] !== "cpe" || f[2] !== "a") return null;
  const un = (s: string) => s.replaceAll("\\", "");
  const version = un(f[5]);
  const update = un(f[6]);
  let exact: string | null = null;
  if (version !== "*" && version !== "-") exact = update === "*" || update === "-" || update === "" ? version : version + update;
  return {
    source: "nvd", cpeVendor: un(f[3]), cpeProduct: un(f[4]), exact,
    startIncluding: si ?? null, startExcluding: se ?? null, endIncluding: ei ?? null, endExcluding: ee ?? null, fixed: ee ?? null,
  };
}

// ------------------------------------------------------------------ danger

export type Level = "clear" | "low" | "elevated" | "high" | "severe";

/** CVSS (or a severity fallback) + 2 if in CISA KEV + 3 × EPSS, capped at 10; × 0.6 when the version is unknown. */
export function dangerScore(cvss: number | null | undefined, severity: string | null | undefined, kev: boolean, epss: number | null | undefined, status: MatchStatus): number {
  const base = cvss ?? ({ critical: 9.5, high: 7.5, medium: 5.0, low: 2.5 } as Record<string, number>)[severity ?? ""] ?? 5.0;
  let s = Math.min(10, base + (kev ? 2 : 0) + 3 * (epss ?? 0));
  if (status === "possible") s *= 0.6;
  return Math.round(s * 10 + 1e-9) / 10; // half away from zero, as in C#
}

export const dangerLevel = (score: number): Level =>
  score >= 9 ? "severe" : score >= 7 ? "high" : score >= 4 ? "elevated" : score > 0 ? "low" : "clear";

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export const severityRank = (s: string | null | undefined) => SEVERITY_RANK[s ?? ""] ?? 0;

export const severityFromScore = (score: number) =>
  score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "none";
