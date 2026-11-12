// Response shapes of the ASP.NET Core API; the browser engine returns the same.
import type { Level } from "../engine/matching";
export type { Level };

export interface UserView { id: string; username: string; displayName: string }
export interface Me { user: UserView; sites: number; assets: number; unread: number }

export interface Site { id: string; name: string; kind: "office" | "datacenter" | "cloud"; presetKey: string | null; lat: number; lon: number; createdAt: string }

export interface Asset {
  id: string; siteId: string; productKey: string | null; label: string; version: string; ecosystem: string | null; package: string | null;
  cpeVendor: string | null; cpeProduct: string | null; createdAt: string; affected: number; possible: number; maxScore: number; level: Level;
}

export interface ExposureSite {
  id: string; name: string; kind: string; lat: number; lon: number; score: number; level: Level; assets: number; affected: number;
  possible: number; kev: number; exploitPressure: number; top: { id: string; title: string; score: number } | null;
}

export interface Threat {
  id: string; title: string; severity: string; cvss: number | null; kev: boolean; kevAdded: string | null; epss: number | null;
  score: number; level: Level;
  assets: { assetId: string; label: string; version: string; siteId: string; site: string; status: "affected" | "possible"; basis: string; explanation: string; fixedIn: string | null; score: number }[];
}

export interface Exposure {
  generatedAt: string; score: number; level: Level;
  totals: { sites: number; assets: number; vulnerabilities: number; affected: number; kev: number; severe: number };
  sites: ExposureSite[];
  threats: Threat[];
}

export interface VulnRow {
  id: string; title: string; severity: string; cvss: number | null; kev: boolean; epss: number | null; published: string | null;
  modified: string | null; sources: string[]; aliases: string[]; matched: number;
}
export interface Page<T> { items: T[]; page: number; size: number; total: number }

export interface VulnDetail {
  id: string; requested: string; redirected: boolean; title: string; description: string; severity: string; cvss: number | null;
  cvssVector: string | null; cvssSource: string | null; published: string | null; modified: string | null; withdrawn: boolean;
  sources: string[]; aliases: string[]; cwes: string[];
  kev: { added: string | null; due: string | null; ransomware: boolean; action: string | null } | null;
  epss: number | null; epssPercentile: number | null;
  ranges: { source: string; identity: string; versions: string; fixed: string | null }[];
  references: { url: string; source?: string | null }[];
  matches: { assetId: string; label: string; version: string; siteId: string; site: string; status: string; basis: string; explanation: string; fixedIn: string | null; score: number; level: Level; firstSeen: string }[];
}

export interface Subscription {
  id: string; name: string; scope: "all" | "site" | "product"; scopeSiteId: string | null; scopeProductKey: string | null;
  minSeverity: string; kevOnly: boolean; minEpss: number; keyword: string | null; webhookUrl: string | null; active: boolean; createdAt: string;
}
export interface Preview { matches: number; vulnerabilities: number; sample: { id: string; title: string; asset: string; site: string }[] }

export interface NotificationItem {
  id: string; reason: "new_exposure" | "kev_added" | "severity_raised"; title: string; detail: string; vulnerabilityId: string;
  assetId: string | null; createdAt: string; readAt: string | null; subscription: string; severity: string | null; kev: boolean;
}
export interface Inbox { unread: number; total: number; page: number; size: number; items: NotificationItem[] }

export interface Delivery { id: string; subscriptionId: string; notificationId: string | null; url: string; outcome: string; httpStatus: number | null; error: string | null; durationMs: number; createdAt: string }

export interface IngestionSummary {
  batchId: string; startedAt: string; finishedAt: string; fetched: number; created: number; updated: number; linked: number;
  merged: number; kevMarked: number; epssScored: number; notifications: number; errors: string[];
}
export interface IngestionStatus {
  running: boolean; nextScheduled: string | null; last: IngestionSummary | null;
  totals: { vulnerabilities: number; nvdOnly: number; ghsaOnly: number; both: number; kev: number; withEpss: number; aliases: number; withdrawn: number };
  targets: { source: string; target: string; startedAt: string; finishedAt: string | null; fetched: number; created: number; updated: number; linked: number; merged: number; unchanged: number; error: string | null; current: boolean }[];
}
