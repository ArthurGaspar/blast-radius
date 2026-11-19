# Domain rules and invariants

The README's [Matching](../README.md#matching) section explains these rules for users. This page lists them as invariants, with where they're enforced, so changes don't break them by accident. Every rule here exists in both `api/` and `web/src/engine/`.

## Identity

- Identity keys are `cpe:<vendor>:<product>` and `pkg:<ecosystem>:<name>`, all lower-cased (`Identity.cs`, `matching.ts`).
- PyPI names are normalized per PEP 503: runs of `-`, `_`, `.` are equivalent (`Jupyter_Server` = `jupyter-server`). Other ecosystems are only lower-cased.
- An asset matches a range only through a shared identity key. A catalog product carries both a CPE and a package identity, so it is reached by both sources.

## Deduplication (`Ingestion/Merge.cs`, `merge.ts`)

- **Primary id:** the ordinally-first CVE among the aliases; otherwise the first GHSA id. All identifiers become aliases. One alias → one record, enforced by the alias table's primary key.
- **Joining:** an advisory sharing *any* alias with existing records joins them. If it touches several, they collapse into one (`Absorb`) and the losers are retired.
- **Re-keying:** when a CVE appears for a GHSA-keyed record, a copy is created under the CVE (`Rekey`; EF can't change keys in place) and the old record is retired. Notifications follow via the remap, so nothing alerts twice.
- **Field ownership:**
  - Title: GitHub's summary, else the first sentence of the description (`TitleSource` = `ghsa` | `derived`).
  - Description and CVSS: NVD wins; GitHub fills gaps only.
  - Severity: derived from CVSS when there is one, else the source's label.
  - Ranges: each source owns its own. An update replaces only that source's ranges. A withdrawn GitHub advisory drops GitHub's ranges. The record is `Withdrawn` only if nothing else backs it.
  - Dates: earliest published, latest modified. References and CWEs: union.
- **Determinism:** aliases, sources and ranges are kept in ordinal order. `Apply` returns "changed" from a fingerprint comparison, so re-applying an unchanged advisory changes nothing. Merging is order-independent. Both properties are tested; don't introduce culture-sensitive sorting or insertion-order dependence.

## Versions (`VersionComparer.cs`, `matching.ts`)

Ecosystem-agnostic comparison. Tokens are numbers and words. A leading `v` and `+build` metadata are ignored. Pre-release words rank `dev/snapshot < a/alpha < b/beta < pre/preview/m < c/rc/cr < release`. `post/p/patch/pl/r/rev` sort after the release. `final/ga/release/stable` are neutral. A single trailing letter after digits is an OpenSSL-style suffix (`1.1.1w > 1.1.1`). The cases live in `vectors.json` → `compare`.

## Ranges and match status (`AffectedRange.cs`, `matching.ts`)

`Evaluate(version)` returns `none`, `possible` or `affected`:

| Situation | Result |
|---|---|
| Asset version empty | `possible` |
| Range has no exact version and no bounds | `none` (says nothing about a known version) |
| Exact version | `affected` if equal; `possible` if not comparable |
| Any bound excludes the version | `none` |
| A bound can't be compared (a date against `3.17.2`) and none excludes it | `possible` |
| Otherwise | `affected` |

**Best across sources** (`AffectedRange.Best`): `affected` beats `possible`. When any source gives bounds, unbounded statements are ignored, so specific beats vague. This rule exists because NVD lists some products without bounds (CVE-2023-6018 for MLflow). Without it, old OpenSSH CVEs flagged OpenSSH 10.

**Basis** (`ExposureService.BasisOf`):
- `range` — affected by a range.
- `no-version` — possible because the asset has no version.
- `no-bounds` — possible because the source names the product without versions.
- `incomparable` — possible because of a different version scheme.

Only `range` and `no-version` may raise alerts.

## Danger (`Danger.cs`, `matching.ts`)

```
base  = CVSS, else severity fallback (critical 9.5, high 7.5, medium 5, low 2.5, unknown 5)
score = min(10, base + 2·KEV + 3·EPSS) × (0.6 if possible), rounded to 0.1 half away from zero
level = severe ≥ 9 · high ≥ 7 · elevated ≥ 4 · low > 0 · clear
```

A site's level is the worst score among its matches. The thresholds are also in `catalog.json` → `dangerLevels` for the UI. Keep them in sync. In the UI, red is used only for danger.

## Alerts (`Notifier.cs`, `engine.ts`)

- Only **ingestion** raises alerts, from a before/after diff: `new_exposure` (a new asset × vulnerability pair), `kev_added` (a matched record became KEV), `severity_raised` (a matched record's severity rank went up). Inventory edits recompute exposure silently.
- A subscription passes an event when all of these hold:
  - it is active;
  - the basis may alert;
  - the scope matches (all / site / product);
  - severity ≥ `MinSeverity`;
  - `KevOnly` is respected;
  - EPSS ≥ `MinEpss`;
  - the keyword, if set, appears in the id, title or description (case-insensitive).
- At most one notification per (subscription, vulnerability, reason), enforced by a unique index.

## Webhooks (`WebhookGuard`, `checkWebhook`)

- The URL must be absolute `https`. Plain `http` is accepted only with `AllowPrivateTargets`.
- The URL is checked when saved (syntax, `localhost`, literal IPs) and again at send time after DNS resolution.
- Refused targets:
  - loopback and `0.0.0.0/8`;
  - RFC 1918 private ranges;
  - link-local, including `169.254.169.254`;
  - CGNAT (`100.64/10`);
  - benchmarking (`198.18/15`);
  - multicast and reserved (`224/3` and above);
  - IPv6 link-local, site-local, ULA and multicast;
  - IPv4-mapped forms of all the above.
- Redirects are not followed (`AllowAutoRedirect = false` on the `webhooks` client).
- Every attempt is logged as a `WebhookDelivery` (`delivered` | `failed` | `blocked`).
- `Webhooks:AllowPrivateTargets` bypasses the guard for local development only.
