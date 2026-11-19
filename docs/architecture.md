# Architecture

## Components

```text
                ┌──────────────────────── web/ (React 19, Vite) ────────────────────────┐
                │  App.tsx, views/*, WorldRadar.tsx                                      │
                │              │                                                        │
                │          api/client.ts  ── Api (typed calls) ── Transport             │
                │                                   ┌──────────────┴──────────────┐     │
                │                             HttpTransport                BrowserTransport
                └───────────────────────────────────┼─────────────────────────────┼─────┘
                                                    │ HTTP /api/*                 │ in-process
                                                    ▼                             ▼
                           api/ ASP.NET Core 10 (EF Core)          web/src/engine/engine.ts
                           SQLite | PostgreSQL                     state in IndexedDB
                                                    │                             │
                                                    └────────────┬────────────────┘
                                                                 ▼
                                         NVD CVE API 2.0 · GitHub Advisory DB · CISA KEV · FIRST EPSS
```

The UI never knows which backend it has. `client.ts` picks the transport at build time: if `VITE_API_URL` is set (`npm run dev:api`, the Docker image) it uses `HttpTransport`; otherwise (`npm run dev`, GitHub Pages) it uses `BrowserTransport`, which hands each request to the in-browser `Engine` and persists the engine's state to IndexedDB after every non-GET.

Both backends expose the same `/api/*` surface. That is what makes one contract scenario able to test both (see [parity.md](parity.md)).

## shared/

Data used by both implementations, bundled into each:

| File | Purpose | Consumed by |
|---|---|---|
| `catalog.json` | Watched products (verified CPE and GitHub package identities), severities, danger levels, site presets | API (copied to output, `Catalog.cs`), web (`@shared` alias) |
| `vectors.json` | Matching cases both implementations assert | `VectorTests.cs`, `vectors.test.ts` |
| `contract/scenario.json` | End-to-end HTTP scenario | `ContractRunner.cs`, `contract.test.ts` |
| `fixtures/day1`, `day2` | Recorded source responses | `FixtureHandler` (C#), `fixtureFetcher` (TS) |

The web build reaches `../shared` through the `@shared` alias in `vite.config.ts`. Both Dockerfiles build from the repository root for the same reason.

## API (api/src/BlastRadius.Api)

Minimal APIs, wired in `Program.cs`:

- **Http/** — one static `Map(app)` per area: `AuthEndpoints`, `InventoryEndpoints`, `IntelEndpoints` (catalog, exposure, vulnerabilities), `AlertEndpoints` (subscriptions, notifications, deliveries), `IngestionEndpoints`. `ApiError` + `UseApiErrors()` turn rule violations into problem details with a `code`.
- **Ingestion/** — `NvdClient`, `GhsaClient`, `KevClient`, `EpssClient` (`Sources.cs`); `Normalize` turns raw responses into `Advisory` records (`Advisory.cs`); `Merge` folds advisories into canonical records; `IngestionService` runs one batch; `IngestionCoordinator` serializes runs and enforces the manual cooldown; `IngestionScheduler` (hosted service) runs on start and every `Ingestion:IntervalHours`; `SnapshotCommand` is the `snapshot` CLI verb.
- **Matching/** — pure functions: `VersionComparer`, `AffectedRange` (range parsing and evaluation, `Best` across sources), `Identity` (normalized identity keys), `Danger` (score and level).
- **Exposure/** — `ExposureService` materializes `Match` rows (asset × vulnerability) with a status, a basis and a human explanation.
- **Notifications/** — `Notifier` filters ingestion events through subscriptions, writes notifications, posts webhooks; `WebhookGuard` is the SSRF check.
- **Data/** — `AppDb`, entities, PostgreSQL migrations, `DesignTimeFactory` for `dotnet ef`.

Startup: PostgreSQL runs migrations; SQLite calls `EnsureCreated`. If the first argument is `snapshot`, the app ingests once, writes the file and exits without serving HTTP.

## Data model

Per-account (everything filtered by `UserId`): `Site`, `Asset`, `Match`, `Subscription`, `Notification`, `WebhookDelivery`.

Global: `Vulnerability`, `VulnerabilityAlias`, `IngestionRun`, `SyncState`, and `User`.

Key points:

- **`Vulnerability.Id`** is the CVE when any source names one, otherwise the GHSA id. Every identifier ever seen is in `Aliases`; the `VulnerabilityAlias` table (primary key = alias) guarantees one owner per identifier.
- **`Vulnerability.Ranges`** is a JSON list of `AffectedRange`, each tagged with its `Source`. `IdentityIndex` (`"|cpe:vendor:product|pkg:eco:name|"`) lets exposure find candidates with a `LIKE` query on both databases.
- **`Asset`** identity is `ProductKey` (a catalog product) or hand-entered `Ecosystem`/`Package` and/or `CpeVendor`/`CpeProduct`. `Version` may be empty (unknown).
- **`Match`** is unique per (asset, vulnerability). `Status` is `affected` or `possible`; `Basis` records why (`range`, `no-version`, `no-bounds`, `incomparable`) and decides whether it may alert.
- **`Notification`** is unique per (subscription, vulnerability, reason). This index is what makes "alert at most once" hold.
- **`SyncState`** stores high-water marks (`nvd:cpe:…`, `ghsa:pkg:…`) for incremental fetches.

## Ingestion pipeline

One batch (`IngestionService.RunAsync`, mirrored by `Engine.ingest`):

1. **Snapshot** current (asset, vulnerability) pairs and each matched vulnerability's KEV flag and severity.
2. **Watch list** = catalog products + identities users entered by hand (assets without a `ProductKey`).
3. **NVD**, per CPE (`virtualMatchString`, incremental by `lastModStartDate` within NVD's 120-day window, throttled process-wide), then **GitHub**, per package (incremental by `modified`). Each advisory is normalized and **upserted**: find every record any of its aliases already points to; none → create; several → they were duplicates, absorb into one; then re-key if a CVE has appeared.
4. **KEV** marks and unmarks records; **EPSS** scores every CVE record.
5. Sync the alias table, **re-point** notifications from retired ids to their successors (dropping would-be duplicates), drop matches keyed by retired ids.
6. **Recompute exposure** for everyone.
7. **Diff** against step 1 (old ids resolved through the remap) into events: `new_exposure`, `kev_added`, `severity_raised`.
8. **Notify**: each event × each passing subscription → at most one notification; webhooks batched per subscription.

Each source × target gets an `IngestionRun` row with counts (fetched, created, updated, linked, merged, unchanged) and any error. A failing source records its error and the batch continues.

Editing the inventory recomputes exposure for that account but never raises alerts — only ingestion does.

## Web client (web/src)

- `App.tsx` — sign-in, hash routing (`#/view/arg`), layout. The map fills the window; views are panels docked around it.
- `WorldRadar.tsx` — d3-geo projection on a canvas: dot-matrix land, site dots colored by danger level, simulated probe traces, highlighting for the selected vulnerability or site.
- `views/` — `Radar`, `Vulnerabilities`, `Inventory`, `Alerts`, `Sources`.
- `ui.tsx` — shared context (`Ctx`) and small components.
- `api/demo.ts` — seeds the 72-site demo account on first visit of the browser build; versions are drawn from release numbers that appear in the vulnerability data.
- `index.html` loads an external `ads.js` from the author's profile site (cross-promotion of other projects); it does not run on localhost.
