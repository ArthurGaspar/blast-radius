# CLAUDE.md

Blast Radius matches published vulnerabilities (NVD, GitHub Advisory Database, enriched with CISA KEV and FIRST EPSS) against a per-account inventory of sites and software, and alerts when that picture changes. `README.md` is the user-facing description; `docs/` holds the developer documentation (start at `docs/README.md`).

## The one rule: two implementations, one behavior

The backend logic exists twice:

- `api/` — ASP.NET Core 10 API (EF Core, SQLite or PostgreSQL, JWT).
- `web/src/engine/` — a TypeScript port that runs *in the browser* for the GitHub Pages build (no server).

They must stay behaviorally identical: same routes, status codes, error `code`s, response shapes, merge rules, matching rules and alert rules. Any change to domain logic or the HTTP surface goes into **both**, and is pinned by the shared tests in `shared/` (`contract/scenario.json`, `vectors.json`). See `docs/parity.md` for the file-by-file mapping.

## Commands

```bash
# API (from api/) — needs the .NET 10 SDK (api/global.json)
dotnet run --project src/BlastRadius.Api          # http://localhost:5190, SQLite, ingests on start
dotnet test                                       # xUnit v3 on Microsoft.Testing.Platform
dotnet run --project src/BlastRadius.Api -- snapshot <file>   # live ingestion -> browser snapshot JSON

# Web (from web/) — Node 22
npm ci
npm run dev        # browser build: engine runs in the tab, http://localhost:5173
npm run dev:api    # client talks to the API at VITE_API_URL (web/.env.api -> :5190)
npm test           # Vitest: contract scenario, vectors, merge
npm run build      # tsc --noEmit && vite build

# Everything with PostgreSQL
docker compose up --build    # web :5173, API :8080
```

The PostgreSQL contract test uses Testcontainers and is skipped without Docker; CI runs it.

## Layout

```text
shared/        catalog.json, vectors.json, contract/scenario.json, fixtures/ (recorded source responses) — used by both sides
api/src/BlastRadius.Api/
  Matching/        VersionComparer, AffectedRange, Identity, Danger
  Ingestion/       source clients, Advisory normalization, Merge, IngestionService, coordinator/scheduler, snapshot command
  Exposure/        ExposureService (matches + explanations)
  Notifications/   Notifier, WebhookGuard (SSRF)
  Http/            minimal-API endpoint groups, ApiError
  Data/            AppDb, entities, PostgreSQL migrations
api/tests/BlastRadius.Tests/   contract runner, vectors, merge, security, notifier tests
web/src/engine/    engine.ts (routes + ingestion), matching.ts, merge.ts, sources.ts (+ *.test.ts)
web/src/api/       client.ts (HttpTransport / BrowserTransport), types.ts, demo.ts (72-site demo inventory)
web/src/views/     one panel per view; WorldRadar.tsx is the canvas map
docs/              developer docs + screenshots referenced by README.md
```

## Conventions

- **Errors:** throw `ApiError` (C#) / the engine's `ApiError` (TS) with a stable kebab/dotted `code` (`auth.username-taken`, `site.limit`, `validation`, `not-found`). Responses are RFC 7807 problem details with `code`. The web client switches on `code`, never on message text.
- **Ordering is ordinal and deterministic.** Aliases, sources and ranges are sorted ordinally so re-applying unchanged data is a no-op. Keep it that way; merge is tested for order independence and idempotence.
- **Lists on entities are JSON columns** (`AppDb.JsonList`) so one model runs on both databases. On SQLite, `DateTimeOffset` is stored as ticks.
- **Migrations target PostgreSQL only.** SQLite uses `EnsureCreated`. After changing the model, add a migration (see `docs/how-to.md`).
- **Sources are injectable.** `Sources:FixtureDir` makes every HTTP client read `shared/fixtures/<day>/` — tests never hit the network.
- **Code style:** match the surrounding code — compact, comments explain *why* (often citing a real CVE that motivated a rule), no ceremony. C# uses primary constructors, records and minimal APIs; TS uses plain functions and types, no state library.
- **Commits:** conventional prefixes (`feat(web): …`, `fix(api): …`); messages in this repo are written in Portuguese.
- `web/public/data/snapshot.json` is regenerated daily by CI; don't hand-edit it.

## Before finishing a change

- Domain/HTTP change → both implementations updated, `dotnet test` and `npm test` green, scenario/vectors extended to cover it.
- UI-only change → `npm run build` (type check) and `npm test`.
- Model change → new migration in `api/src/BlastRadius.Api/Data/Migrations/`.
