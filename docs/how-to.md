# How to

Recipes for common changes. Each one assumes you've read [parity.md](parity.md): domain and HTTP changes go into both implementations.

## Add a product to the catalog

1. Find its **verified** identities:
   - The CPE vendor/product, exactly as NVD uses it. Check that `virtualMatchString=cpe:2.3:a:<vendor>:<product>` returns results.
   - The GitHub ecosystem/package, exactly as the Advisory Database uses it.
   - Wrong identities fail silently: the product just never matches anything.
2. Add an entry to `shared/catalog.json` → `products` (`key`, `name`, `category` `ai` | `infra`, `description`, `ghsa`, `cpe`). Either identity may be omitted.
3. Update the product count asserted by the "the catalog is public" step in `shared/contract/scenario.json`.
4. Optionally use it in `web/src/api/demo.ts` site templates.
5. `dotnet test` and `npm test`. The next ingestion fetches it. Regenerate the snapshot if the browser build should include it at once.

Site presets work the same way (`sitePresets`, also counted in the scenario).

## Add or change an endpoint

1. Add a step to `shared/contract/scenario.json` covering the success path and the main error codes.
2. API: add the route to the matching `Http/*Endpoints.cs` group. Throw `ApiError` for rule violations with a stable `code`. Filter everything per-account by `User.UserId()`.
3. Engine: register the same route with `this.on(...)` in `Engine.defineRoutes` (`web/src/engine/engine.ts`) with the same status, errors and response shape. Mutating routes run on a cloned state that is only kept on success.
4. Client: add a typed call to `Api` in `web/src/api/client.ts` and any types to `types.ts`.
5. Run both suites.

## Change the data model

1. Edit `Data/Entities.cs` and, if needed, `Data/AppDb.cs`. List properties need the `JsonList`/`ListComparer` conversion.
2. Create a PostgreSQL migration (from `api/`):

   ```bash
   dotnet tool restore
   dotnet ef migrations add <Name> --project src/BlastRadius.Api --output-dir Data/Migrations
   ```

   `DesignTimeFactory` targets PostgreSQL, so no running database is needed to generate the migration.
3. SQLite picks up the model through `EnsureCreated`. Existing local `.db` files won't be migrated, so delete them.
4. Mirror the change in the engine's `State` types. If stored browser state becomes incompatible, bump `KEY` in `client.ts`.

## Change a matching or merge rule

1. Find the real advisory that shows the problem. Add vectors to `shared/vectors.json` (or a scenario step) that fail today.
2. Fix it in `Matching/` or `Ingestion/Merge.cs`. Add a short comment saying *why*, naming the CVE if there is one.
3. Port it to `matching.ts` / `merge.ts`.
4. Check the merge tests still prove order independence and idempotence.
5. Update [domain-rules.md](domain-rules.md) and the README's Matching section if the user-visible rule changed.

## Add a data source

This is a larger change.

1. Write a client in `Ingestion/Sources.cs` with fixture support: extend `FixtureHandler` and the fixture file layout.
2. Normalize its responses into `Advisory` (or into an enrichment like KEV/EPSS).
3. Add a step to `IngestionService.RunAsync` with its own `IngestionRun` rows.
4. Mirror all of it in `sources.ts`, `merge.ts` and `Engine.ingest`.
5. Decide its precedence in `Merge.Apply` and document it.
6. Record fixtures and extend the scenario.
7. The browser build calls sources directly, so the source must send CORS headers or it can't be supported there.

## Add a UI view or panel

UI-only changes don't need parity work.

1. Add the component under `web/src/views/` and register it in `VIEWS` and the router in `App.tsx`.
2. Use the `Api` from context (`Ctx` in `ui.tsx`). Never branch on the transport mode for data.
3. Run `npm run build` to type-check, and `npm run dev` to try it.
