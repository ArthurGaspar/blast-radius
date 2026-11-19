# Parity between the API and the browser engine

The GitHub Pages build has no server. `web/src/engine/` is a TypeScript port of the API that answers the same HTTP requests in the browser. The two must behave identically, because the same UI talks to either and the same tests run against both.

## What must match

- Routes, methods, query parameters and required auth.
- Status codes, error `code`s and problem-details shape.
- Response JSON shapes (field names are camelCase on both sides; enums serialize as camelCase strings).
- Merge rules, version comparison, range parsing, cross-source precedence, identity normalization, danger scores.
- Alert rules: what raises an event, subscription filtering, once-per-(subscription, vulnerability, reason).
- Limits (sites, assets, subscriptions per account) and validation messages' *codes*.

Allowed differences, all documented in the README: the browser keeps data in IndexedDB, uses anonymous rate limits, and records webhooks without sending them (browsers can't post to arbitrary hosts). Passwords are salted hashes on both sides, but the engine issues opaque session tokens (`local.<uuid>`, kept in its state) instead of JWTs. The engine runs in one browser and is not a security boundary.

## File mapping

| C# (`api/src/BlastRadius.Api/`) | TypeScript (`web/src/engine/`) |
|---|---|
| `Matching/VersionComparer.cs`, `AffectedRange.cs`, `Identity.cs`, `Danger.cs` | `matching.ts` |
| `Ingestion/Advisory.cs` (`Normalize`), `Ingestion/Merge.cs` | `merge.ts` (`fromNvd`, `fromGhsa`, `apply`, `absorb`, `rekey`, `preferredId`) |
| `Ingestion/Sources.cs` (clients, `FixtureHandler`) | `sources.ts` (`Sources`, `liveFetcher`, `fixtureFetcher`) |
| `Ingestion/IngestionService.cs` | `engine.ts` → `Engine.ingest` |
| `Exposure/ExposureService.cs` | `engine.ts` (`explain`, `basisOf`, recompute) |
| `Notifications/Notifier.cs` (`Passes`, `Describe`, `WebhookGuard`) | `engine.ts` (`passes`, `describeEvent`, `checkWebhook`) |
| `Http/*Endpoints.cs` | `engine.ts` route table (`this.on(...)` in `defineRoutes`) |
| `Http/ApiError.cs` | `engine.ts` `ApiError`, `notFound`, `invalid`, `conflict` |
| `Ingestion/SnapshotCommand.cs` (writes) | `engine.ts` `importSnapshot` (reads) |
| `Data/Entities.cs` | `engine.ts` `State` and row interfaces |
| `Tests/ContractRunner.cs`, `VectorTests.cs`, `MergeTests.cs` | `contract.test.ts`, `vectors.test.ts`, `merge.test.ts` |

The TypeScript files open with a comment naming the C# file they port. Keep those comments accurate.

## What keeps them honest

1. **`shared/contract/scenario.json`** — one HTTP scenario, run against the API on SQLite, the API on PostgreSQL, and the engine. If a behavior is observable over HTTP, it belongs here.
2. **`shared/vectors.json`** — table-driven cases for the pure matching functions, asserted by both test suites.
3. **Merge tests** on both sides — order independence and idempotence on the recorded fixtures.

A change is not done until both `dotnet test` and `npm test` pass with the new behavior covered in one of the shared files. If you can only express it in one side's tests, ask whether it really is shared behavior.

## Workflow for a shared change

1. Write the failing case first, in `scenario.json` or `vectors.json`.
2. Implement it in C#. Run `dotnet test`.
3. Port it to TypeScript, mirroring structure and naming so the two read side by side. Run `npm test`.
4. If the response shape changed, update `web/src/api/types.ts` and the views that read it.

## Snapshot format

`SnapshotCommand` writes `{ generatedAt, summary, runs, vulnerabilities }`, and `Engine.importSnapshot` reads it. Vulnerability records are trimmed (descriptions to 900 characters, references to 8, ranges to watched identities). Changing a field means changing both ends. Then bump `KEY` in `web/src/api/client.ts` if existing browsers must re-seed.
