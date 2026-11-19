# Testing

```bash
cd api && dotnet test     # xUnit v3 on Microsoft.Testing.Platform
cd web && npm test        # Vitest
```

No test touches the network. Sources are answered from `shared/fixtures/`.

## Suites

| Test | API (`api/tests/BlastRadius.Tests/`) | Web (`web/src/engine/`) |
|---|---|---|
| Contract scenario | `ContractTests.cs` (SQLite, and PostgreSQL via Testcontainers) | `contract.test.ts` |
| Matching vectors | `VectorTests.cs` | `vectors.test.ts` |
| Merge order-independence / idempotence | `MergeTests.cs` | `merge.test.ts` |
| Webhook delivery, failure, refusal | `NotifierTests.cs` | — (browser doesn't send) |
| SSRF at resolve time, tokens, rate limits, cooldown | `SecurityTests.cs` | — |

`ApiFactory` boots the real app via `WebApplicationFactory<Program>` with:
- a private in-memory SQLite database (or a PostgreSQL connection string);
- `Sources:FixtureDir` set to `day1`;
- scheduling off;
- no manual-sync cooldown;
- a high auth rate limit;
- a fixed JWT secret.

`factory.UseFixtures("day2")` switches the recorded data mid-test.

The PostgreSQL scenario is skipped when Docker isn't available. CI always has Docker. If you change the EF model or a query that might behave differently on PostgreSQL, run it with Docker locally or rely on CI.

## The contract scenario (`shared/contract/scenario.json`)

A list of HTTP steps run in order against one fresh backend. Step shape:

```jsonc
{
  "name": "a site from a preset",
  "as": "alex",                         // send saved token "token:alex" as Bearer
  "method": "POST",
  "path": "/api/sites/{office}",        // {key} interpolates a saved value
  "body": { "siteId": "{office}" },     // whole-string "{key}" substitutes the saved JSON value (keeps its type)
  "expect": {
    "status": 201,
    "code": "site.limit",               // problem-details code, for errors
    "json": {
      "$.lat": -23.55,                  // equality; numbers compared by value
      "$.items#": 3,                    // trailing # = array length / object key count
      "$.items[0].score": { "gte": 7 }, // also gt, lt
      "$.detail": { "contains": "KEV" }
    }
  },
  "save": { "office": "$.id" }          // remember a value for later steps
}
```

A step of the form `{ "fixtures": "day2" }` switches the recorded source data.

Paths support only `$.prop`, `[n]` and a trailing `#`. Both runners implement this small dialect (`ContractRunner.Select` / `select` in `contract.test.ts`). Extend both if you need more.

Guidelines:

- Add steps for every observable behavior change: new route, new field, new error code, new rule.
- Assert outcomes the user cares about (ids, counts, codes), not incidental fields like timestamps.
- Steps share state. Inserting a step in the middle can shift counts asserted later; re-run both suites.
- The catalog step asserts product and preset counts. Adding a product to `catalog.json` means updating it.

## Vectors (`shared/vectors.json`)

Sections, each asserted by both suites:

- `compare` — `[a, b, sign]`, checked in both directions.
- `ghsaRanges` — a GitHub range string, a version, the expected status.
- `nvdCriteria` — a CPE match object (criteria plus `versionStart*`/`versionEnd*`), a version, the expected status.
- `precedence` — several ranges from different sources, a version, the expected best status.
- `packageNames` — `[ecosystem, a, b, same]`.
- `danger` — inputs, then the expected score and level.

A new matching rule should come with vectors that would fail without it, ideally taken from the real advisory that motivated it.

## Fixtures (`shared/fixtures/`)

Real responses recorded on 2026-11-12 for Ollama and Ray. `day2` is the data as fetched. `day1` is the same data with two real events removed: a KEV addition, and a GHSA receiving its CVE. See `shared/fixtures/README.md`.

The file layout is shared by `FixtureHandler` (C#) and `fixtureFetcher` (TS):

```text
nvd/<vendor>_<product>.json
ghsa/<ecosystem>/<package with / replaced by _>.json
kev.json
epss.json
```

A product without a fixture file gets an empty result. Don't re-record fixtures casually. The scenario's expectations are tied to their exact contents. If you must, record both days consistently and update the scenario and the fixtures README.
