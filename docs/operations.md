# Operations

## Configuration

Standard ASP.NET Core configuration (`appsettings.json`, environment variables with `__`, or `--Key=value` on the command line).

| Key | Default | Notes |
|---|---|---|
| `Database:Provider` | `sqlite` | `postgres` to use Npgsql; migrations then run on start. |
| `ConnectionStrings:Default` | `Data Source=blast-radius.db` | |
| `Jwt:Secret` | dev value | 32+ bytes. Must be changed anywhere shared. |
| `Jwt:Issuer`, `Jwt:Hours` | `blast-radius`, `12` | |
| `Sources:NvdApiKey` | empty | 50 requests/30 s instead of 5. Changes the NVD throttle from 6.5 s to 0.7 s between requests. |
| `Sources:GithubToken` | empty | Any token, no scopes. 5,000 requests/hour instead of 60. |
| `Sources:*BaseUrl`, `Sources:KevUrl` | public endpoints | Override for testing. |
| `Sources:FixtureDir` | unset | Answers every source from recorded files instead of the network. |
| `Ingestion:Scheduled` | `true` | Run 5 s after start, then every `IntervalHours`. |
| `Ingestion:IntervalHours` | `6` | |
| `Ingestion:ManualCooldownMinutes` | `10` | Minimum gap between manual runs (`ingestion.cooldown`). |
| `Webhooks:AllowPrivateTargets` | `false` | Local development only. |
| `Webhooks:TimeoutSeconds` | `5` | |
| `Cors:Origins` | `["http://localhost:5173"]` | Array; env form `Cors__Origins__0`. |
| `RateLimits:AuthPerMinute` | `20` | Per IP, on `/api/auth/*`. |

The web client reads one build-time variable: `VITE_API_URL`. When it is set, the client talks to that API. When it is unset, it runs the browser engine.

## Endpoints worth knowing

- `/health` — liveness.
- `/openapi/v1.json` — OpenAPI document.
- `GET /api/ingestion/status`, `GET /api/ingestion/runs` — what the last batch did per source and target.
- `POST /api/ingestion/run?wait=true` — manual run. It returns `ingestion.running` if one is in progress and `ingestion.cooldown` if one ran too recently.

## Deployments

- **Docker Compose** (`docker-compose.yml`): PostgreSQL 17, the API on `:8080`, and the web image (nginx) on `:5173` built with `API_URL`. It passes through `JWT_SECRET`, `NVD_API_KEY` and `GITHUB_TOKEN` from the environment. Both Dockerfiles build from the repo root because they need `shared/`.
- **GitHub Pages**: the static browser build from `web/dist`, deployed by CI from `main`.

## CI (`.github/workflows/ci.yml`)

It runs on pushes to `main`, on pull requests, daily at 07:00 UTC, and on manual dispatch.

1. **api**: `dotnet test` (includes the PostgreSQL scenario via Testcontainers).
2. **web** (after api):
   1. Outside PRs only, run a live `snapshot` with the job's `GITHUB_TOKEN` and the `NVD_API_KEY` secret, and copy it to `web/public/data/snapshot.json`. If it fails, CI warns and keeps the committed snapshot.
   2. `npm ci && npm test && npm run build`.
   3. Upload the Pages artifact.
3. **images**: `docker compose build`.
4. **deploy**: publish to Pages (`main`, non-PR only).

The daily schedule exists to refresh the snapshot the Pages build starts from. The refreshed snapshot is deployed, not committed. The committed `snapshot.json` is a fallback and goes stale over time. Refresh it by running the snapshot command locally and committing the result when that matters.

## Snapshot command

```bash
cd api
dotnet run --project src/BlastRadius.Api -c Release -- snapshot ../web/public/data/snapshot.json \
  --Ingestion:Scheduled=false "--ConnectionStrings:Default=Data Source=/tmp/snap.db"
```

Exit codes:
- `0` — success.
- `1` — couldn't start (another run was in progress).
- `2` — written, but some sources reported errors.

Use a throwaway database so the snapshot reflects one clean ingestion.

## Browser build state

The browser engine keeps its whole state in IndexedDB (`blast-radius` database, key `v2` in `client.ts`). Bump the key when the demo inventory or the stored state shape changes incompatibly, so existing visitors re-seed from the snapshot.
