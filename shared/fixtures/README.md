# Fixtures

Real responses from the NVD CVE API 2.0, the GitHub Advisory Database REST API, CISA KEV (cisagov/kev-data mirror)
and FIRST EPSS, recorded on 2026-11-12 for two watched products: Ollama and Ray.

- `day2/` is the data as fetched. The KEV file keeps only four entries of the catalog.
- `day1/` is the same data before two real events, reconstructed by removal:
  - CVE-2025-62593 (Ray) was added to KEV on 2026-08-17, so it is absent from `day1/kev.json`.
  - GHSA-hhrp-gw25-jr43 had no CVE yet: its `cve_id` is null and NVD does not list CVE-2026-57516.

Ingesting day1 then day2 exercises KEV escalation and the re-keying of a GitHub-only advisory into a CVE record.
File names: `nvd/<vendor>_<product>.json`, `ghsa/<ecosystem>/<package with / as _>.json`.
