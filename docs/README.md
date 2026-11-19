# Developer documentation

The top-level [README](../README.md) explains what Blast Radius does and how to run it. These pages explain how it is built and how to change it safely.

| Page | Read it when |
|---|---|
| [architecture.md](architecture.md) | You need the big picture: components, the two runtimes, the data model, the ingestion pipeline. |
| [parity.md](parity.md) | You change anything in the API or the browser engine. Which files mirror which, and what keeps them honest. |
| [domain-rules.md](domain-rules.md) | You touch deduplication, version matching, danger scores or alerts. The invariants and where they live. |
| [testing.md](testing.md) | You add or debug tests: the contract scenario format, vectors, fixtures. |
| [operations.md](operations.md) | You configure, deploy or debug a running instance: settings, CI, the daily snapshot. |
| [how-to.md](how-to.md) | You have a concrete task: add a product, an endpoint, a migration, a matching rule. |

The PNG files in this folder are screenshots used by the top-level README.
