# OPTICLab

Public release bundle for OPTIC database materials.

This folder is intended to become the public GitHub repo contents for the database release. The static dashboard, schema, and orientation docs live in the repo. The PostgreSQL dump is staged under `release-assets/` so it can be uploaded as a GitHub Release asset instead of being committed into source control.

## Current corpus framing

Use this distinction consistently in public copy:

- `571` normalized Mandiant archive articles are preserved on disk.
- `402` corpus-policy-filtered articles make up the current analyst-usable operational corpus.
- Preferred wording: `402 analyst-usable reports in the production corpus, built from a 571-report normalized archive.`

This distinction matters because the operational corpus is the cleaner production search set. Archive-only articles remain preserved for review and reprocessing but are intentionally excluded from the production corpus.

## Public release snapshot

The downloadable PostgreSQL dump in `release-assets/` is still the historical public snapshot dated March 25, 2026.

## Included

- `index.html`: static dashboard copy reflecting the current operational corpus / normalized archive distinction.
- `iran.html`: companion report linked from the dashboard and served as `/iran` on Cloudflare Pages.
- `schema.sql`: PostgreSQL DDL for the OPTIC schema.
- `schema-overview.md`: table-by-table explanation of the data model.
- `release-assets/optic-postgres-2026-03-25.dump`: PostgreSQL custom-format dump for the March 25 public snapshot.
- `release-assets/SHA256SUMS.txt`: checksum manifest for the dump.

## Historical Snapshot Metrics

Snapshot source: live `optic` PostgreSQL database on March 25, 2026.

| Metric | Value |
| --- | --- |
| Reports indexed | `371` |
| Findings with source quotes | `16,998 / 17,091` (`99.5%`) |
| Explicit findings | `14,308 / 17,091` (`83.7%`) |
| Reports with named threat actors | `282 / 371` (`76.0%`) |
| Reports with sector targeting | `281 / 371` (`75.7%`) |
| Searchable IOCs | `6,624` |
| Connected relationships | `1,041` |

Additional release context:

- The current working corpus has moved beyond this snapshot: `402` analyst-usable operational reports built from a `571`-article normalized archive.
- The downloadable asset remains the older March 25, 2026 PostgreSQL snapshot with `371` reports loaded into PostgreSQL.
- Public copy should describe this release as a historical snapshot, not as the current production corpus.

## Restore

Requirements:

- PostgreSQL 16 client tools (`createdb` and `pg_restore`)
- An empty target database

Restore the release asset into a fresh database:

```bash
createdb opticlab
pg_restore --clean --if-exists --no-owner --no-privileges -d opticlab release-assets/optic-postgres-2026-03-25.dump
```

If you only want to inspect the schema before restoring data, review `schema.sql` directly or apply it to an empty database first.

## Licensing

Frontend and schema code in this repository are licensed under the MIT License. Database snapshots, release assets, and written analytical content in this repository are licensed under CC BY-NC 4.0.

Underlying source reporting, trademarks, and third-party intelligence content remain the property of their respective owners, including Mandiant / Google Threat Intelligence.

## Release Notes

- Upload `release-assets/optic-postgres-2026-03-25.dump` as the GitHub Release asset for this snapshot.
- Keep `schema.sql`, `schema-overview.md`, `index.html`, and this README in the public repo.
- Do not describe the March 25 dump as the current production corpus. Public copy should distinguish the `402`-report operational corpus from the older `371`-report dump snapshot.
- Verify the release asset against `release-assets/SHA256SUMS.txt` after upload.
