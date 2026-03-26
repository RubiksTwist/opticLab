# OPTICLab

Public release bundle for the OPTIC database snapshot dated March 25, 2026.

This folder is intended to become the public GitHub repo contents for the database release. The static dashboard, schema, and orientation docs live in the repo. The actual PostgreSQL dump is staged under `release-assets/` so it can be uploaded as a GitHub Release asset instead of being committed into source control.

## Included

- `index.html`: static dashboard for the March 25, 2026 OPTIC snapshot.
- `iran.html`: companion report linked from the dashboard and served as `/iran` on Cloudflare Pages.
- `schema.sql`: PostgreSQL DDL for the OPTIC schema.
- `schema-overview.md`: table-by-table explanation of the data model.
- `release-assets/optic-postgres-2026-03-25.dump`: PostgreSQL custom-format dump for the public release.
- `release-assets/SHA256SUMS.txt`: checksum manifest for the dump.

## Seven Headline Metrics

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

- `524` source reports have been collected in the archive.
- `371` of those reports are currently loaded into PostgreSQL.
- `153` collected reports are not yet included in this snapshot.

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
- Verify the release asset against `release-assets/SHA256SUMS.txt` after upload.
