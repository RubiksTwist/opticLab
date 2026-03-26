# PostgreSQL First-Pass Schema

This is the first practical database shape for OPTIC (Open Provenance Threat Intelligence Corpus) if the goal is:

1. searchable articles
2. canonical entity profiles
3. evidence-backed trend summaries
4. room for later AI-assisted retrieval without throwing away provenance

The DDL lives in [schema.sql](./schema.sql).

## Storage Model

Use a hybrid relational plus document model:

- Keep the current full `ExtractionResult` JSON in `article_extractions.result_json`.
- Flatten the important parts into `article_entity_mentions` and `article_relationships`.
- Resolve stable entities into `entities` and `entity_aliases`.
- Keep raw article HTML on disk for now, but store its paths on `articles`.

This avoids an early, brittle over-normalization step while still making the data queryable.

## Database Feed Policy

Operational rule:

- only the latest Mandiant normalization pipeline output should be loaded into PostgreSQL
- pure LLM outputs are benchmark artifacts, not database source-of-truth records
- hybrid pre-normalization outputs are benchmark artifacts, not database source-of-truth records
- when the normalizer version changes, re-normalize persisted results first and then reload PostgreSQL from that latest normalized set

Why:

- the database is intended to support search, entity profiles, and evidence-backed summaries
- mixing raw benchmark variants into the same operational store makes counts, trends, and relationship support misleading
- benchmark comparisons should remain file-based artifacts, not production search data

Practical implication:

- `optic.article_extractions` should contain one operational row per article for the latest normalized pipeline
- `pipeline_name` and `normalizer_version` remain useful for lineage, but not for maintaining multiple benchmark arms in the same database

## Core Tables

`articles`

- one row per article URL
- stores source metadata, article body text, parsed sections, ATT&CK table fragments, and raw archive paths
- is the base table for full-text search

`ingestion_runs`

- one row per batch or pipeline execution
- tracks pipeline label, extractor model, normalizer version, and run settings

`article_extractions`

- one operational row per article from the latest normalized pipeline result
- stores the full extraction JSON, raw LLM output, model used, and normalizer version
- preserves lineage for the normalized record that was actually loaded

`entities`

- canonical entity table
- one row per resolved actor, campaign, malware family, service, technique, CVE, IOC, or victim geography concept
- unique on `(entity_type, normalized_name)`

`entity_aliases`

- alternate names for canonical entities
- lets `UNC2814`, branded names, or tool aliases collapse onto a single entity

`article_entity_mentions`

- the most important table for search and analytics
- one row per extracted mention from one extraction result
- stores `entity_type`, mention role, normalized name, provenance, confidence, source quote, and extra per-mention attributes

`article_relationships`

- stores cross-entity assertions from a single article
- examples:
  - actor `uses` malware
  - actor `targets` sector
  - campaign `attributed_to` actor
  - actor `distinct_from` another actor
  - actor `abuses_service` legitimate service

## Provenance Rules

The schema includes a `provenance` field with three intended values:

- `explicit`: directly stated in the article or extracted from an explicit identifier
- `derived`: deterministic transform from article evidence, heuristics, or the normalizer
- `inferred`: model inference that is plausible but not directly stated verbatim

That split matters if you later want AI to write summaries without overstating weak evidence.

## Why This Shape Fits The Current Pipeline

Current persisted outputs are article-scoped JSON documents with rich field-level quotes and confidence. The DDL keeps that intact in `article_extractions.result_json`, so no information is lost.

At the same time, your actual product needs are not document storage. They are:

- search all articles mentioning a tool, actor, technique, or country
- compare entity support across articles
- compute counts over time
- gate "top X" claims on support thresholds

Those use cases want flattened mention and relationship tables.

The database should therefore ingest only the normalized search-ready corpus, not every benchmark variant produced during experimentation.

## Expected Mapping From Current `ExtractionResult`

`source`

- maps to `articles`

top-level extraction metadata

- maps to `article_extractions`

`threat_actors`, `campaigns`, `malware`, `cves`, `iocs`, `victims`, `legitimate_services_abused`

- map to `article_entity_mentions`

cross-links inside the extraction

- map to `article_relationships`

Examples:

- `Campaign.actor_name` becomes `campaign attributed_to threat_actor`
- `ThreatActor.aliases` becomes canonical alias rows or unresolved alias mentions
- `distinct_from` becomes a negative relationship row
- `confirmed_victim_count` stays in `attributes_json` until it earns a dedicated analytic table

## Example Queries This Supports

Search recent articles that mention a specific actor:

```sql
select a.publication_date, a.title, a.source_url
from optic.articles a
join optic.article_entity_mentions m on m.article_id = a.article_id
where m.entity_type = 'threat_actor'
  and m.normalized_name = 'unc2814'
order by a.publication_date desc;
```

Top ATT&CK techniques by article support in the last 12 months:

```sql
select m.raw_name as technique_name, m.normalized_name, count(distinct m.article_id) as article_count
from optic.article_entity_mentions m
join optic.articles a on a.article_id = m.article_id
where m.entity_type = 'technique'
  and a.publication_date >= current_date - interval '12 months'
group by m.raw_name, m.normalized_name
order by article_count desc, technique_name asc
limit 25;
```

Trend-safe entity rollups:

```sql
select *
from optic.entity_article_support
where article_count >= 5
order by article_count desc, display_name asc;
```

## Deliberate Omissions

This first pass does not include:

- embeddings or `pgvector`
- materialized rollup tables
- document chunk tables
- a canonical relationship resolver
- migration tooling

Those can be added later. The base schema is intentionally enough to move from ad hoc JSON files to queryable article and entity search.

## Recommended Next Step

After this DDL, the next implementation step should be a loader that:

1. upserts `articles`
2. writes one row into `article_extractions`
3. projects extraction fields into `article_entity_mentions`
4. projects linked assertions into `article_relationships`
5. optionally resolves mentions into `entities` and `entity_aliases`

That is the minimum needed to move from benchmark artifacts to a real search surface.
