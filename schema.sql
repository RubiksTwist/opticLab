-- First-pass PostgreSQL schema for OPTIC article search and structured threat
-- intelligence storage.
--
-- Design goals:
-- 1. Keep the full per-article ExtractionResult as jsonb for lossless storage.
-- 2. Flatten entities and relationships into queryable tables for search and
--    trend analysis.
-- 3. Preserve provenance, confidence, and source quotes for every mention.
-- 4. Support article search first; embeddings can be added later.

create extension if not exists pgcrypto;
create extension if not exists pg_trgm;

create schema if not exists optic;

create or replace function optic.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

create table if not exists optic.articles (
    article_id uuid primary key default gen_random_uuid(),
    source_name text not null,
    vendor text not null,
    source_url text not null unique,
    title text not null,
    publication_date date,
    access_date date,
    authors text[] not null default '{}'::text[],
    body_text text,
    sections_json jsonb not null default '[]'::jsonb,
    attack_table_json jsonb,
    article_metadata_json jsonb not null default '{}'::jsonb,
    raw_html_path text,
    raw_meta_path text,
    raw_fetch_timestamp timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint articles_source_name_not_blank check (btrim(source_name) <> ''),
    constraint articles_vendor_not_blank check (btrim(vendor) <> ''),
    constraint articles_source_url_not_blank check (btrim(source_url) <> '')
);

create table if not exists optic.ingestion_runs (
    run_id uuid primary key default gen_random_uuid(),
    source_name text not null,
    pipeline_name text not null,
    extractor_model text,
    normalizer_version text,
    code_version text,
    settings_json jsonb not null default '{}'::jsonb,
    started_at timestamptz not null default now(),
    completed_at timestamptz,
    notes text,
    constraint ingestion_runs_source_name_not_blank check (btrim(source_name) <> ''),
    constraint ingestion_runs_pipeline_name_not_blank check (btrim(pipeline_name) <> '')
);

create table if not exists optic.article_extractions (
    extraction_id uuid primary key default gen_random_uuid(),
    article_id uuid not null references optic.articles(article_id) on delete cascade,
    run_id uuid references optic.ingestion_runs(run_id) on delete set null,
    pipeline_name text not null,
    model_used text not null default '',
    normalizer_version text not null default '',
    extraction_schema_version text not null default 'extraction_result_v1',
    extraction_timestamp timestamptz not null,
    result_json jsonb not null,
    raw_llm_output text,
    created_at timestamptz not null default now(),
    constraint article_extractions_pipeline_name_not_blank check (btrim(pipeline_name) <> ''),
    constraint article_extractions_result_json_object check (jsonb_typeof(result_json) = 'object')
);

create table if not exists optic.entities (
    entity_id uuid primary key default gen_random_uuid(),
    entity_type text not null,
    canonical_name text not null,
    normalized_name text not null,
    description text,
    entity_metadata_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint entities_entity_type_check check (
        entity_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ),
    constraint entities_canonical_name_not_blank check (btrim(canonical_name) <> ''),
    constraint entities_normalized_name_not_blank check (btrim(normalized_name) <> ''),
    unique (entity_type, normalized_name)
);

create table if not exists optic.entity_aliases (
    alias_id uuid primary key default gen_random_uuid(),
    entity_id uuid not null references optic.entities(entity_id) on delete cascade,
    alias_name text not null,
    normalized_alias_name text not null,
    alias_type text not null default 'alias',
    created_at timestamptz not null default now(),
    constraint entity_aliases_alias_name_not_blank check (btrim(alias_name) <> ''),
    constraint entity_aliases_normalized_alias_name_not_blank check (btrim(normalized_alias_name) <> ''),
    unique (entity_id, normalized_alias_name)
);

create table if not exists optic.article_entity_mentions (
    mention_id uuid primary key default gen_random_uuid(),
    article_id uuid not null references optic.articles(article_id) on delete cascade,
    extraction_id uuid not null references optic.article_extractions(extraction_id) on delete cascade,
    entity_id uuid references optic.entities(entity_id) on delete set null,
    entity_type text not null,
    mention_role text not null,
    raw_name text not null,
    normalized_name text not null,
    provenance text not null default 'explicit',
    confidence numeric(4,3) not null,
    source_quote text not null default '',
    attributes_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint article_entity_mentions_entity_type_check check (
        entity_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ),
    constraint article_entity_mentions_mention_role_not_blank check (btrim(mention_role) <> ''),
    constraint article_entity_mentions_raw_name_not_blank check (btrim(raw_name) <> ''),
    constraint article_entity_mentions_normalized_name_not_blank check (btrim(normalized_name) <> ''),
    constraint article_entity_mentions_provenance_check check (
        provenance in ('explicit', 'derived', 'inferred')
    ),
    constraint article_entity_mentions_confidence_check check (
        confidence >= 0 and confidence <= 1
    )
);

create table if not exists optic.article_relationships (
    relationship_id uuid primary key default gen_random_uuid(),
    article_id uuid not null references optic.articles(article_id) on delete cascade,
    extraction_id uuid not null references optic.article_extractions(extraction_id) on delete cascade,
    subject_entity_id uuid references optic.entities(entity_id) on delete set null,
    subject_type text not null,
    subject_name text not null,
    predicate text not null,
    object_entity_id uuid references optic.entities(entity_id) on delete set null,
    object_type text not null,
    object_name text not null,
    provenance text not null default 'explicit',
    confidence numeric(4,3) not null,
    source_quote text not null default '',
    attributes_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint article_relationships_subject_type_check check (
        subject_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ),
    constraint article_relationships_object_type_check check (
        object_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ),
    constraint article_relationships_subject_name_not_blank check (btrim(subject_name) <> ''),
    constraint article_relationships_predicate_not_blank check (btrim(predicate) <> ''),
    constraint article_relationships_object_name_not_blank check (btrim(object_name) <> ''),
    constraint article_relationships_provenance_check check (
        provenance in ('explicit', 'derived', 'inferred')
    ),
    constraint article_relationships_confidence_check check (
        confidence >= 0 and confidence <= 1
    )
);

create index if not exists idx_articles_publication_date
    on optic.articles (publication_date desc);

create index if not exists idx_articles_vendor_publication_date
    on optic.articles (vendor, publication_date desc);

create index if not exists idx_articles_title_trgm
    on optic.articles using gin (title gin_trgm_ops);

create index if not exists idx_articles_full_text
    on optic.articles
    using gin (to_tsvector('english', coalesce(title, '') || ' ' || coalesce(body_text, '')));

create index if not exists idx_article_extractions_article_pipeline_timestamp
    on optic.article_extractions (article_id, pipeline_name, extraction_timestamp desc);

create index if not exists idx_article_extractions_result_json
    on optic.article_extractions using gin (result_json jsonb_path_ops);

create index if not exists idx_entities_type_normalized_name
    on optic.entities (entity_type, normalized_name);

create index if not exists idx_entities_canonical_name_trgm
    on optic.entities using gin (canonical_name gin_trgm_ops);

create index if not exists idx_entity_aliases_normalized_alias_name
    on optic.entity_aliases (normalized_alias_name);

create index if not exists idx_article_entity_mentions_entity
    on optic.article_entity_mentions (entity_id, article_id);

create index if not exists idx_article_entity_mentions_lookup
    on optic.article_entity_mentions (entity_type, normalized_name);

create index if not exists idx_article_entity_mentions_extraction
    on optic.article_entity_mentions (extraction_id);

create index if not exists idx_article_relationships_subject
    on optic.article_relationships (subject_entity_id, article_id);

create index if not exists idx_article_relationships_object
    on optic.article_relationships (object_entity_id, article_id);

create index if not exists idx_article_relationships_predicate
    on optic.article_relationships (predicate);

drop trigger if exists tr_articles_set_updated_at on optic.articles;
create trigger tr_articles_set_updated_at
before update on optic.articles
for each row
execute function optic.set_updated_at();

drop trigger if exists tr_entities_set_updated_at on optic.entities;
create trigger tr_entities_set_updated_at
before update on optic.entities
for each row
execute function optic.set_updated_at();

create or replace view optic.latest_article_extractions as
select distinct on (article_id, pipeline_name)
    extraction_id,
    article_id,
    run_id,
    pipeline_name,
    model_used,
    normalizer_version,
    extraction_schema_version,
    extraction_timestamp,
    result_json,
    raw_llm_output,
    created_at
from optic.article_extractions
order by article_id, pipeline_name, extraction_timestamp desc, created_at desc;

create or replace view optic.entity_article_support as
select
    coalesce(e.entity_id::text, m.entity_type || ':' || m.normalized_name) as entity_key,
    e.entity_id,
    m.entity_type,
    coalesce(e.canonical_name, min(m.raw_name)) as display_name,
    m.normalized_name,
    count(distinct m.article_id) as article_count,
    count(distinct case when m.provenance = 'explicit' then m.article_id end) as explicit_article_count,
    min(a.publication_date) as first_publication_date,
    max(a.publication_date) as last_publication_date
from optic.article_entity_mentions m
join optic.articles a on a.article_id = m.article_id
left join optic.entities e on e.entity_id = m.entity_id
group by
    coalesce(e.entity_id::text, m.entity_type || ':' || m.normalized_name),
    e.entity_id,
    e.canonical_name,
    m.entity_type,
    m.normalized_name;
