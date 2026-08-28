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
    relationship_rule_version text not null default '',
    extraction_schema_version text not null default 'extraction_result_v4',
    extraction_timestamp timestamptz not null,
    result_json jsonb not null,
    raw_llm_output text,
    created_at timestamptz not null default now(),
    constraint article_extractions_pipeline_name_not_blank check (btrim(pipeline_name) <> ''),
    constraint article_extractions_result_json_object check (jsonb_typeof(result_json) = 'object')
);

alter table if exists optic.article_extractions
    add column if not exists relationship_rule_version text not null default '';

alter table if exists optic.article_extractions
    alter column extraction_schema_version set default 'extraction_result_v4';

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
            'product',
            'platform',
            'detection_artifact',
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
            'product',
            'platform',
            'detection_artifact',
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
    subject_normalized_name text not null,
    predicate text not null,
    object_entity_id uuid references optic.entities(entity_id) on delete set null,
    object_type text not null,
    object_name text not null,
    object_normalized_name text not null,
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
            'product',
            'platform',
            'detection_artifact',
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
            'product',
            'platform',
            'detection_artifact',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ),
    constraint article_relationships_subject_name_not_blank check (btrim(subject_name) <> ''),
    constraint article_relationships_subject_normalized_name_not_blank check (
        btrim(subject_normalized_name) <> ''
    ),
    constraint article_relationships_predicate_not_blank check (btrim(predicate) <> ''),
    constraint article_relationships_object_name_not_blank check (btrim(object_name) <> ''),
    constraint article_relationships_object_normalized_name_not_blank check (
        btrim(object_normalized_name) <> ''
    ),
    constraint article_relationships_provenance_check check (
        provenance in ('explicit', 'derived', 'inferred')
    ),
    constraint article_relationships_confidence_check check (
        confidence >= 0 and confidence <= 1
    )
);

alter table if exists optic.entities
    drop constraint if exists entities_entity_type_check;

alter table if exists optic.entities
    add constraint entities_entity_type_check check (
        entity_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'product',
            'platform',
            'detection_artifact',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ) not valid;

alter table if exists optic.article_entity_mentions
    drop constraint if exists article_entity_mentions_entity_type_check;

alter table if exists optic.article_entity_mentions
    add constraint article_entity_mentions_entity_type_check check (
        entity_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'product',
            'platform',
            'detection_artifact',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ) not valid;

alter table if exists optic.article_relationships
    drop constraint if exists article_relationships_subject_type_check;

alter table if exists optic.article_relationships
    add constraint article_relationships_subject_type_check check (
        subject_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'product',
            'platform',
            'detection_artifact',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ) not valid;

alter table if exists optic.article_relationships
    drop constraint if exists article_relationships_object_type_check;

alter table if exists optic.article_relationships
    add constraint article_relationships_object_type_check check (
        object_type in (
            'threat_actor',
            'campaign',
            'malware',
            'tool',
            'service',
            'product',
            'platform',
            'detection_artifact',
            'technique',
            'cve',
            'ioc',
            'victim_sector',
            'victim_region',
            'victim_country'
        )
    ) not valid;

alter table if exists optic.article_relationships
    drop constraint if exists article_relationships_predicate_allowed_check;

alter table if exists optic.article_relationships
    add column if not exists subject_normalized_name text;

alter table if exists optic.article_relationships
    add column if not exists object_normalized_name text;

update optic.article_relationships
set
    subject_normalized_name = trim(
        regexp_replace(
            regexp_replace(
                replace(lower(subject_name), 'â€™', ''''),
                '[^a-z0-9._:+#/@-]+',
                ' ',
                'g'
            ),
            '\s+',
            ' ',
            'g'
        )
    ),
    object_normalized_name = trim(
        regexp_replace(
            regexp_replace(
                replace(lower(object_name), 'â€™', ''''),
                '[^a-z0-9._:+#/@-]+',
                ' ',
                'g'
            ),
            '\s+',
            ' ',
            'g'
        )
    )
where coalesce(btrim(subject_normalized_name), '') = ''
   or coalesce(btrim(object_normalized_name), '') = '';

alter table if exists optic.article_relationships
    alter column subject_normalized_name set not null;

alter table if exists optic.article_relationships
    alter column object_normalized_name set not null;

alter table if exists optic.article_relationships
    add constraint article_relationships_predicate_allowed_check check (
        predicate in (
            'abuses_service',
            'attributed_to',
            'detected_by',
            'deploys',
            'distinct_from',
            'exploits',
            'suspected_targets_country',
            'targets_country',
            'targets_platform',
            'targets_product',
            'targets_region',
            'targets_sector',
            'uses'
        )
    ) not valid;

create table if not exists optic.attack_catalog (
    attack_id text not null,
    domain text not null,
    name text not null,
    stix_id text,
    is_subtechnique boolean not null default false,
    is_deprecated boolean not null default false,
    is_revoked boolean not null default false,
    attack_version text not null default 'current',
    metadata_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (attack_id, domain, attack_version),
    constraint attack_catalog_attack_id_not_blank check (btrim(attack_id) <> ''),
    constraint attack_catalog_domain_not_blank check (btrim(domain) <> ''),
    constraint attack_catalog_name_not_blank check (btrim(name) <> '')
);

create table if not exists optic.attack_mappings (
    mapping_id uuid primary key default gen_random_uuid(),
    source_attack_id text not null,
    source_domain text,
    mapping_type text not null,
    target_attack_id text,
    target_domain text,
    confidence text not null,
    reason text not null,
    metadata_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint attack_mappings_source_attack_id_not_blank check (btrim(source_attack_id) <> ''),
    constraint attack_mappings_mapping_type_not_blank check (btrim(mapping_type) <> ''),
    constraint attack_mappings_confidence_check check (confidence in ('high', 'medium', 'low')),
    constraint attack_mappings_reason_not_blank check (btrim(reason) <> '')
);

create table if not exists optic.attack_backfill_runs (
    backfill_run_id uuid primary key default gen_random_uuid(),
    started_at timestamptz not null default now(),
    completed_at timestamptz,
    attack_reference_version text,
    mapping_rule_version text not null,
    scope_type text not null,
    scope_ref text,
    status text not null,
    summary_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint attack_backfill_runs_mapping_rule_version_not_blank check (btrim(mapping_rule_version) <> ''),
    constraint attack_backfill_runs_scope_type_not_blank check (btrim(scope_type) <> ''),
    constraint attack_backfill_runs_status_not_blank check (btrim(status) <> '')
);

create table if not exists optic.article_technique_facts (
    fact_id uuid primary key default gen_random_uuid(),
    article_id uuid not null references optic.articles(article_id) on delete cascade,
    extraction_id uuid not null references optic.article_extractions(extraction_id) on delete cascade,
    source_attack_id text not null,
    source_name text,
    source_tactic text,
    source_domain text,
    technique_status text not null,
    current_attack_id text,
    current_name text,
    current_tactic text,
    current_domain text,
    replacement_attack_id text,
    mapping_confidence text not null,
    mapping_reason text not null,
    source_quote text not null default '',
    confidence numeric(4,3) not null,
    provenance text not null default 'explicit',
    attributes_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint article_technique_facts_source_attack_id_not_blank check (btrim(source_attack_id) <> ''),
    constraint article_technique_facts_technique_status_check check (
        technique_status in ('current', 'deprecated', 'revoked', 'legacy_pre_attack', 'unknown')
    ),
    constraint article_technique_facts_mapping_confidence_check check (
        mapping_confidence in ('high', 'medium', 'low')
    ),
    constraint article_technique_facts_mapping_reason_not_blank check (btrim(mapping_reason) <> ''),
    constraint article_technique_facts_provenance_check check (
        provenance in ('explicit', 'derived', 'inferred')
    ),
    constraint article_technique_facts_confidence_check check (
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

create index if not exists idx_article_relationships_extraction
    on optic.article_relationships (extraction_id);

create index if not exists idx_article_relationships_subject_lookup
    on optic.article_relationships (subject_type, subject_normalized_name);

create index if not exists idx_article_relationships_object_lookup
    on optic.article_relationships (object_type, object_normalized_name);

create index if not exists idx_attack_catalog_attack_id
    on optic.attack_catalog (attack_id, domain);

create index if not exists idx_attack_catalog_name_trgm
    on optic.attack_catalog using gin (name gin_trgm_ops);

create index if not exists idx_attack_mappings_source
    on optic.attack_mappings (source_attack_id, source_domain);

create unique index if not exists idx_attack_mappings_dedupe
    on optic.attack_mappings (
        source_attack_id,
        coalesce(source_domain, ''),
        mapping_type,
        coalesce(target_attack_id, ''),
        coalesce(target_domain, '')
    );

create index if not exists idx_article_technique_facts_article
    on optic.article_technique_facts (article_id, extraction_id);

create index if not exists idx_article_technique_facts_source_attack
    on optic.article_technique_facts (source_attack_id, source_domain);

create index if not exists idx_article_technique_facts_current_attack
    on optic.article_technique_facts (current_attack_id, current_domain);

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

drop trigger if exists tr_attack_catalog_set_updated_at on optic.attack_catalog;
create trigger tr_attack_catalog_set_updated_at
before update on optic.attack_catalog
for each row
execute function optic.set_updated_at();

drop trigger if exists tr_attack_mappings_set_updated_at on optic.attack_mappings;
create trigger tr_attack_mappings_set_updated_at
before update on optic.attack_mappings
for each row
execute function optic.set_updated_at();

drop trigger if exists tr_attack_backfill_runs_set_updated_at on optic.attack_backfill_runs;
create trigger tr_attack_backfill_runs_set_updated_at
before update on optic.attack_backfill_runs
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
    created_at,
    relationship_rule_version
from optic.article_extractions
order by article_id, pipeline_name, extraction_timestamp desc, created_at desc;

comment on view optic.latest_article_extractions is
'Debugging view: latest extraction per (article_id, pipeline_name). Analytics should prefer optic.preferred_article_extractions.';

create or replace view optic.preferred_article_extractions as
select distinct on (article_id)
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
    created_at,
    relationship_rule_version
from optic.article_extractions
order by
    article_id,
    case pipeline_name
        when 'source_pack_unc3886_google' then 110
        when 'source_pack_unc6201_google' then 110
        when 'mandiant_normalized' then 100
        when 'unit42_hybrid' then 95
        when 'microsoft_hybrid' then 95
        when 'talos_hybrid' then 95
        when 'sophos_hybrid' then 95
        when 'crowdstrike_hybrid' then 95
        when 'hybrid_post_normalization' then 90
        when 'hybrid' then 80
        when 'hybrid_pre_normalization' then 70
        when 'pure_llm_gpt_4o' then 60
        when 'pure_llm_gpt_4o_mini' then 55
        when 'pure_llm' then 50
        else 0
    end desc,
    extraction_timestamp desc,
    created_at desc;

comment on view optic.preferred_article_extractions is
'Operational analytics view: exactly one preferred extraction per article selected by pipeline priority, then recency.';

drop view if exists optic.relationship_vendor_support;
create view optic.relationship_vendor_support as
select
    r.subject_type,
    coalesce(subject_entity.canonical_name, r.subject_name) as subject_name,
    r.subject_normalized_name,
    r.subject_entity_id,
    r.predicate,
    r.object_type,
    coalesce(object_entity.canonical_name, r.object_name) as object_name,
    r.object_normalized_name,
    r.object_entity_id,
    count(distinct a.vendor) as vendor_count,
    array_agg(distinct a.vendor order by a.vendor) as vendors,
    count(distinct r.article_id) as article_count,
    max(a.publication_date) as last_seen
from optic.article_relationships r
join optic.preferred_article_extractions pae on pae.extraction_id = r.extraction_id
join optic.articles a on a.article_id = pae.article_id
left join optic.entities subject_entity on subject_entity.entity_id = r.subject_entity_id
left join optic.entities object_entity on object_entity.entity_id = r.object_entity_id
group by
    r.subject_type,
    coalesce(subject_entity.canonical_name, r.subject_name),
    r.subject_normalized_name,
    r.subject_entity_id,
    r.predicate,
    r.object_type,
    coalesce(object_entity.canonical_name, r.object_name),
    r.object_normalized_name,
    r.object_entity_id;

comment on view optic.relationship_vendor_support is
'Cross-vendor support for canonical relationship claims using one preferred extraction per article.';

drop view if exists optic.actor_relationship_profile;
create view optic.actor_relationship_profile as
select
    coalesce(subject_entity.canonical_name, r.subject_name) as actor,
    r.subject_normalized_name as actor_normalized_name,
    r.subject_entity_id as actor_entity_id,
    r.predicate,
    r.object_type,
    coalesce(object_entity.canonical_name, r.object_name) as object_name,
    r.object_normalized_name,
    r.object_entity_id,
    count(distinct a.vendor) as vendor_count,
    array_agg(distinct a.vendor order by a.vendor) as vendors,
    count(distinct r.article_id) as article_count,
    round(avg(r.confidence), 3) as avg_confidence,
    max(a.publication_date) as last_reported
from optic.article_relationships r
join optic.preferred_article_extractions pae on pae.extraction_id = r.extraction_id
join optic.articles a on a.article_id = pae.article_id
left join optic.entities subject_entity on subject_entity.entity_id = r.subject_entity_id
left join optic.entities object_entity on object_entity.entity_id = r.object_entity_id
where r.subject_type = 'threat_actor'
group by
    coalesce(subject_entity.canonical_name, r.subject_name),
    r.subject_normalized_name,
    r.subject_entity_id,
    r.predicate,
    r.object_type,
    coalesce(object_entity.canonical_name, r.object_name),
    r.object_normalized_name,
    r.object_entity_id;

comment on view optic.actor_relationship_profile is
'Actor-centric relationship aggregate built on preferred extractions for profile and support queries.';

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

create or replace view optic.quoted_entity_mention_evidence as
select
    m.mention_id,
    m.article_id,
    m.extraction_id,
    a.source_name,
    a.vendor,
    a.source_url,
    a.title,
    a.publication_date,
    e.pipeline_name,
    e.model_used,
    e.normalizer_version,
    e.relationship_rule_version,
    e.extraction_timestamp,
    m.entity_id,
    m.entity_type,
    m.mention_role,
    coalesce(entity.canonical_name, m.raw_name) as display_name,
    m.raw_name,
    m.normalized_name,
    m.provenance,
    m.confidence,
    m.source_quote,
    m.attributes_json
from optic.article_entity_mentions m
join optic.articles a on a.article_id = m.article_id
join optic.article_extractions e on e.extraction_id = m.extraction_id
left join optic.entities entity on entity.entity_id = m.entity_id
where btrim(m.source_quote) <> '';

comment on view optic.quoted_entity_mention_evidence is
'Evidence-first mention view with direct quotes, source metadata, and extraction lineage.';

create or replace view optic.quoted_relationship_evidence as
select
    r.relationship_id,
    r.article_id,
    r.extraction_id,
    a.source_name,
    a.vendor,
    a.source_url,
    a.title,
    a.publication_date,
    e.pipeline_name,
    e.model_used,
    e.normalizer_version,
    e.relationship_rule_version,
    e.extraction_timestamp,
    r.subject_entity_id,
    r.subject_type,
    coalesce(subject_entity.canonical_name, r.subject_name) as subject_name,
    r.subject_normalized_name,
    r.predicate,
    r.object_entity_id,
    r.object_type,
    coalesce(object_entity.canonical_name, r.object_name) as object_name,
    r.object_normalized_name,
    r.provenance,
    r.confidence,
    r.source_quote,
    r.attributes_json,
    coalesce(r.attributes_json->>'subject_resolution', 'unresolved') as subject_resolution,
    coalesce(r.attributes_json->>'object_resolution', 'unresolved') as object_resolution
from optic.article_relationships r
join optic.articles a on a.article_id = r.article_id
join optic.article_extractions e on e.extraction_id = r.extraction_id
left join optic.entities subject_entity on subject_entity.entity_id = r.subject_entity_id
left join optic.entities object_entity on object_entity.entity_id = r.object_entity_id
where btrim(r.source_quote) <> '';

comment on view optic.quoted_relationship_evidence is
'Evidence-first relationship view with direct quotes, source metadata, and extraction lineage, including unresolved canonical endpoints.';
