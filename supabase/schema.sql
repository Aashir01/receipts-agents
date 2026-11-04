-- Receipts: database schema for Supabase (run once in Studio > SQL Editor).
-- The app server talks to the database with the service-role key, so it is the only
-- writer. Row-level security is still enabled on every table: a leaked anon key can
-- read only a signed-in user's own rows, plus runs they chose to share.

create extension if not exists pgcrypto;

-- Uploaded files (the bytes live in Storage bucket "uploads")
create table if not exists public.datasets (
  id            uuid primary key default gen_random_uuid(),
  owner         uuid references auth.users(id) on delete cascade,
  filename      text not null,
  size_bytes    bigint not null,
  sha256        text not null,
  storage_path  text not null,
  profile       jsonb not null,
  data_flags    jsonb not null default '[]'::jsonb,
  created_at    timestamptz not null default now()
);

-- One row per question asked
create table if not exists public.runs (
  id            uuid primary key default gen_random_uuid(),
  owner         uuid references auth.users(id) on delete cascade,
  dataset_id    uuid references public.datasets(id) on delete set null,
  question      text not null,
  status        text not null default 'running'
                check (status in ('running', 'done', 'failed', 'stopped', 'rejected')),
  answer        text,
  verified      text check (verified in ('verified', 'mismatch', 'skipped')),
  total_s       numeric,
  share_slug    text unique,
  is_public     boolean not null default false,
  created_at    timestamptz not null default now(),
  finished_at   timestamptz
);

-- The live timeline, stored so a shared run can be replayed step by step
create table if not exists public.run_events (
  id            bigserial primary key,
  run_id        uuid not null references public.runs(id) on delete cascade,
  seq           int not null,
  type          text not null,
  payload       jsonb not null,
  created_at    timestamptz not null default now(),
  unique (run_id, seq)
);

-- One receipt per sandbox execution (profile, analysis attempt, verification, replay)
create table if not exists public.receipts (
  id             uuid primary key default gen_random_uuid(),
  run_id         uuid references public.runs(id) on delete cascade,
  dataset_id     uuid references public.datasets(id) on delete set null,
  kind           text not null check (kind in ('profile', 'analysis', 'verification', 'replay', 'browser')),
  attempt        int,
  job_id         text not null,
  model          text,
  code           text not null,
  code_sha256    text not null,
  input_sha256   text,
  status         text not null,
  exit_code      int,
  duration_s     numeric,
  limits         jsonb,
  events         jsonb,
  outputs        jsonb,          -- [{name, size, sha256, storage_path}]
  preflight      jsonb,
  executed_on    text not null default 'executor-vm',   -- or 'disposable-vm:<id>'
  created_at     timestamptz not null default now()
);

-- Re-runs of a stored receipt and whether the outputs matched
create table if not exists public.replays (
  id             uuid primary key default gen_random_uuid(),
  receipt_id     uuid not null references public.receipts(id) on delete cascade,
  replay_receipt uuid references public.receipts(id) on delete set null,
  matched        boolean not null,
  details        jsonb,
  requested_by   uuid references auth.users(id) on delete set null,
  created_at     timestamptz not null default now()
);

create index if not exists runs_owner_idx      on public.runs (owner, created_at desc);
create index if not exists runs_slug_idx       on public.runs (share_slug);
create index if not exists receipts_run_idx    on public.receipts (run_id);
create index if not exists events_run_idx      on public.run_events (run_id, seq);
create index if not exists replays_receipt_idx on public.replays (receipt_id);

-- Row-level security: owners read their own rows; anyone reads rows of public runs.
alter table public.datasets   enable row level security;
alter table public.runs       enable row level security;
alter table public.run_events enable row level security;
alter table public.receipts   enable row level security;
alter table public.replays    enable row level security;

drop policy if exists "own datasets"    on public.datasets;
drop policy if exists "own or public runs" on public.runs;
drop policy if exists "events of visible runs" on public.run_events;
drop policy if exists "receipts of visible runs" on public.receipts;
drop policy if exists "replays of visible receipts" on public.replays;

create policy "own datasets" on public.datasets
  for select using (owner = auth.uid());

create policy "own or public runs" on public.runs
  for select using (owner = auth.uid() or is_public);

create policy "events of visible runs" on public.run_events
  for select using (exists (select 1 from public.runs r
                            where r.id = run_id and (r.owner = auth.uid() or r.is_public)));

create policy "receipts of visible runs" on public.receipts
  for select using (exists (select 1 from public.runs r
                            where r.id = run_id and (r.owner = auth.uid() or r.is_public)));

create policy "replays of visible receipts" on public.replays
  for select using (exists (select 1 from public.receipts rc join public.runs r on r.id = rc.run_id
                            where rc.id = receipt_id and (r.owner = auth.uid() or r.is_public)));
-- No insert/update/delete policies: only the app server (service role) writes.

-- Containment dashboard numbers, computed by the database
create or replace view public.containment_stats
with (security_invoker = true) as
select
  (select count(*) from public.runs)                                              as runs_total,
  (select count(*) from public.receipts)                                          as sandbox_jobs,
  (select count(*) from public.receipts r, jsonb_array_elements(coalesce(r.events, '[]'::jsonb)) e
     where e->>'kind' in ('blocked', 'killed'))                                   as actions_blocked,
  (select count(*) from public.receipts where (preflight->>'code_findings')::int > 0) as risky_code_caught,
  (select count(*) from public.runs where status = 'rejected')                   as runs_rejected_by_humans,
  (select count(*) from public.runs where verified = 'verified')                 as runs_verified,
  (select count(*) from public.runs where verified = 'mismatch')                 as runs_mismatched,
  (select count(*) from public.replays where matched)                            as replays_matched,
  (select count(*) from public.replays)                                          as replays_total,
  (select round(avg(duration_s)::numeric, 2) from public.receipts)               as avg_job_seconds;

-- Storage: private buckets, served only through the app server
insert into storage.buckets (id, name, public)
values ('uploads', 'uploads', false), ('outputs', 'outputs', false)
on conflict (id) do nothing;
