-- Run this once in Supabase: Dashboard > SQL Editor > New query > Run.
create table if not exists public.tracker_state (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.tracker_state enable row level security;

drop policy if exists "select own" on public.tracker_state;
drop policy if exists "insert own" on public.tracker_state;
drop policy if exists "update own" on public.tracker_state;
drop policy if exists "delete own" on public.tracker_state;

create policy "select own" on public.tracker_state for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "insert own" on public.tracker_state for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "update own" on public.tracker_state for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "delete own" on public.tracker_state for delete to authenticated
  using ((select auth.uid()) = user_id);
