-- Run this ONCE in Supabase: Dashboard > SQL Editor > New query > paste > Run.
-- No accounts, no emails. One private row holds your passcode (hashed) and your data.
-- The table is closed to the public; the app can only reach it through the functions below,
-- and every function checks your passcode on the server first.

create table if not exists public.tracker (
  id           int primary key default 1 check (id = 1),
  pin_hash     text,
  data         jsonb not null default '{}'::jsonb,
  updated_at   timestamptz not null default now(),
  fails        int not null default 0,
  locked_until timestamptz
);
insert into public.tracker (id) values (1) on conflict (id) do nothing;

alter table public.tracker enable row level security;      -- no policies = nobody can read it directly
revoke all on public.tracker from anon, authenticated;

-- internal: checks the passcode, counts wrong tries, pauses for 5 minutes after 8 wrong ones
create or replace function public.ht_check(p text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker%rowtype;
begin
  select * into r from public.tracker where id = 1 for update;
  if r.pin_hash is null then return 'nopin'; end if;
  if r.locked_until is not null and r.locked_until > now() then return 'locked'; end if;
  if r.pin_hash = crypt(coalesce(p, ''), r.pin_hash) then
    update public.tracker set fails = 0, locked_until = null where id = 1;
    return 'ok';
  end if;
  if r.fails + 1 >= 8 then
    update public.tracker set fails = 0, locked_until = now() + interval '5 minutes' where id = 1;
  else
    update public.tracker set fails = r.fails + 1 where id = 1;
  end if;
  return 'bad';
end $$;

create or replace function public.ht_status() returns jsonb
language sql security definer set search_path = public as $$
  select jsonb_build_object('has_pin', exists (select 1 from public.tracker where id = 1 and pin_hash is not null));
$$;

create or replace function public.ht_verify(p text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c text := public.ht_check(p);
begin
  return jsonb_build_object('ok', c = 'ok', 'reason', c);
end $$;

-- first-time setup (no passcode yet) or change (old passcode must match)
create or replace function public.ht_set_pin(new_pin text, old_pin text default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare c text;
begin
  if new_pin is null or new_pin !~ '^[0-9]{6}$' then
    return jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  c := public.ht_check(old_pin);
  if c in ('ok', 'nopin') then
    update public.tracker set pin_hash = crypt(new_pin, gen_salt('bf')), fails = 0, locked_until = null where id = 1;
    return jsonb_build_object('ok', true);
  end if;
  return jsonb_build_object('ok', false, 'reason', c);
end $$;

create or replace function public.ht_load(p text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c text := public.ht_check(p); d jsonb;
begin
  if c <> 'ok' then return jsonb_build_object('ok', false, 'reason', c); end if;
  select data into d from public.tracker where id = 1;
  return jsonb_build_object('ok', true, 'data', d);
end $$;

create or replace function public.ht_save(p text, d jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c text := public.ht_check(p);
begin
  if c <> 'ok' then return jsonb_build_object('ok', false, 'reason', c); end if;
  update public.tracker set data = d, updated_at = now() where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- only the five app functions are callable from the app
revoke all on function public.ht_check(text) from public, anon, authenticated;
revoke all on function public.ht_status(), public.ht_verify(text), public.ht_set_pin(text, text), public.ht_load(text), public.ht_save(text, jsonb) from public;
grant execute on function public.ht_status(), public.ht_verify(text), public.ht_set_pin(text, text), public.ht_load(text), public.ht_save(text, jsonb) to anon, authenticated;

-- Forgot your passcode? Run this, then set a new one in the app:
--   update public.tracker set pin_hash = null, fails = 0, locked_until = null where id = 1;
