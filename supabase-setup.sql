-- Nova Games: shared accounts, sign-in tracking, delete, lockdown.
-- Paste this whole file into Supabase > SQL Editor > New query > Run.
-- Passwords are hashed on the server (bcrypt). Tables are locked; the website can only use the functions below.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.app_users (
  username text primary key,
  pw_hash text not null,
  rec_hash text,
  is_admin boolean not null default false,
  deleted boolean not null default false,
  created_at timestamptz not null default now(),
  last_login timestamptz,
  sign_in_count int not null default 0,
  fail_count int not null default 0,
  locked_until timestamptz
);
create table if not exists public.app_sessions (
  token uuid primary key default gen_random_uuid(),
  username text not null references public.app_users(username) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.app_config (key text primary key, value text not null);
insert into public.app_config values ('locked', 'false') on conflict do nothing;

alter table public.app_users enable row level security;
alter table public.app_sessions enable row level security;
alter table public.app_config enable row level security;

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on public.app_users, public.app_sessions, public.app_config from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke all on public.app_users, public.app_sessions, public.app_config from authenticated';
  end if;
end $$;

create or replace function public.nova_is_locked() returns boolean
language sql security definer set search_path = public as $$
  select coalesce((select value = 'true' from app_config where key = 'locked'), false)
$$;

create or replace function public.nova_status() returns jsonb
language sql security definer set search_path = public as $$
  select jsonb_build_object('locked', nova_is_locked())
$$;

create or replace function public.nova_signup(p_user text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(trim(coalesce(p_user, ''))); code text; tok uuid;
begin
  if u !~ '^[a-z0-9_]{3,20}$' then return jsonb_build_object('ok', false, 'error', 'badname'); end if;
  if length(coalesce(p_pass, '')) < 6 or length(p_pass) > 72 then return jsonb_build_object('ok', false, 'error', 'badpass'); end if;
  if nova_is_locked() then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  if exists (select 1 from app_users where username = u) then return jsonb_build_object('ok', false, 'error', 'taken'); end if;
  code := upper(encode(gen_random_bytes(8), 'hex'));
  insert into app_users (username, pw_hash, rec_hash, last_login, sign_in_count)
    values (u, crypt(p_pass, gen_salt('bf')), crypt(code, gen_salt('bf')), now(), 1);
  insert into app_sessions (username) values (u) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok, 'recovery', regexp_replace(code, '(.{4})(?=.)', '\1-', 'g'));
exception when unique_violation then
  return jsonb_build_object('ok', false, 'error', 'taken');
end $$;

create or replace function public.nova_login(p_user text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(trim(coalesce(p_user, ''))); r app_users%rowtype; tok uuid;
begin
  select * into r from app_users where username = u;
  if not found then perform pg_sleep(0.3); return jsonb_build_object('ok', false, 'error', 'bad'); end if;
  if r.locked_until is not null and r.locked_until > now() then return jsonb_build_object('ok', false, 'error', 'wait'); end if;
  if r.pw_hash <> crypt(coalesce(p_pass, ''), r.pw_hash) then
    update app_users set
      fail_count = case when fail_count + 1 >= 5 then 0 else fail_count + 1 end,
      locked_until = case when fail_count + 1 >= 5 then now() + interval '5 minutes' else locked_until end
      where username = u;
    return jsonb_build_object('ok', false, 'error', 'bad');
  end if;
  if r.deleted then return jsonb_build_object('ok', false, 'error', 'deleted'); end if;
  if nova_is_locked() and not r.is_admin then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  update app_users set last_login = now(), sign_in_count = sign_in_count + 1, fail_count = 0, locked_until = null where username = u;
  delete from app_sessions where created_at < now() - interval '7 days';
  insert into app_sessions (username) values (u) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.nova_recover(p_user text, p_code text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(trim(coalesce(p_user, ''))); r app_users%rowtype; tok uuid; c text;
begin
  c := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
  if length(coalesce(p_pass, '')) < 6 or length(p_pass) > 72 then return jsonb_build_object('ok', false, 'error', 'badpass'); end if;
  select * into r from app_users where username = u;
  if not found or r.rec_hash is null then perform pg_sleep(0.3); return jsonb_build_object('ok', false, 'error', 'badcode'); end if;
  if r.locked_until is not null and r.locked_until > now() then return jsonb_build_object('ok', false, 'error', 'wait'); end if;
  if r.rec_hash <> crypt(c, r.rec_hash) then
    update app_users set
      fail_count = case when fail_count + 1 >= 5 then 0 else fail_count + 1 end,
      locked_until = case when fail_count + 1 >= 5 then now() + interval '5 minutes' else locked_until end
      where username = u;
    return jsonb_build_object('ok', false, 'error', 'badcode');
  end if;
  if r.deleted then return jsonb_build_object('ok', false, 'error', 'deleted'); end if;
  if nova_is_locked() and not r.is_admin then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  update app_users set pw_hash = crypt(p_pass, gen_salt('bf')), last_login = now(), sign_in_count = sign_in_count + 1, fail_count = 0, locked_until = null where username = u;
  insert into app_sessions (username) values (u) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.nova_check(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select u.username, u.is_admin, u.deleted into r
    from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days';
  if not found then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if r.deleted then return jsonb_build_object('ok', false, 'error', 'deleted'); end if;
  if nova_is_locked() and not r.is_admin then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  return jsonb_build_object('ok', true, 'admin', r.is_admin, 'user', r.username, 'locked', nova_is_locked());
end $$;

create or replace function public.nova_admin_ok(p_token uuid) returns boolean
language sql security definer set search_path = public as $$
  select exists (
    select 1 from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days' and u.is_admin and not u.deleted)
$$;

create or replace function public.nova_admin_users(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  return jsonb_build_object('ok', true, 'users', coalesce((
    select jsonb_agg(jsonb_build_object('username', username, 'created', created_at, 'last', last_login,
      'count', sign_in_count, 'deleted', deleted, 'admin', is_admin) order by last_login desc nulls last)
    from app_users), '[]'::jsonb));
end $$;

create or replace function public.nova_admin_set_deleted(p_token uuid, p_user text, p_deleted boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(coalesce(p_user, '')));
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  if exists (select 1 from app_users where username = u and is_admin) then return jsonb_build_object('ok', false, 'error', 'admin'); end if;
  update app_users set deleted = p_deleted where username = u;
  if p_deleted then delete from app_sessions where username = u; end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.nova_admin_set_lock(p_token uuid, p_locked boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  update app_config set value = case when p_locked then 'true' else 'false' end where key = 'locked';
  return jsonb_build_object('ok', true, 'locked', p_locked);
end $$;

-- Only the functions are reachable from the website.
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'grant execute on all functions in schema public to anon';
  end if;
end $$;

-- Let a signed-in user delete their own account (asks for their password).
create or replace function public.nova_delete_self(p_token uuid, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r app_users%rowtype;
begin
  select u.* into r from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days';
  if not found then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if r.is_admin then return jsonb_build_object('ok', false, 'error', 'admin'); end if;
  if r.locked_until is not null and r.locked_until > now() then return jsonb_build_object('ok', false, 'error', 'wait'); end if;
  if r.pw_hash <> crypt(coalesce(p_pass, ''), r.pw_hash) then
    update app_users set
      fail_count = case when fail_count + 1 >= 5 then 0 else fail_count + 1 end,
      locked_until = case when fail_count + 1 >= 5 then now() + interval '5 minutes' else locked_until end
      where username = r.username;
    return jsonb_build_object('ok', false, 'error', 'bad');
  end if;
  delete from app_users where username = r.username;
  return jsonb_build_object('ok', true);
end $$;
grant execute on function public.nova_delete_self(uuid, text) to anon;
