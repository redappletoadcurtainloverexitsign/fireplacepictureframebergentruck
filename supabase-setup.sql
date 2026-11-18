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
  lockdown_exempt boolean not null default false,
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

alter table public.app_users add column if not exists lockdown_exempt boolean not null default false;
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
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
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
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  update app_users set pw_hash = crypt(p_pass, gen_salt('bf')), last_login = now(), sign_in_count = sign_in_count + 1, fail_count = 0, locked_until = null where username = u;
  insert into app_sessions (username) values (u) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.nova_check(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select u.username, u.is_admin, u.deleted, u.lockdown_exempt into r
    from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days';
  if not found then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if r.deleted then return jsonb_build_object('ok', false, 'error', 'deleted'); end if;
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
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
      'count', sign_in_count, 'deleted', deleted, 'admin', is_admin, 'exempt', lockdown_exempt) order by last_login desc nulls last)
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

create or replace function public.nova_admin_set_exempt(p_token uuid, p_user text, p_exempt boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(coalesce(p_user, '')));
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  update app_users set lockdown_exempt = p_exempt where username = u and not is_admin;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.nova_admin_purge(p_token uuid, p_user text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(coalesce(p_user, '')));
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  if not exists (select 1 from app_users where username = u and deleted and not is_admin) then
    return jsonb_build_object('ok', false, 'error', 'notdeleted');
  end if;
  delete from app_users where username = u;
  return jsonb_build_object('ok', true);
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

grant execute on all functions in schema public to anon;

-- ===== Update 2 (banner, hidden games, play counts, requests, history, profile) =====
-- Nova Games update 2: announcement banner, hidden games, play counts, game requests, sign-in history, profile.
-- Safe to run more than once.

insert into public.app_config values ('banner', ''), ('hidden_games', '') on conflict do nothing;

create table if not exists public.app_plays (slug text primary key, plays bigint not null default 0);
create table if not exists public.app_user_plays (username text not null, slug text not null, last_at timestamptz not null default now(), primary key (username, slug));
create table if not exists public.app_requests (id bigserial primary key, username text not null, body text not null, created_at timestamptz not null default now());
create table if not exists public.app_logins (id bigserial primary key, username text not null, at timestamptz not null default now(), kind text not null default 'login');
create index if not exists app_logins_at_idx on public.app_logins (at desc);

alter table public.app_plays enable row level security;
alter table public.app_user_plays enable row level security;
alter table public.app_requests enable row level security;
alter table public.app_logins enable row level security;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on public.app_plays, public.app_user_plays, public.app_requests, public.app_logins from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke all on public.app_plays, public.app_user_plays, public.app_requests, public.app_logins from authenticated';
  end if;
end $$;

create or replace function public.nova_who(p_token uuid) returns text
language sql security definer set search_path = public as $$
  select u.username from app_sessions s join app_users u on u.username = s.username
  where s.token = p_token and s.created_at > now() - interval '7 days' and not u.deleted
$$;

-- sign-in functions, now also recording sign-in history
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
  insert into app_logins (username, kind) values (u, 'signup');
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
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  update app_users set last_login = now(), sign_in_count = sign_in_count + 1, fail_count = 0, locked_until = null where username = u;
  delete from app_sessions where created_at < now() - interval '7 days';
  delete from app_logins where at < now() - interval '90 days';
  insert into app_logins (username, kind) values (u, 'login');
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
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  update app_users set pw_hash = crypt(p_pass, gen_salt('bf')), last_login = now(), sign_in_count = sign_in_count + 1, fail_count = 0, locked_until = null where username = u;
  insert into app_logins (username, kind) values (u, 'recover');
  insert into app_sessions (username) values (u) returning token into tok;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

-- session check now also returns the banner and the hidden-games list
create or replace function public.nova_check(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select u.username, u.is_admin, u.deleted, u.lockdown_exempt into r
    from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days';
  if not found then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if r.deleted then return jsonb_build_object('ok', false, 'error', 'deleted'); end if;
  if nova_is_locked() and not r.is_admin and not r.lockdown_exempt then return jsonb_build_object('ok', false, 'error', 'locked'); end if;
  return jsonb_build_object('ok', true, 'admin', r.is_admin, 'user', r.username, 'locked', nova_is_locked(),
    'banner', coalesce((select value from app_config where key = 'banner'), ''),
    'hidden', coalesce((select value from app_config where key = 'hidden_games'), ''));
end $$;

create or replace function public.nova_admin_set_banner(p_token uuid, p_text text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  update app_config set value = left(trim(coalesce(p_text, '')), 300) where key = 'banner';
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.nova_admin_set_hidden(p_token uuid, p_slug text, p_hidden boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s text := lower(trim(coalesce(p_slug, ''))); cur text[]; 
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  if s !~ '^[a-z0-9_-]{1,40}$' then return jsonb_build_object('ok', false, 'error', 'badslug'); end if;
  cur := coalesce(string_to_array((select value from app_config where key = 'hidden_games'), ','), '{}');
  cur := array_remove(cur, s);
  cur := array_remove(cur, '');
  if p_hidden then cur := cur || s; end if;
  update app_config set value = array_to_string(cur, ',') where key = 'hidden_games';
  return jsonb_build_object('ok', true, 'hidden', array_to_string(cur, ','));
end $$;

create or replace function public.nova_admin_history(p_token uuid, p_limit int default 100) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  return jsonb_build_object('ok', true, 'rows', coalesce((
    select jsonb_agg(jsonb_build_object('username', username, 'at', at, 'kind', kind) order by at desc)
    from (select * from app_logins order by at desc limit least(greatest(coalesce(p_limit, 100), 1), 300)) x), '[]'::jsonb));
end $$;

create or replace function public.nova_play(p_token uuid, p_slug text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare w text := nova_who(p_token); s text := lower(trim(coalesce(p_slug, ''))); last timestamptz;
begin
  if w is null then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if s !~ '^[a-z0-9_-]{1,40}$' then return jsonb_build_object('ok', false, 'error', 'badslug'); end if;
  select last_at into last from app_user_plays where username = w and slug = s;
  if last is not null and last > now() - interval '10 minutes' then return jsonb_build_object('ok', true, 'counted', false); end if;
  insert into app_user_plays (username, slug, last_at) values (w, s, now())
    on conflict (username, slug) do update set last_at = now();
  insert into app_plays (slug, plays) values (s, 1) on conflict (slug) do update set plays = app_plays.plays + 1;
  return jsonb_build_object('ok', true, 'counted', true);
end $$;

create or replace function public.nova_popular(p_token uuid, p_limit int default 12) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if nova_who(p_token) is null then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  return jsonb_build_object('ok', true, 'rows', coalesce((
    select jsonb_agg(jsonb_build_object('slug', slug, 'plays', plays) order by plays desc)
    from (select * from app_plays order by plays desc limit least(greatest(coalesce(p_limit, 12), 1), 50)) x), '[]'::jsonb));
end $$;

create or replace function public.nova_request_game(p_token uuid, p_text text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare w text := nova_who(p_token); t text := trim(coalesce(p_text, ''));
begin
  if w is null then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  if length(t) < 3 or length(t) > 200 then return jsonb_build_object('ok', false, 'error', 'badtext'); end if;
  if (select count(*) from app_requests where username = w and created_at > now() - interval '1 day') >= 5 then
    return jsonb_build_object('ok', false, 'error', 'limit');
  end if;
  if (select count(*) from app_requests) >= 500 then return jsonb_build_object('ok', false, 'error', 'full'); end if;
  insert into app_requests (username, body) values (w, t);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.nova_admin_requests(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  return jsonb_build_object('ok', true, 'rows', coalesce((
    select jsonb_agg(jsonb_build_object('id', id, 'username', username, 'text', body, 'at', created_at) order by created_at desc)
    from (select * from app_requests order by created_at desc limit 200) x), '[]'::jsonb));
end $$;

create or replace function public.nova_admin_clear_request(p_token uuid, p_id bigint) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not nova_admin_ok(p_token) then return jsonb_build_object('ok', false, 'error', 'denied'); end if;
  delete from app_requests where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.nova_profile(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select u.username, u.created_at, u.last_login, u.sign_in_count, u.is_admin into r
    from app_sessions s join app_users u on u.username = s.username
    where s.token = p_token and s.created_at > now() - interval '7 days' and not u.deleted;
  if not found then return jsonb_build_object('ok', false, 'error', 'invalid'); end if;
  return jsonb_build_object('ok', true, 'username', r.username, 'created', r.created_at, 'last', r.last_login, 'count', r.sign_in_count, 'admin', r.is_admin);
end $$;

grant execute on all functions in schema public to anon;
