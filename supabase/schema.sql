-- Groupflicks backend for Supabase.
-- Run this once in the Supabase SQL editor of a new project.
--
-- The server only ever stores ciphertext. Album names, people, tags, face data and the
-- photos themselves are encrypted in the browser with a key that lives in the invite link.
-- What the server can see: random album ids, how many items an album has, their sizes
-- and when they changed.
--
-- Access model: there are no accounts. An album has an access token derived from the
-- invite link; the server keeps only its SHA-256 hash. Tables are closed to direct access,
-- and every read or write goes through the functions below, which check the token.

create table if not exists public.gf_albums (
  id          text primary key check (id ~ '^[A-Za-z0-9_-]{16,40}$'),
  token_hash  text not null,
  created_at  timestamptz not null default now()
);

create sequence if not exists public.gf_seq;

create table if not exists public.gf_docs (
  album_id    text not null references public.gf_albums(id) on delete cascade,
  id          text not null check (id ~ '^[A-Za-z0-9_-]{1,64}$'),
  kind        text not null check (kind in ('album', 'photo', 'person', 'member')),
  data        text not null check (length(data) <= 400000),
  deleted     boolean not null default false,
  seq         bigint not null default nextval('public.gf_seq'),
  updated_at  timestamptz not null default now(),
  primary key (album_id, id)
);
create index if not exists gf_docs_album_seq on public.gf_docs (album_id, seq);

alter table public.gf_albums enable row level security;
alter table public.gf_docs   enable row level security;
revoke all on public.gf_albums, public.gf_docs from anon, authenticated;
revoke all on sequence public.gf_seq from anon, authenticated;

-- Raises unless the token matches the album.
create or replace function public.gf_check(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (
    select 1 from gf_albums
    where id = p_album
      and token_hash = encode(sha256(convert_to(coalesce(p_token, ''), 'UTF8')), 'hex')
  ) then
    raise exception 'album not found' using errcode = 'P0002';
  end if;
end $$;

create or replace function public.gf_create_album(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_token is null or length(p_token) < 32 then
    raise exception 'token too short' using errcode = '22023';
  end if;
  insert into gf_albums (id, token_hash)
  values (p_album, encode(sha256(convert_to(p_token, 'UTF8')), 'hex'));
end $$;

create or replace function public.gf_put(p_album text, p_token text, p_id text, p_kind text, p_data text)
returns bigint language plpgsql security definer set search_path = public as $$
declare v_seq bigint;
begin
  perform gf_check(p_album, p_token);
  if (select count(*) from gf_docs where album_id = p_album) >= 6000
     and not exists (select 1 from gf_docs where album_id = p_album and id = p_id) then
    raise exception 'album is full' using errcode = '54000';
  end if;
  insert into gf_docs (album_id, id, kind, data)
  values (p_album, p_id, p_kind, p_data)
  on conflict (album_id, id) do update
    set kind = excluded.kind, data = excluded.data, deleted = false,
        seq = nextval('public.gf_seq'), updated_at = now()
  returning seq into v_seq;
  return v_seq;
end $$;

create or replace function public.gf_delete(p_album text, p_token text, p_id text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform gf_check(p_album, p_token);
  update gf_docs set deleted = true, data = '', seq = nextval('public.gf_seq'), updated_at = now()
  where album_id = p_album and id = p_id;
end $$;

create or replace function public.gf_list(p_album text, p_token text, p_since bigint default 0)
returns table (id text, kind text, data text, deleted boolean, seq bigint)
language plpgsql security definer set search_path = public as $$
begin
  perform gf_check(p_album, p_token);
  return query
    select d.id, d.kind, d.data, d.deleted, d.seq
    from gf_docs d
    where d.album_id = p_album and d.seq > coalesce(p_since, 0)
    order by d.seq
    limit 5000;
end $$;

-- Deletes an album and every record in it. The app removes the encrypted photo files
-- through the Storage API first; this removes the rows.
create or replace function public.gf_delete_album(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform gf_check(p_album, p_token);
  delete from gf_albums where id = p_album;
end $$;

-- Used by the storage rules below. Album ids are 128-bit random values, so knowing
-- that one exists means you already have the link.
create or replace function public.gf_album_exists(p_album text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from gf_albums where id = p_album);
$$;

revoke all on function public.gf_check(text, text) from public, anon, authenticated;
grant execute on function
  public.gf_create_album(text, text),
  public.gf_put(text, text, text, text, text),
  public.gf_delete(text, text, text),
  public.gf_list(text, text, bigint),
  public.gf_delete_album(text, text),
  public.gf_album_exists(text)
to anon, authenticated;

-- Encrypted photo files. The bucket is public-read on purpose: file names are random,
-- and the contents are useless without the key from the invite link.
insert into storage.buckets (id, name, public, file_size_limit)
values ('gf-photos', 'gf-photos', true, 15728640)
on conflict (id) do nothing;

drop policy if exists "gf upload into an existing album" on storage.objects;
create policy "gf upload into an existing album" on storage.objects
  for insert to anon, authenticated
  with check (bucket_id = 'gf-photos' and public.gf_album_exists((storage.foldername(name))[1]));

-- Nobody can list the bucket. Reading a row is allowed only while the Storage API is carrying out
-- a delete, which needs to find and lock the row first. A delete therefore needs the album id and
-- the random file name, and both are known only to people who hold the invite link.
drop policy if exists "gf read within an existing album" on storage.objects;
drop policy if exists "gf find a file while deleting it" on storage.objects;
create policy "gf find a file while deleting it" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_album_exists((storage.foldername(name))[1]));

drop policy if exists "gf lock a file while deleting it" on storage.objects;
create policy "gf lock a file while deleting it" on storage.objects
  for update to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_album_exists((storage.foldername(name))[1]))
  with check (false);

drop policy if exists "gf delete within an existing album" on storage.objects;
create policy "gf delete within an existing album" on storage.objects
  for delete to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_album_exists((storage.foldername(name))[1]));

-- ───────── view-only links, write-protected storage and usage limits ─────────
-- (also available alone as 2026-11-17-view-links-and-limits.sql for projects set up earlier)

alter table public.gf_albums add column if not exists read_hash text;

create table if not exists public.gf_grants (
  name      text primary key,
  album_id  text not null references public.gf_albums(id) on delete cascade,
  op        text not null check (op in ('upload', 'delete')),
  expires   timestamptz not null
);
create table if not exists public.gf_rate (
  who   text not null,
  kind  text not null,
  hour  timestamptz not null,
  n     integer not null default 0,
  primary key (who, kind, hour)
);
alter table public.gf_grants enable row level security;
alter table public.gf_rate   enable row level security;
revoke all on public.gf_grants, public.gf_rate from anon, authenticated;

create or replace function public.gf_hash(p text)
returns text language sql immutable as $$
  select encode(sha256(convert_to(coalesce(p, ''), 'UTF8')), 'hex');
$$;

-- Raises unless the token is the album's full token or its view-only token.
create or replace function public.gf_check_read(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (
    select 1 from gf_albums
    where id = p_album and (token_hash = gf_hash(p_token) or read_hash = gf_hash(p_token))
  ) then
    raise exception 'album not found' using errcode = 'P0002';
  end if;
end $$;

-- Counts a request against the caller's network and raises GF001 when over the limit.
-- Only a hash of the address is kept, for two days.
create or replace function public.gf_bump(p_kind text, p_n integer, p_per_hour integer, p_per_day integer)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_ip   text := '';
  v_who  text;
  v_hour timestamptz := date_trunc('hour', now());
  v_h    bigint;
  v_d    bigint;
begin
  begin
    v_ip := split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''), ',', 1);
  exception when others then v_ip := '';
  end;
  v_who := md5('gf:' || coalesce(nullif(trim(v_ip), ''), 'unknown'));
  insert into gf_rate (who, kind, hour, n) values (v_who, p_kind, v_hour, p_n)
    on conflict (who, kind, hour) do update set n = gf_rate.n + excluded.n;
  select coalesce(sum(n) filter (where hour = v_hour), 0), coalesce(sum(n), 0) into v_h, v_d
    from gf_rate where who = v_who and kind = p_kind and hour > now() - interval '24 hours';
  if v_h > p_per_hour or v_d > p_per_day then
    raise exception 'too many requests' using errcode = 'GF001';
  end if;
  delete from gf_rate where hour < now() - interval '2 days';
end $$;

create or replace function public.gf_create_album(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_token is null or length(p_token) < 32 then
    raise exception 'token too short' using errcode = '22023';
  end if;
  perform gf_bump('album', 1, 10, 20);                      -- per network: 10 an hour, 20 a day
  if (select count(*) from gf_albums where created_at > now() - interval '24 hours') >= 300 then
    raise exception 'too many requests' using errcode = 'GF001';
  end if;
  insert into gf_albums (id, token_hash) values (p_album, gf_hash(p_token));
end $$;

-- Registers the album's view-only token. Needs the full token.
create or replace function public.gf_set_read(p_album text, p_token text, p_read text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform gf_check(p_album, p_token);
  if p_read is null or length(p_read) < 32 then
    raise exception 'token too short' using errcode = '22023';
  end if;
  update gf_albums set read_hash = gf_hash(p_read) where id = p_album;
end $$;

create or replace function public.gf_list(p_album text, p_token text, p_since bigint default 0)
returns table (id text, kind text, data text, deleted boolean, seq bigint)
language plpgsql security definer set search_path = public as $$
begin
  perform gf_check_read(p_album, p_token);
  return query
    select d.id, d.kind, d.data, d.deleted, d.seq
    from gf_docs d
    where d.album_id = p_album and d.seq > coalesce(p_since, 0)
    order by d.seq
    limit 5000;
end $$;

-- Asks permission to upload or delete named files in an album. Needs the full token.
-- Raises GF002 when the album is full and GF003 when the site's storage is full.
create or replace function public.gf_allow_files(p_album text, p_token text, p_names text[], p_op text)
returns void language plpgsql security definer set search_path = public as $$
declare v_n integer := coalesce(array_length(p_names, 1), 0);
begin
  perform gf_check(p_album, p_token);
  if p_op not in ('upload', 'delete') or v_n < 1 or v_n > 400
     or exists (select 1 from unnest(p_names) x where x !~ '^[A-Za-z0-9_-]{8,64}$') then
    raise exception 'bad request' using errcode = '22023';
  end if;
  if p_op = 'upload' then
    perform gf_bump('upload', v_n, 4000, 20000);            -- files per network: 4,000 an hour
    if (select count(*) from gf_docs where album_id = p_album and kind = 'photo' and not deleted) >= 2000 then
      raise exception 'album is full' using errcode = 'GF002';
    end if;
    if (select coalesce(sum((metadata ->> 'size')::bigint), 0) from storage.objects where bucket_id = 'gf-photos') >= 943718400 then
      raise exception 'storage is full' using errcode = 'GF003';   -- 900 MB of the free plan's 1 GB
    end if;
  end if;
  delete from gf_grants where expires < now();
  insert into gf_grants (name, album_id, op, expires)
    select p_album || '/' || x, p_album, p_op, now() + interval '15 minutes' from unnest(p_names) x
    on conflict (name) do update set op = excluded.op, expires = excluded.expires, album_id = excluded.album_id;
end $$;

-- Used by the storage rules: has the app been allowed to do this to this file?
create or replace function public.gf_file_ok(p_name text, p_op text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from gf_grants where name = p_name and op = p_op and expires > now());
$$;

revoke all on function public.gf_check_read(text, text), public.gf_bump(text, integer, integer, integer) from public, anon, authenticated;
grant execute on function
  public.gf_create_album(text, text),
  public.gf_set_read(text, text, text),
  public.gf_list(text, text, bigint),
  public.gf_allow_files(text, text, text[], text),
  public.gf_file_ok(text, text)
to anon, authenticated;

-- Storage rules: nothing can be listed; uploads and deletes need a permission from gf_allow_files.
drop policy if exists "gf upload into an existing album" on storage.objects;
drop policy if exists "gf read within an existing album" on storage.objects;
drop policy if exists "gf find a file while deleting it" on storage.objects;
drop policy if exists "gf lock a file while deleting it" on storage.objects;
drop policy if exists "gf delete within an existing album" on storage.objects;
drop policy if exists "gf upload a permitted file" on storage.objects;
drop policy if exists "gf find a permitted file while deleting it" on storage.objects;
drop policy if exists "gf lock a permitted file while deleting it" on storage.objects;
drop policy if exists "gf delete a permitted file" on storage.objects;

create policy "gf upload a permitted file" on storage.objects
  for insert to anon, authenticated
  with check (bucket_id = 'gf-photos' and public.gf_file_ok(name, 'upload'));

create policy "gf find a permitted file while deleting it" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_file_ok(name, 'delete'));

create policy "gf lock a permitted file while deleting it" on storage.objects
  for update to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_file_ok(name, 'delete'))
  with check (false);

create policy "gf delete a permitted file" on storage.objects
  for delete to anon, authenticated
  using (bucket_id = 'gf-photos'
         and coalesce(current_setting('storage.operation', true), '') ilike '%delete%'
         and public.gf_file_ok(name, 'delete'));
