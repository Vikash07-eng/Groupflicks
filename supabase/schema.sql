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

drop policy if exists "gf read within an existing album" on storage.objects;
create policy "gf read within an existing album" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'gf-photos' and public.gf_album_exists((storage.foldername(name))[1]));

drop policy if exists "gf delete within an existing album" on storage.objects;
create policy "gf delete within an existing album" on storage.objects
  for delete to anon, authenticated
  using (bucket_id = 'gf-photos' and public.gf_album_exists((storage.foldername(name))[1]));
