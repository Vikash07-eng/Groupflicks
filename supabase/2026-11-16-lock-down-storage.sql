-- Groupflicks: close file listing on the photo bucket.
-- Run once in the Supabase SQL editor. Safe to run more than once.
-- Before this, anyone with the public key could list the bucket and delete files.
-- Photos were never readable (they are encrypted), but files could be seen and removed.

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

-- Removes every record of an album once the app has deleted its files.
create or replace function public.gf_delete_album(p_album text, p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform gf_check(p_album, p_token);
  delete from gf_albums where id = p_album;
end $$;
grant execute on function public.gf_delete_album(text, text) to anon, authenticated;
