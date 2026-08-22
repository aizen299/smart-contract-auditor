-- Row-level security for public.scans
--
-- This file records the access policy that protects scan history. It is
-- schema-as-code, not an automatically applied migration: this project has no
-- Supabase CLI setup (no supabase/config.toml, no CI step), so the policies
-- below were applied by hand in the dashboard and are transcribed here so they
-- can be reviewed, diffed, and restored. Nothing runs this on deploy.
--
-- Why it matters: NEXT_PUBLIC_SUPABASE_ANON_KEY ships to every browser, and
-- the `.eq("user_id", ...)` filter in frontend/app/history/page.tsx is a query
-- parameter, not a security boundary — a client can simply omit it. RLS is the
-- only thing that stops one user reading another's rows, and those rows carry
-- the full `findings` array: unfixed vulnerabilities in real contracts.
--
-- Verified live on 2026-08-23:
--   relrowsecurity = true
--   three policies present, matching the definitions below
--
-- Idempotent and atomic: safe to re-run. The drop/create pairs are wrapped in
-- a transaction so there is no window in which a policy is missing.
--
-- Not captured here: the CREATE TABLE for public.scans. Its exact column types,
-- defaults and constraints were not verified, and guessing at DDL that does not
-- match production would be worse than omitting it. To append the real
-- definition, run this in the SQL Editor and paste the result above:
--
--   select
--     column_name, data_type, is_nullable, column_default
--   from information_schema.columns
--   where table_schema = 'public' and table_name = 'scans'
--   order by ordinal_position;

begin;

alter table public.scans enable row level security;

-- SELECT: a user sees only their own scans.
drop policy if exists "Users can view own scans" on public.scans;
create policy "Users can view own scans"
  on public.scans
  for select
  using (auth.uid() = user_id);

-- INSERT: a user cannot write a row attributed to someone else.
-- Uses with_check rather than using, since there is no pre-existing row.
drop policy if exists "Users can insert own scans" on public.scans;
create policy "Users can insert own scans"
  on public.scans
  for insert
  with check (auth.uid() = user_id);

-- DELETE: a user can only remove their own scans. frontend/app/history/page.tsx
-- deletes by id alone, so this policy is what makes that safe.
drop policy if exists "Users can delete own scans" on public.scans;
create policy "Users can delete own scans"
  on public.scans
  for delete
  using (auth.uid() = user_id);

-- No UPDATE policy, deliberately. The application never updates a scan, and
-- under RLS a command with no policy is denied. Adding a permissive UPDATE
-- policy "for completeness" would widen access for no reason.

commit;

-- Notes on what this does NOT protect against:
--
-- * The service_role key bypasses RLS entirely, by design and regardless of
--   these policies. It must never reach the browser. As of this commit the
--   frontend references only NEXT_PUBLIC_SUPABASE_URL and
--   NEXT_PUBLIC_SUPABASE_ANON_KEY, which is correct.
--
-- * relforcerowsecurity is false (the default). That exempts the table owner
--   from its own policies, which is what allows the SQL Editor to administer
--   the table. It is not a gap: the owner role is not reachable from a client.
