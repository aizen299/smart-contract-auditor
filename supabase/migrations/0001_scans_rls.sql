-- public.scans — scan history, and the row-level security that protects it.
--
-- The DDL below is the real remote schema, captured with `supabase db dump`
-- on 2026-08-23, not hand-written. An earlier version of this file recorded
-- only the RLS policies and deliberately omitted the table definition, on the
-- grounds that guessing at column types would be worse than omitting them.
-- That was right as documentation but wrong as a migration: `supabase db pull`
-- replays local migrations against an empty shadow database, and a file that
-- opens with `alter table public.scans ...` fails with 42P01 because nothing
-- created the table. It is now replayable from nothing.
--
-- Why RLS is load-bearing here rather than defence in depth:
-- NEXT_PUBLIC_SUPABASE_ANON_KEY ships to every browser, and the
-- `.eq("user_id", ...)` filter in frontend/app/history/page.tsx is a query
-- parameter, not a boundary — a client can simply omit it. RLS is what stops
-- one user reading another's rows, and those rows carry the full `findings`
-- array: unfixed vulnerabilities in real contracts under audit.

create table if not exists "public"."scans" (
    "id"             "uuid" default "gen_random_uuid"() not null,
    "user_id"        "uuid" not null,
    "file_name"      "text" not null,
    "risk_score"     integer not null,
    "total_findings" integer not null,
    "findings"       "jsonb" default '[]'::"jsonb" not null,
    "created_at"     timestamp with time zone default "timezone"('utc'::"text", "now"()) not null
);

alter table "public"."scans" owner to "postgres";

-- Hidden from the auto-generated GraphQL API; the app uses PostgREST only.
comment on table "public"."scans" is '@graphql({"visible": false})';

alter table only "public"."scans"
    add constraint "scans_pkey" primary key ("id");

-- Deleting an auth user removes their scan history with them. Worth knowing:
-- account deletion is already GDPR-shaped because of this cascade.
alter table only "public"."scans"
    add constraint "scans_user_id_fkey" foreign key ("user_id")
    references "auth"."users"("id") on delete cascade;

-- Table grants.
--
-- `anon` is deliberately absent: it holds USAGE on the schema but no privilege
-- on this table, so an unauthenticated request is refused at the permission
-- layer before RLS is consulted at all.
--
-- `authenticated` is granted UPDATE even though no UPDATE policy exists below.
-- Under RLS a command with no policy is denied, so update is unreachable — but
-- note the grant is wider than the policy, which means disabling RLS would
-- silently make updates possible. The policies are the control, not the grants.
grant all on table "public"."scans" to "service_role";
grant select, insert, delete, update on table "public"."scans" to "authenticated";

alter table "public"."scans" enable row level security;

create policy "Users can view own scans"
    on "public"."scans" for select
    using (("auth"."uid"() = "user_id"));

create policy "Users can insert own scans"
    on "public"."scans" for insert
    with check (("auth"."uid"() = "user_id"));

-- frontend/app/history/page.tsx deletes by id alone, with no user_id predicate.
-- This policy is the only thing that makes that safe.
create policy "Users can delete own scans"
    on "public"."scans" for delete
    using (("auth"."uid"() = "user_id"));

-- No UPDATE policy, deliberately: the app never updates a scan, and an
-- un-policied command is denied. Adding a permissive one "for completeness"
-- would widen access for nothing.

-- ---------------------------------------------------------------------------
-- Two things this schema does NOT protect against, worth knowing before adding
-- another table:
--
-- 1. service_role bypasses RLS entirely, by design. It must never reach the
--    browser. The frontend references only NEXT_PUBLIC_SUPABASE_URL and
--    NEXT_PUBLIC_SUPABASE_ANON_KEY, which is correct.
--
-- 2. This project carries Supabase's default privileges, which include
--    `alter default privileges ... grant all on tables to "anon"`. A new table
--    created by postgres in `public` is therefore granted to anon the moment
--    it exists. RLS is the only thing between a new table and anyone holding
--    the anon key — which is everyone, since it ships in the browser bundle.
--    Enable RLS on every new table before putting data in it.
