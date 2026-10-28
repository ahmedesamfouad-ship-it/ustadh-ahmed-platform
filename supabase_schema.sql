-- ============================================================================
-- USTADH AHMED PLATFORM — IDEMPOTENT SUPABASE / POSTGRESQL SCHEMA, RLS & RPCs
-- Version: 6.0.0-PRODUCTION-RELEASE
-- Safe to run multiple times (idempotent CREATE TABLE IF NOT EXISTS, policies & functions)
-- ============================================================================

begin;

create extension if not exists "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. ADMIN USERS TABLE & ROLE HELPER FUNCTION
--    Supports BOTH `public.admin_users` membership AND `app_metadata.role` JWT
-- ----------------------------------------------------------------------------
create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null default '',
  role text not null default 'tutor_admin',
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;

create or replace function public.is_tutor_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'tutor_admin',
    false
  ) or exists (
    select 1 from public.admin_users where user_id = auth.uid()
  );
$$;

drop policy if exists "Admins can read admin_users" on public.admin_users;
create policy "Admins can read admin_users"
  on public.admin_users for select
  using (auth.uid() = user_id or public.is_tutor_admin());

drop policy if exists "Admins can manage admin_users" on public.admin_users;
create policy "Admins can manage admin_users"
  on public.admin_users for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 2. PLATFORM SETTINGS & BILINGUAL CMS CONFIGURATION (SINGLETON ROW)
-- ----------------------------------------------------------------------------
create table if not exists public.platform_settings (
  id text primary key default 'default' check (id = 'default'),
  schema_version text not null default '6.0.0-PRODUCTION-RELEASE',
  cms_texts jsonb not null default '{}'::jsonb,
  ui_dictionary jsonb not null default '{"ar": {}, "en": {}}'::jsonb,
  theme jsonb not null default '{}'::jsonb,
  header_footer_config jsonb not null default '{}'::jsonb,
  student_portal_config jsonb not null default '{}'::jsonb,
  seo_meta jsonb not null default '{}'::jsonb,
  announcement_banner jsonb not null default '{}'::jsonb,
  layout_config jsonb not null default '{}'::jsonb,
  landing_sections jsonb not null default '{}'::jsonb,
  landing_section_order jsonb not null default '["hero","credentials","tracks","reviews"]'::jsonb,
  custom_landing_sections jsonb not null default '[]'::jsonb,
  custom_pages jsonb not null default '[]'::jsonb,
  nav_items jsonb not null default '[]'::jsonb,
  pillars_schema jsonb not null default '{}'::jsonb,
  placement_test jsonb not null default '{}'::jsonb,
  teacher_notifications jsonb not null default '[]'::jsonb,
  site_images jsonb not null default '{}'::jsonb,
  font_family text not null default 'Cairo',
  custom_css text not null default '',
  preply_url text not null default 'https://preply.com/en/tutor/arabic-medical-scholar',
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

alter table public.platform_settings enable row level security;

drop policy if exists "Public can read platform_settings" on public.platform_settings;
create policy "Public can read platform_settings"
  on public.platform_settings for select
  using (true);

drop policy if exists "Tutor admin can modify platform_settings" on public.platform_settings;
create policy "Tutor admin can modify platform_settings"
  on public.platform_settings for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 3. PRIVATE TEACHER NOTIFICATIONS (RLS RESTRICTED TO TUTOR ADMIN ONLY)
-- ----------------------------------------------------------------------------
create table if not exists public.teacher_notifications (
  id text primary key,
  type text not null default 'HOMEWORK_SUBMISSION',
  student_id text not null default '',
  student_name text not null default '',
  rating int not null default 5,
  text text not null default '',
  date text not null default '',
  read boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.teacher_notifications enable row level security;

drop policy if exists "Tutor admin manages teacher_notifications" on public.teacher_notifications;
create policy "Tutor admin manages teacher_notifications"
  on public.teacher_notifications for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 4. ACADEMIC CREDENTIALS, TRACKS & VERIFIED REVIEWS
-- ----------------------------------------------------------------------------
create table if not exists public.credentials (
  id text primary key,
  sort_order int not null default 0,
  badge_ar text not null,
  badge_en text not null,
  title_ar text not null,
  title_en text not null,
  org_ar text not null,
  org_en text not null,
  desc_ar text not null,
  desc_en text not null,
  cert_detail text not null default '',
  logo_url text not null default '',
  cert_images jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.credentials enable row level security;
drop policy if exists "Public read credentials" on public.credentials;
create policy "Public read credentials" on public.credentials for select using (true);
drop policy if exists "Admin manage credentials" on public.credentials;
create policy "Admin manage credentials" on public.credentials for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

create table if not exists public.tracks (
  id text primary key,
  sort_order int not null default 0,
  code_ar text not null,
  code_en text not null,
  cefr_range text not null,
  title_ar text not null,
  title_en text not null,
  book_ar text not null,
  book_en text not null,
  desc_ar text not null,
  desc_en text not null,
  highlights_ar jsonb not null default '[]'::jsonb,
  highlights_en jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.tracks enable row level security;
drop policy if exists "Public read tracks" on public.tracks;
create policy "Public read tracks" on public.tracks for select using (true);
drop policy if exists "Admin manage tracks" on public.tracks;
create policy "Admin manage tracks" on public.tracks for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

create table if not exists public.reviews (
  id text primary key,
  sort_order int not null default 0,
  name_ar text not null,
  name_en text not null,
  location_ar text not null,
  location_en text not null,
  track_ar text not null,
  track_en text not null,
  rating text not null default '5.0 ★',
  quote_ar text not null,
  quote_en text not null,
  is_verified boolean not null default true,
  visible boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.reviews enable row level security;
drop policy if exists "Public read visible reviews" on public.reviews;
create policy "Public read visible reviews" on public.reviews for select using (visible = true or public.is_tutor_admin());
drop policy if exists "Admin manage reviews" on public.reviews;
create policy "Admin manage reviews" on public.reviews for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 5. STUDENT PROFILES & SERVER SESSIONS (STRICT PER-STUDENT ISOLATION)
-- ----------------------------------------------------------------------------
create table if not exists public.student_profiles (
  id text primary key,
  auth_user_id uuid unique references auth.users(id) on delete set null,
  username text unique not null,
  password_verifier_sha256 text not null default '',
  salt text not null default '',
  name_ar text not null,
  name_en text not null default '',
  country_ar text not null default '',
  country_en text not null default '',
  native_lang_ar text not null default '',
  native_lang_en text not null default '',
  timezone text not null default 'UTC+2',
  avatar text not null default '',
  cefr text not null default 'A1',
  track text not null default 'FUSHA_MSA',
  completed_hours int not null default 0,
  attendance_rate int not null default 100,
  last_session text default '',
  goal_ar text not null default '',
  goal_en text not null default '',
  clinical_notes text not null default '',
  six_pillars jsonb not null default '{}'::jsonb,
  psych_profile jsonb not null default '{}'::jsonb,
  assigned_decks jsonb not null default '[]'::jsonb,
  assignments jsonb not null default '[]'::jsonb,
  homework_tasks jsonb not null default '[]'::jsonb,
  assigned_exams jsonb not null default '[]'::jsonb,
  notifications jsonb not null default '[]'::jsonb,
  class_notes jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.student_profiles enable row level security;

drop policy if exists "Students read own profile or Admin reads all" on public.student_profiles;
create policy "Students read own profile or Admin reads all"
  on public.student_profiles for select
  using (public.is_tutor_admin() or (auth.uid() is not null and auth.uid() = auth_user_id));

drop policy if exists "Students update own profile" on public.student_profiles;
create policy "Students update own profile"
  on public.student_profiles for update
  using (auth.uid() is not null and auth.uid() = auth_user_id)
  with check (auth.uid() is not null and auth.uid() = auth_user_id);

drop policy if exists "Admin full control over student_profiles" on public.student_profiles;
create policy "Admin full control over student_profiles"
  on public.student_profiles for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

create table if not exists public.student_sessions (
  session_token text primary key,
  student_id text not null references public.student_profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours')
);

alter table public.student_sessions enable row level security;

drop policy if exists "Admin manage student_sessions" on public.student_sessions;
create policy "Admin manage student_sessions"
  on public.student_sessions for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 6. CURRICULUM LESSONS (PUBLIC UNLOCKED VS RESTRICTED TO ALLOWED STUDENTS)
-- ----------------------------------------------------------------------------
create table if not exists public.lessons (
  id text primary key,
  sort_order int not null default 0,
  track text not null,
  cefr text not null,
  content_type text not null default 'NATIVE',
  is_locked boolean not null default false,
  access_mode text not null default 'PUBLIC',
  allowed_student_ids jsonb not null default '[]'::jsonb,
  curriculum_ar text not null default '',
  curriculum_en text not null default '',
  unit_ar text not null default '',
  unit_en text not null default '',
  title_ar text not null,
  title_en text not null,
  summary_ar text not null default '',
  summary_en text not null default '',
  duration int not null default 45,
  dialogue_lines jsonb not null default '[]'::jsonb,
  vocabulary jsonb not null default '[]'::jsonb,
  grammar_note_ar text not null default '',
  grammar_note_en text not null default '',
  visual_blocks jsonb not null default '[]'::jsonb,
  quiz jsonb,
  html_source text,
  updated_at timestamptz not null default now()
);

alter table public.lessons enable row level security;

drop policy if exists "Read public lessons or authorized student lessons" on public.lessons;
create policy "Read public lessons or authorized student lessons"
  on public.lessons for select
  using (
    (not is_locked and access_mode <> 'RESTRICTED')
    or public.is_tutor_admin()
    or exists (
      select 1 from public.student_profiles sp
      where sp.auth_user_id = auth.uid()
        and public.lessons.allowed_student_ids ? sp.id
    )
  );

drop policy if exists "Admin manage lessons" on public.lessons;
create policy "Admin manage lessons"
  on public.lessons for all
  using (public.is_tutor_admin())
  with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 7. FLASHCARD DECKS, EXAMS & VERSION HISTORY
-- ----------------------------------------------------------------------------
create table if not exists public.flashcard_decks (
  id text primary key,
  sort_order int not null default 0,
  title_ar text not null,
  title_en text not null default '',
  cefr text not null default 'A1',
  track text not null default 'FUSHA_MSA',
  cards jsonb not null default '[]'::jsonb,
  source_html text,
  source_filename text,
  preferred_view_mode text not null default 'STUDY',
  updated_at timestamptz not null default now()
);

alter table public.flashcard_decks enable row level security;
drop policy if exists "Authenticated or public read flashcard_decks" on public.flashcard_decks;
create policy "Authenticated or public read flashcard_decks" on public.flashcard_decks for select using (true);
drop policy if exists "Admin manage flashcard_decks" on public.flashcard_decks;
create policy "Admin manage flashcard_decks" on public.flashcard_decks for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

create table if not exists public.exams (
  id text primary key,
  title_ar text not null,
  title_en text not null default '',
  track text not null default 'CLASSICAL_HERITAGE',
  cefr text not null default 'B1',
  duration_minutes int not null default 20,
  questions jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.exams enable row level security;
drop policy if exists "Authenticated read exams" on public.exams;
create policy "Authenticated read exams" on public.exams for select using (auth.role() = 'authenticated' or public.is_tutor_admin());
drop policy if exists "Admin manage exams" on public.exams;
create policy "Admin manage exams" on public.exams for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

create table if not exists public.content_revisions (
  revision_id text primary key,
  operation_type text not null,
  label text not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null
);

alter table public.content_revisions enable row level security;
drop policy if exists "Admin manage content_revisions" on public.content_revisions;
create policy "Admin manage content_revisions" on public.content_revisions for all using (public.is_tutor_admin()) with check (public.is_tutor_admin());

-- ----------------------------------------------------------------------------
-- 8. SERVER-SIDE STUDENT AUTHENTICATION & ISOLATED PORTAL RPC FUNCTIONS
--    Enforces strict server-side password verification and ensures each
--    student can ONLY read/update their own profile and authorized lessons.
-- ----------------------------------------------------------------------------
create or replace function public.authenticate_student_rpc(
  p_username text,
  p_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_stu public.student_profiles%rowtype;
  v_expected_hash text;
  v_payload text;
  v_token text;
begin
  if coalesce(trim(p_username), '') = '' or coalesce(trim(p_password), '') = '' then
    return jsonb_build_object('ok', false, 'error', 'MISSING_CREDENTIALS');
  end if;

  select * into v_stu
  from public.student_profiles
  where lower(trim(username)) = lower(trim(p_username))
  limit 1;

  if not found or coalesce(v_stu.password_verifier_sha256, '') = '' then
    return jsonb_build_object('ok', false, 'error', 'INVALID_STUDENT_CREDENTIALS');
  end if;

  if coalesce(trim(v_stu.salt), '') <> '' then
    v_payload := trim(v_stu.salt) || ':' || p_password;
  else
    v_payload := p_password;
  end if;

  v_expected_hash := encode(digest(v_payload, 'sha256'), 'hex');
  if v_expected_hash <> v_stu.password_verifier_sha256 then
    return jsonb_build_object('ok', false, 'error', 'INVALID_STUDENT_CREDENTIALS');
  end if;

  delete from public.student_sessions where expires_at < now();
  v_token := encode(gen_random_bytes(32), 'hex');

  insert into public.student_sessions (session_token, student_id, expires_at)
  values (v_token, v_stu.id, now() + interval '24 hours');

  return jsonb_build_object(
    'ok', true,
    'session_token', v_token,
    'student_id', v_stu.id,
    'student', (to_jsonb(v_stu) - 'password_verifier_sha256' - 'salt')
  );
end;
$$;

grant execute on function public.authenticate_student_rpc(text, text) to anon, authenticated;

create or replace function public.get_student_authorized_state_rpc(
  p_session_token text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_student_id text;
  v_stu jsonb;
  v_lessons jsonb;
  v_decks jsonb;
  v_exams jsonb;
begin
  -- Resolve student identity from session_token OR Supabase Auth JWT
  if coalesce(trim(p_session_token), '') <> '' then
    select s.student_id into v_student_id
    from public.student_sessions s
    where s.session_token = trim(p_session_token)
      and s.expires_at > now()
    limit 1;
  end if;

  if v_student_id is null and auth.uid() is not null then
    select sp.id into v_student_id
    from public.student_profiles sp
    where sp.auth_user_id = auth.uid()
    limit 1;
  end if;

  if v_student_id is null then
    return jsonb_build_object('ok', false, 'error', 'UNAUTHORIZED_STUDENT_SESSION');
  end if;

  select (to_jsonb(sp) - 'password_verifier_sha256' - 'salt')
  into v_stu
  from public.student_profiles sp
  where sp.id = v_student_id;

  if v_stu is null then
    return jsonb_build_object('ok', false, 'error', 'STUDENT_NOT_FOUND');
  end if;

  select coalesce(jsonb_agg(to_jsonb(l) order by l.sort_order asc), '[]'::jsonb)
  into v_lessons
  from public.lessons l
  where (not l.is_locked and l.access_mode <> 'RESTRICTED')
     or (l.allowed_student_ids ? v_student_id);

  select coalesce(jsonb_agg(to_jsonb(d) order by d.sort_order asc), '[]'::jsonb)
  into v_decks
  from public.flashcard_decks d;

  select coalesce(jsonb_agg(to_jsonb(e)), '[]'::jsonb)
  into v_exams
  from public.exams e;

  return jsonb_build_object(
    'ok', true,
    'student_id', v_student_id,
    'student', v_stu,
    'lessons', v_lessons,
    'flashcard_decks', v_decks,
    'exams', v_exams
  );
end;
$$;

grant execute on function public.get_student_authorized_state_rpc(text) to anon, authenticated;

create or replace function public.student_update_own_portal_rpc(
  p_session_token text,
  p_student_id text,
  p_homework_tasks jsonb default null,
  p_assigned_exams jsonb default null,
  p_notifications jsonb default null,
  p_six_pillars jsonb default null,
  p_psych_profile jsonb default null,
  p_teacher_notification jsonb default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_verified_student_id text;
  v_now timestamptz := now();
begin
  if coalesce(trim(p_session_token), '') <> '' then
    select s.student_id into v_verified_student_id
    from public.student_sessions s
    where s.session_token = trim(p_session_token)
      and s.expires_at > now()
    limit 1;
  end if;

  if v_verified_student_id is null and auth.uid() is not null then
    select sp.id into v_verified_student_id
    from public.student_profiles sp
    where sp.auth_user_id = auth.uid()
    limit 1;
  end if;

  if v_verified_student_id is null or v_verified_student_id <> coalesce(trim(p_student_id), '') then
    return jsonb_build_object('ok', false, 'error', 'FORBIDDEN_CROSS_STUDENT_ACCESS');
  end if;

  update public.student_profiles
  set
    homework_tasks = coalesce(p_homework_tasks, homework_tasks),
    assigned_exams = coalesce(p_assigned_exams, assigned_exams),
    notifications  = coalesce(p_notifications, notifications),
    six_pillars    = coalesce(p_six_pillars, six_pillars),
    psych_profile  = coalesce(p_psych_profile, psych_profile),
    updated_at     = v_now
  where id = v_verified_student_id;

  if p_teacher_notification is not null and jsonb_typeof(p_teacher_notification) = 'object' then
    insert into public.teacher_notifications (
      id, type, student_id, student_name, rating, text, date, read, created_at
    ) values (
      coalesce(p_teacher_notification ->> 'id', 'tnotif-' || extract(epoch from v_now)::bigint::text),
      coalesce(p_teacher_notification ->> 'type', 'HOMEWORK_SUBMISSION'),
      v_verified_student_id,
      coalesce(p_teacher_notification ->> 'student_name', ''),
      coalesce((p_teacher_notification ->> 'rating')::int, 5),
      coalesce(p_teacher_notification ->> 'text', ''),
      coalesce(p_teacher_notification ->> 'date', to_char(v_now, 'YYYY-MM-DD')),
      false,
      v_now
    )
    on conflict (id) do update set
      text = excluded.text,
      read = excluded.read;
  end if;

  return jsonb_build_object(
    'ok', true,
    'student_id', v_verified_student_id,
    'updated_at', v_now
  );
end;
$$;

grant execute on function public.student_update_own_portal_rpc(text, text, jsonb, jsonb, jsonb, jsonb, jsonb, jsonb) to anon, authenticated;

create or replace function public.logout_student_session_rpc(
  p_session_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(trim(p_session_token), '') <> '' then
    delete from public.student_sessions where session_token = trim(p_session_token);
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function public.logout_student_session_rpc(text) to anon, authenticated;

-- Ensure singleton default row exists in platform_settings
insert into public.platform_settings (id, schema_version)
values ('default', '6.0.0-PRODUCTION-RELEASE')
on conflict (id) do nothing;

commit;

-- ============================================================================
-- POST-SETUP INSTRUCTION: GRANT TUTOR ADMIN ROLE TO YOUR SUPABASE AUTH USER
-- ============================================================================
-- After creating your account in Supabase Dashboard -> Authentication -> Users,
-- copy your User UUID and run EITHER of the following commands in SQL Editor:
--
-- Option A (Insert into public.admin_users table):
--   insert into public.admin_users (user_id, email)
--   values ('00000000-0000-0000-0000-000000000000', 'your-email@example.com')
--   on conflict (user_id) do nothing;
--
-- Option B (Set app_metadata.role = 'tutor_admin' in auth.users):
--   update auth.users
--   set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role": "tutor_admin"}'::jsonb
--   where id = '00000000-0000-0000-0000-000000000000';
-- ============================================================================