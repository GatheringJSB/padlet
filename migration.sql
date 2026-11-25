-- MINDLET migration.sql — 기존 DB 변경 전용
--
-- ■ 적용 전제조건 (실행 전에 반드시 확인)
--   1. public.memos 테이블이 이미 있고 id(uuid), title, content 컬럼이 있어야 합니다.
--      테이블이 없으면 이 파일이 아니라 schema.sql을 사용하세요.
--   2. 먼저 DB 백업(Supabase 대시보드 Backups 또는 pg_dump)을 만드세요.
--   3. 아래 "확인 SQL"을 먼저 따로 실행해 현재 구조와 데이터를 확인하세요.
--   4. 이 스크립트는 하나의 트랜잭션입니다. 해시 누락·형식 오류가 있으면 예외로 중단되고
--      아무 것도 변경되지 않습니다(memos.password_hash 컬럼도 삭제되지 않습니다).
--   5. memos 외에 memo_credentials / admin_sessions / rate_limits 및 아래 함수 3개만 다룹니다.
--      public 스키마 전체나 관련 없는 테이블의 권한은 변경하지 않습니다.
--   6. 이 4개 테이블에 붙어 있던 기존 RLS 정책은 모두 삭제되고 필요한 정책만 다시 만들어집니다.
--
-- ■ 확인 SQL (읽기 전용, 먼저 실행)
--   select column_name, data_type, is_nullable
--     from information_schema.columns
--    where table_schema = 'public' and table_name = 'memos' order by ordinal_position;
--   select count(*) as memos, count(password_hash) as memos_with_legacy_hash from public.memos;
--     -- (password_hash 컬럼이 없으면 이 쿼리는 오류가 나며, 그 경우 아래 2번 확인으로 충분합니다)
--   select count(*) as credentials from public.memo_credentials;   -- 테이블이 없으면 오류
--   select policyname, cmd, roles from pg_policies
--    where schemaname = 'public' and tablename in ('memos','memo_credentials');
--   select grantee, privilege_type from information_schema.role_table_grants
--    where table_schema = 'public' and table_name in ('memos','memo_credentials');

begin;

create extension if not exists pgcrypto;

-- 1) 전제조건 확인
do $$
begin
  if to_regclass('public.memos') is null then
    raise exception 'public.memos not found. Use schema.sql for a new database.';
  end if;

  if (
    select count(*) from information_schema.columns
    where table_schema = 'public' and table_name = 'memos'
      and column_name in ('id', 'title', 'content')
  ) <> 3 then
    raise exception 'public.memos must have id, title and content columns.';
  end if;
end $$;

-- 2) memos 에 필요한 컬럼 보강 (기존 값은 그대로 유지)
alter table public.memos add column if not exists color text not null default '#fef3c7';
alter table public.memos add column if not exists position integer not null default 0;
alter table public.memos add column if not exists created_at timestamptz not null default now();
alter table public.memos add column if not exists updated_at timestamptz not null default now();
alter table public.memos alter column color set default '#fef3c7';

-- 3) 비공개 암호 테이블 (이미 있으면 그대로 사용)
create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

-- 기존 외래키가 CASCADE가 아닐 수 있으므로 memos 참조 FK를 CASCADE로 다시 만든다.
do $$
declare
  fk record;
begin
  for fk in
    select conname
    from pg_constraint
    where conrelid = 'public.memo_credentials'::regclass
      and contype = 'f'
      and confrelid = 'public.memos'::regclass
  loop
    execute format('alter table public.memo_credentials drop constraint %I', fk.conname);
  end loop;

  alter table public.memo_credentials
    add constraint memo_credentials_memo_id_fkey
    foreign key (memo_id) references public.memos(id) on delete cascade;
end $$;

-- 4) 기존 memos.password_hash → memo_credentials 이전, 검증, 공개 테이블에서 제거
do $$
declare
  has_legacy boolean;
begin
  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'password_hash'
  ) into has_legacy;

  if has_legacy then
    execute $q$
      insert into public.memo_credentials (memo_id, password_hash)
      select id, password_hash from public.memos where password_hash is not null
      on conflict (memo_id) do nothing
    $q$;

    -- 이미 다른 해시가 credentials에 있다면 어느 쪽이 맞는지 알 수 없으므로 중단
    if exists (
      select 1
      from public.memos m
      join public.memo_credentials c on c.memo_id = m.id
      where m.password_hash is not null and c.password_hash <> m.password_hash
    ) then
      raise exception 'Migration aborted: memo_credentials hash differs from legacy memos.password_hash.';
    end if;
  end if;

  -- 누락 검증: 모든 메모에 해시가 있어야 한다
  if exists (
    select 1 from public.memos m
    where not exists (select 1 from public.memo_credentials c where c.memo_id = m.id)
  ) then
    raise exception 'Migration aborted: some memos have no password hash.';
  end if;

  -- 고아 행/형식 검증 (memo_id는 PK이므로 중복은 불가능하다)
  if exists (
    select 1 from public.memo_credentials where password_hash !~ '^\$2[aby]\$[0-9]{2}\$.{53}$'
  ) then
    raise exception 'Migration aborted: non-bcrypt password hash found.';
  end if;

  if has_legacy then
    -- 컬럼과 함께 해당 컬럼의 NOT NULL/CHECK/UNIQUE 제약도 사라진다
    execute 'alter table public.memos drop column password_hash';
  end if;
end $$;

-- ============================================================
-- 이하 schema.sql 과 동일한 구성
-- ============================================================

create table if not exists public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create table if not exists public.rate_limits (
  key text primary key,
  window_start timestamptz not null default now(),
  hit_count integer not null default 0
);

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists memos_position_idx on public.memos (position asc, created_at desc);
create index if not exists admin_sessions_expires_at_idx on public.admin_sessions (expires_at);
create index if not exists rate_limits_window_start_idx on public.rate_limits (window_start);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists memos_set_updated_at on public.memos;
create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

drop function if exists public.create_memo_with_credentials(text, text, text, text);
create function public.create_memo_with_credentials(
  p_title text,
  p_content text,
  p_password_hash text,
  p_color text default '#fef3c7'
)
returns public.memos
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  inserted_memo public.memos;
begin
  if char_length(p_title) < 1 or char_length(p_title) > 80 then
    raise exception 'Invalid title length';
  end if;

  if char_length(p_content) < 1 or char_length(p_content) > 2000 then
    raise exception 'Invalid content length';
  end if;

  if p_password_hash is null or p_password_hash !~ '^\$2[aby]\$[0-9]{2}\$.{53}$' then
    raise exception 'Invalid password hash';
  end if;

  insert into public.memos (title, content, color, position)
  values (p_title, p_content, coalesce(nullif(p_color, ''), '#fef3c7'), 0)
  returning * into inserted_memo;

  insert into public.memo_credentials (memo_id, password_hash)
  values (inserted_memo.id, p_password_hash);

  return inserted_memo;
end;
$$;

drop function if exists public.rate_limit_hit(text, integer, integer);
create function public.rate_limit_hit(
  p_key text,
  p_limit integer,
  p_window_seconds integer
)
returns boolean
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  v_count integer;
begin
  if p_key is null or p_key = '' or p_limit < 1 or p_window_seconds < 1 then
    raise exception 'Invalid rate limit arguments';
  end if;

  if random() < 0.02 then
    delete from public.rate_limits where window_start < now() - interval '1 day';
  end if;

  insert into public.rate_limits as r (key, window_start, hit_count)
  values (p_key, now(), 1)
  on conflict (key) do update
  set
    window_start = case
      when r.window_start <= now() - make_interval(secs => p_window_seconds)
        then now() else r.window_start end,
    hit_count = case
      when r.window_start <= now() - make_interval(secs => p_window_seconds)
        then 1 else r.hit_count + 1 end
  returning hit_count into v_count;

  return v_count <= p_limit;
end;
$$;

drop function if exists public.rate_limit_reset(text);
create function public.rate_limit_reset(p_key text)
returns void
language sql
security invoker
set search_path = public, pg_temp
as $$
  delete from public.rate_limits where key = p_key;
$$;

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

do $$
declare
  pol record;
begin
  for pol in
    select policyname, tablename
    from pg_policies
    where schemaname = 'public'
      and tablename in ('memos', 'memo_credentials', 'admin_sessions', 'rate_limits')
  loop
    execute format('drop policy %I on public.%I', pol.policyname, pol.tablename);
  end loop;
end $$;

create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);

revoke all on table public.memos from anon, authenticated;
revoke all on table public.memo_credentials from anon, authenticated;
revoke all on table public.admin_sessions from anon, authenticated;
revoke all on table public.rate_limits from anon, authenticated;

grant select on table public.memos to anon, authenticated;

grant all on table public.memos to service_role;
grant all on table public.memo_credentials to service_role;
grant all on table public.admin_sessions to service_role;
grant all on table public.rate_limits to service_role;

revoke all on function public.create_memo_with_credentials(text, text, text, text)
  from public, anon, authenticated;
revoke all on function public.rate_limit_hit(text, integer, integer)
  from public, anon, authenticated;
revoke all on function public.rate_limit_reset(text)
  from public, anon, authenticated;

grant execute on function public.create_memo_with_credentials(text, text, text, text) to service_role;
grant execute on function public.rate_limit_hit(text, integer, integer) to service_role;
grant execute on function public.rate_limit_reset(text) to service_role;

commit;

-- ■ 적용 후 검증 (읽기 전용)
--   select count(*) from public.memos;                                   -- 이전과 동일해야 함
--   select count(*) from public.memos m
--     where not exists (select 1 from public.memo_credentials c where c.memo_id = m.id);  -- 0
--   select column_name from information_schema.columns
--    where table_schema='public' and table_name='memos' and column_name='password_hash'; -- 0행
