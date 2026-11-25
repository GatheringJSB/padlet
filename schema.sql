-- MINDLET schema.sql — 신규 빈 DB 전용
-- Supabase SQL Editor에서 한 번 실행합니다. 샘플 데이터는 넣지 않습니다.
-- 기존 memos 테이블이 이미 있다면 이 파일 대신 migration.sql을 사용하세요.
-- 이 스크립트는 MINDLET 전용 4개 테이블과 2~3개 함수만 다루며,
-- public 스키마 전체나 관련 없는 테이블의 권한은 변경하지 않습니다.

begin;

create extension if not exists pgcrypto;

-- ============================================================
-- 테이블
-- ============================================================

create table if not exists public.memos (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 80),
  content text not null check (char_length(content) between 1 and 2000),
  color text not null default '#fef3c7' check (char_length(color) > 0),
  position integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 작성자 암호 bcrypt 해시 (공개 memos 테이블과 분리)
create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

-- 관리자 세션: 원본 토큰이 아닌 HMAC 검증값만 저장
create table if not exists public.admin_sessions (
  token_hash text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- 요청 제한 카운터 (고정 윈도우)
create table if not exists public.rate_limits (
  key text primary key,
  window_start timestamptz not null default now(),
  hit_count integer not null default 0
);

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists memos_position_idx on public.memos (position asc, created_at desc);
create index if not exists admin_sessions_expires_at_idx on public.admin_sessions (expires_at);
create index if not exists rate_limits_window_start_idx on public.rate_limits (window_start);

-- ============================================================
-- 함수 (모두 서버 전용: service_role만 실행 가능)
-- ============================================================

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

-- 메모와 암호 해시를 한 트랜잭션(함수 호출 1회)으로 저장한다.
-- SECURITY INVOKER: service_role이 테이블 권한을 직접 가지므로 DEFINER가 필요 없다.
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

-- 원자적 요청 제한: 허용되면 true. 거부된 요청도 카운트에 포함된다.
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

-- ============================================================
-- RLS
-- ============================================================

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

-- 이 4개 테이블의 기존 정책을 모두 제거한 뒤 필요한 정책만 다시 만든다.
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

-- 공개 정책은 memos 조회 하나뿐이다. 나머지 테이블은 정책이 없으므로 anon/authenticated는 전부 거부된다.
create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);

-- ============================================================
-- GRANT (RLS와 별도로 명시적으로 정리)
-- ============================================================

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
