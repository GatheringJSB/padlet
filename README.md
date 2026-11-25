# MINDLET

Next.js(App Router) + Supabase + Vercel 기반 단일 메모 보드입니다. 주소를 아는 사람은 누구나 메모를 보고 쓸 수 있고, 작성자는 자신이 정한 숫자 4자리 암호로, 관리자는 별도 로그인 후 메모를 삭제합니다.

## 로컬 실행

1. 압축을 푼 프로젝트 폴더를 엽니다.
2. `node -v`, `npm -v`로 버전을 확인합니다. 강사가 지정한 버전이 없으면 Node.js 22 이상을 사용합니다.
3. `npm ci`
4. `.env.example`을 `.env.local`로 복사하고 본인의 Supabase 값을 입력합니다.
5. 관리자 암호 해시를 만듭니다(`$` 때문에 셸에서 잘리지 않도록 **파일에 넣을 때 그대로** 붙여 넣으세요).

   ```bash
   node -e "require('bcryptjs').hash(process.argv[1], 12).then(console.log)" "원하는-관리자-암호"
   ```

6. 세션 비밀값을 만듭니다(32자 이상 필수).

   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
   ```

7. Supabase SQL Editor에서 DB 상태에 맞는 SQL을 **하나만** 실행합니다.
   - 새 빈 DB: `schema.sql`
   - 기존 `memos` 데이터가 있는 DB: `migration.sql` (파일 상단의 적용 전제조건과 확인 SQL을 먼저 읽고, 백업 후 실행)
8. `npm run dev` 후 http://localhost:3000 에서 확인합니다.

## 환경 변수

| 이름 | 용도 |
| --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase 프로젝트 URL |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | 브라우저 조회용 Publishable key (`sb_publishable_…`) |
| `SUPABASE_SECRET_KEY` | 서버 전용 Secret key (`sb_secret_…`) |
| `ADMIN_PASSWORD_HASH` | 관리자 암호의 bcrypt 해시 |
| `ADMIN_SESSION_SECRET` | 관리자 세션 HMAC 비밀값 (32자 이상) |

레거시 `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`는 사용하지 않습니다. 비밀값에는 `NEXT_PUBLIC_`을 붙이지 마세요. 누락·형식 오류는 변수 이름만 오류로 표시됩니다.

## Vercel 배포

1. 저장소를 Vercel 프로젝트로 가져옵니다(Framework: Next.js).
2. Project Settings → Environment Variables에 위 5개를 Production/Preview에 등록합니다.
3. 배포 후 보드 로딩, 작성, 삭제, 관리자 로그인을 확인합니다.

## 보안 구조

- 브라우저는 Publishable key로 공개 컬럼(`id,title,content,color,position,created_at,updated_at`)만 조회합니다. `anon`/`authenticated`는 `memos` SELECT 외 권한이 없습니다.
- 암호 해시(`memo_credentials`), 관리자 세션(`admin_sessions`), 요청 제한(`rate_limits`)과 서버 전용 RPC는 `service_role`만 접근합니다.
- 작성은 `create_memo_with_credentials` RPC로 메모와 해시를 원자적으로 저장합니다.
- 요청 제한은 Supabase RPC(`rate_limit_hit`)로 bcrypt 실행 전에 확인하며, 저장소 오류 시 요청을 진행하지 않습니다: 작성 IP당 10분 20회, 삭제 요청 IP당 10분 30회, 메모+IP 조합 삭제 시도 10분 5회(올바른 암호면 초기화), 관리자 로그인 IP당 15분 5회(성공 시 초기화).
- 클라이언트 IP는 Vercel이 덮어쓰는 `x-vercel-forwarded-for`(없으면 `x-real-ip`, `x-forwarded-for`)를 사용합니다. 근거: <https://vercel.com/docs/headers/request-headers>. Vercel 밖에서 직접 호스팅하면 이 헤더는 위조될 수 있으므로 신뢰 가능한 프록시 뒤에서만 사용하세요.
- 모든 상태 변경 API는 `Origin` 헤더가 필수이며, 서버가 받은 요청 URL의 origin과 같아야 합니다.
- 관리자 세션: 무작위 토큰 → HMAC 검증값만 DB 저장, 수명 8시간, 요청마다 DB에서 만료 확인, 로그아웃 시 DB 삭제. 쿠키는 `HttpOnly; SameSite=Strict; Path=/`이며 프로덕션에서 `Secure`.
