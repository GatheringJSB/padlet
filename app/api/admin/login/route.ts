import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  ADMIN_SESSION_SECONDS,
  adminCookieOptions,
  createAdminSession,
} from "@/lib/adminSession";
import { verifyPassword } from "@/lib/password";
import {
  LIMITS,
  consumeRateLimit,
  errorResponse,
  getClientIp,
  internalError,
  rateKey,
  readJson,
  rejectForeignOrigin,
  resetRateLimit,
  tooManyRequests,
} from "@/lib/security";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  try {
    // Every attempt is counted before bcrypt runs; a correct password clears it.
    const key = rateKey.adminLogin(getClientIp(request));
    if (!(await consumeRateLimit(key, LIMITS.adminLogin))) return tooManyRequests();

    const body = await readJson(request);
    if (!body || typeof body.password !== "string" || body.password.length > 200) {
      return errorResponse("잘못된 요청입니다.", 400);
    }

    const adminHash = process.env.ADMIN_PASSWORD_HASH;
    if (!adminHash || !/^\$2[aby]\$/.test(adminHash)) {
      throw new Error("ADMIN_PASSWORD_HASH 환경 변수가 없거나 bcrypt 형식이 아닙니다.");
    }

    if (!(await verifyPassword(body.password, adminHash))) {
      return errorResponse("관리자 비밀번호가 일치하지 않습니다.", 401);
    }

    const token = await createAdminSession();
    await resetRateLimit(key);

    const response = NextResponse.json({ ok: true });
    response.cookies.set(ADMIN_COOKIE, token, adminCookieOptions(ADMIN_SESSION_SECONDS));
    return response;
  } catch (error) {
    return internalError("admin login", error);
  }
}
