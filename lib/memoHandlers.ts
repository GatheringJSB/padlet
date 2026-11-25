import "server-only";

import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import { hashPassword, isFourDigitPassword, verifyPassword } from "@/lib/password";
import {
  LIMITS,
  UUID_PATTERN,
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
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const PASTEL_COLORS = [
  "#fef3c7",
  "#dbeafe",
  "#dcfce7",
  "#fce7f3",
  "#f3e8ff",
  "#fed7aa",
  "#e0f2fe",
  "#fae8ff",
];

const length = (value: string) => Array.from(value).length;

export async function createMemo(request: Request) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  try {
    const allowed = await consumeRateLimit(
      rateKey.create(getClientIp(request)),
      LIMITS.create,
    );
    if (!allowed) return tooManyRequests();

    const body = await readJson(request);
    if (!body) return errorResponse("잘못된 요청입니다.", 400);

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const content = typeof body.content === "string" ? body.content.trim() : "";

    if (!title || !content) {
      return errorResponse("제목과 내용을 모두 입력해 주세요.", 400);
    }
    if (length(title) > 80 || length(content) > 2000) {
      return errorResponse("메모가 허용된 길이를 초과했습니다.", 400);
    }
    if (!isFourDigitPassword(body.password)) {
      return errorResponse("삭제 비밀번호는 숫자 4자리여야 합니다.", 400);
    }

    let color: string;
    if (body.color === undefined || body.color === null || body.color === "") {
      color = PASTEL_COLORS[Math.floor(Math.random() * PASTEL_COLORS.length)];
    } else if (typeof body.color === "string" && PASTEL_COLORS.includes(body.color)) {
      color = body.color;
    } else {
      return errorResponse("허용되지 않은 색상입니다.", 400);
    }

    const passwordHash = await hashPassword(body.password);
    const { data, error } = await getSupabaseAdmin().rpc("create_memo_with_credentials", {
      p_title: title,
      p_content: content,
      p_color: color,
      p_password_hash: passwordHash,
    });
    if (error) throw new Error("create memo rpc failed");

    return NextResponse.json({ memo: data }, { status: 201 });
  } catch (error) {
    return internalError("create memo", error);
  }
}

export async function deleteMemoWithPassword(request: Request, routeId?: string) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  try {
    const ip = getClientIp(request);
    if (!(await consumeRateLimit(rateKey.delete(ip), LIMITS.delete))) {
      return tooManyRequests();
    }

    const body = await readJson(request);
    const id = routeId ?? body?.id;
    if (
      !body ||
      typeof id !== "string" ||
      !UUID_PATTERN.test(id) ||
      !isFourDigitPassword(body.password)
    ) {
      return errorResponse("메모와 숫자 4자리 비밀번호를 확인해 주세요.", 400);
    }

    // Every attempt is counted before bcrypt runs; a correct password clears it.
    const failKey = rateKey.deleteFail(id, ip);
    if (!(await consumeRateLimit(failKey, LIMITS.deleteFail))) {
      return tooManyRequests();
    }

    const supabase = getSupabaseAdmin();
    const { data: credential, error: readError } = await supabase
      .from("memo_credentials")
      .select("password_hash")
      .eq("memo_id", id)
      .maybeSingle();
    if (readError) throw new Error("credential read failed");
    if (!credential) return errorResponse("메모를 찾을 수 없습니다.", 404);

    if (!(await verifyPassword(body.password, credential.password_hash))) {
      return errorResponse("삭제 비밀번호가 일치하지 않습니다.", 403);
    }

    const { error: deleteError } = await supabase.from("memos").delete().eq("id", id);
    if (deleteError) throw new Error("memo delete failed");

    await resetRateLimit(failKey);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return internalError("delete memo", error);
  }
}

export async function adminDeleteMemo(request: Request, routeId?: string) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  if (!(await isAdminRequest())) {
    return errorResponse("관리자 인증이 필요합니다.", 401);
  }

  try {
    const body = routeId ? null : await readJson(request);
    const id = routeId ?? body?.id;
    if (typeof id !== "string" || !UUID_PATTERN.test(id)) {
      return errorResponse("잘못된 요청입니다.", 400);
    }

    const { error } = await getSupabaseAdmin().from("memos").delete().eq("id", id);
    if (error) throw new Error("admin delete failed");
    return NextResponse.json({ ok: true });
  } catch (error) {
    return internalError("admin delete memo", error);
  }
}

export async function adminDeleteAllMemos(request: Request) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  if (!(await isAdminRequest())) {
    return errorResponse("관리자 인증이 필요합니다.", 401);
  }

  try {
    const { error } = await getSupabaseAdmin().from("memos").delete().not("id", "is", null);
    if (error) throw new Error("admin delete all failed");
    return NextResponse.json({ ok: true });
  } catch (error) {
    return internalError("admin delete all", error);
  }
}

export async function adminListMemos() {
  if (!(await isAdminRequest())) {
    return errorResponse("관리자 인증이 필요합니다.", 401);
  }

  try {
    const { data, error } = await getSupabaseAdmin()
      .from("memos")
      .select("id,title,content,color,position,created_at,updated_at")
      .order("created_at", { ascending: false });
    if (error) throw new Error("admin list failed");
    return NextResponse.json({ memos: data ?? [] });
  } catch (error) {
    return internalError("admin list memos", error);
  }
}
