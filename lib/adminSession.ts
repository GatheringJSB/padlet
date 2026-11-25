import "server-only";

import { createHmac, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const ADMIN_COOKIE = "mindlet_admin";
export const ADMIN_SESSION_SECONDS = 60 * 60 * 8;

function sessionSecret() {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "ADMIN_SESSION_SECRET 환경 변수가 없거나 너무 짧습니다. 32자 이상의 무작위 문자열을 설정해 주세요.",
    );
  }
  return secret;
}

function tokenVerifier(token: string) {
  return createHmac("sha256", sessionSecret()).update(token).digest("hex");
}

export function adminCookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict" as const,
    path: "/",
    maxAge,
  };
}

export async function createAdminSession() {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + ADMIN_SESSION_SECONDS * 1000);
  const supabase = getSupabaseAdmin();

  await supabase.from("admin_sessions").delete().lt("expires_at", new Date().toISOString());

  const { error } = await supabase.from("admin_sessions").insert({
    token_hash: tokenVerifier(token),
    expires_at: expiresAt.toISOString(),
  });
  if (error) throw new Error("admin session store error");

  return token;
}

export async function isAdminRequest() {
  try {
    const token = (await cookies()).get(ADMIN_COOKIE)?.value;
    if (!token || token.length > 128) return false;

    const { data, error } = await getSupabaseAdmin()
      .from("admin_sessions")
      .select("token_hash")
      .eq("token_hash", tokenVerifier(token))
      .gt("expires_at", new Date().toISOString())
      .maybeSingle();

    return !error && Boolean(data);
  } catch {
    return false;
  }
}

export async function revokeAdminSession() {
  const token = (await cookies()).get(ADMIN_COOKIE)?.value;
  if (!token || token.length > 128) return;

  const { error } = await getSupabaseAdmin()
    .from("admin_sessions")
    .delete()
    .eq("token_hash", tokenVerifier(token));
  if (error) throw new Error("admin session store error");
}
