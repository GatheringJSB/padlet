import "server-only";

import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const LIMITS = {
  create: { limit: 20, windowSeconds: 600 },
  delete: { limit: 30, windowSeconds: 600 },
  deleteFail: { limit: 5, windowSeconds: 600 },
  adminLogin: { limit: 5, windowSeconds: 900 },
} as const;

export function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export function internalError(label: string, error: unknown) {
  console.error(label, error instanceof Error ? error.message : "unknown error");
  return errorResponse("요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.", 500);
}

// Origin must be present and match the origin of the URL this server received.
export function isSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export function rejectForeignOrigin(request: Request) {
  return isSameOrigin(request)
    ? null
    : errorResponse("허용되지 않은 요청입니다.", 403);
}

// Vercel overwrites these headers with the real client IP and does not forward
// external values, so they cannot be spoofed there:
// https://vercel.com/docs/headers/request-headers
export function getClientIp(request: Request) {
  const candidate =
    request.headers.get("x-vercel-forwarded-for") ??
    request.headers.get("x-real-ip") ??
    request.headers.get("x-forwarded-for");
  const ip = candidate?.split(",")[0]?.trim();
  return ip || "unknown";
}

function bucketKey(scope: string, ...parts: string[]) {
  const digest = createHash("sha256").update(parts.join("|")).digest("hex");
  return `${scope}:${digest}`;
}

export const rateKey = {
  create: (ip: string) => bucketKey("create", ip),
  delete: (ip: string) => bucketKey("delete", ip),
  deleteFail: (memoId: string, ip: string) => bucketKey("delfail", memoId, ip),
  adminLogin: (ip: string) => bucketKey("adminlogin", ip),
};

// Returns true when the request is allowed. Throws if the store is unavailable,
// so callers fail closed.
export async function consumeRateLimit(
  key: string,
  { limit, windowSeconds }: { limit: number; windowSeconds: number },
) {
  const { data, error } = await getSupabaseAdmin().rpc("rate_limit_hit", {
    p_key: key,
    p_limit: limit,
    p_window_seconds: windowSeconds,
  });
  if (error) throw new Error("rate limit store error");
  return data === true;
}

export async function resetRateLimit(key: string) {
  const { error } = await getSupabaseAdmin().rpc("rate_limit_reset", { p_key: key });
  if (error) throw new Error("rate limit store error");
}

export function tooManyRequests() {
  return errorResponse("요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.", 429);
}

export async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await request.json();
    return body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
