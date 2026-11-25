import { NextResponse } from "next/server";
import { ADMIN_COOKIE, adminCookieOptions, revokeAdminSession } from "@/lib/adminSession";
import { internalError, rejectForeignOrigin } from "@/lib/security";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const foreign = rejectForeignOrigin(request);
  if (foreign) return foreign;

  try {
    await revokeAdminSession();
  } catch (error) {
    return internalError("admin logout", error);
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, "", adminCookieOptions(0));
  return response;
}
