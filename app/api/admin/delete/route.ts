import { adminDeleteMemo } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function POST(request: Request) {
  return adminDeleteMemo(request);
}
