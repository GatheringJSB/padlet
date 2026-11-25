import { deleteMemoWithPassword } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function POST(request: Request) {
  return deleteMemoWithPassword(request);
}
