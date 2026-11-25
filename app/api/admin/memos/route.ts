import { adminDeleteAllMemos, adminListMemos } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function GET() {
  return adminListMemos();
}

export async function DELETE(request: Request) {
  return adminDeleteAllMemos(request);
}

export async function POST(request: Request) {
  return adminDeleteAllMemos(request);
}
