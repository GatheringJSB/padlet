import "server-only";

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let adminClient: SupabaseClient | null = null;

function getRequiredEnv(name: string) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} 환경 변수가 설정되지 않았습니다.`);
  }
  return value;
}

export function getSupabaseAdmin() {
  if (adminClient) return adminClient;

  const url = getRequiredEnv("NEXT_PUBLIC_SUPABASE_URL");
  const secretKey = getRequiredEnv("SUPABASE_SECRET_KEY");
  if (!secretKey.startsWith("sb_secret_")) {
    throw new Error(
      "SUPABASE_SECRET_KEY 형식이 올바르지 않습니다. sb_secret_ 으로 시작하는 새 Secret key를 사용해 주세요.",
    );
  }

  adminClient = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  return adminClient;
}

export function getSupabaseServerAnon() {
  const url = getRequiredEnv("NEXT_PUBLIC_SUPABASE_URL");
  const publishableKey = getRequiredEnv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY");

  return createClient(url, publishableKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
