import { NextResponse } from "next/server";
import { createServerSupabaseClient } from "@/lib/supabase-server";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const next = searchParams.get("next") ?? "/";


  const safeNext = next.startsWith("/") ? next : "/";

  if (code) {
    const supabase = await createServerSupabaseClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      const response = NextResponse.redirect(`${origin}${safeNext}`);
      response.headers.set("Cache-Control", "no-store, max-age=0");
      return response;
    }
  }

  return NextResponse.redirect(`${origin}/login?error=auth_failed`);
}