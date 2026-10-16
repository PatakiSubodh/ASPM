import { NextResponse, type NextRequest } from "next/server";

import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
    const code = request.nextUrl.searchParams.get("code");
    const next = request.nextUrl.searchParams.get("next");
    const target = next?.startsWith("/") && !next.startsWith("//") ? next : "/";
    if (code) {
        const supabase = await createClient();
        const { error } = await supabase.auth.exchangeCodeForSession(code);
        if (!error) return NextResponse.redirect(new URL(target, request.url));
    }
    const failure = next ? "confirm" : "oauth";
    return NextResponse.redirect(new URL(`/login?error=${failure}`, request.url));
}
