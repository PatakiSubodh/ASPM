import { NextResponse, type NextRequest } from "next/server";

import { GITHUB_NONCE_COOKIE } from "@/lib/github";
import { cookieOptions, requestAuthorization } from "@/lib/github-server";

const FAILURES: Record<number, string> = {
  0: "unreachable",
  503: "unconfigured",
};

export async function GET(request: NextRequest) {
  const issued = await requestAuthorization();
  if ("status" in issued) {
    if (issued.status === 401) return NextResponse.redirect(new URL("/auth/expired", request.url));
    const code = FAILURES[issued.status] ?? "github";
    return NextResponse.redirect(new URL(`/settings/github?error=${code}`, request.url));
  }
  const response = NextResponse.redirect(issued.url);
  response.cookies.set(GITHUB_NONCE_COOKIE, issued.nonce, cookieOptions());
  return response;
}
