import { NextResponse, type NextRequest } from "next/server";

import { apiHeaders } from "@/lib/api";
import { GITHUB_INSTALLING_COOKIE, GITHUB_NONCE_COOKIE } from "@/lib/github";
import { cookieOptions } from "@/lib/github-server";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const FAILURES: Record<number, string> = {
  400: "state",
  502: "github",
  503: "unconfigured",
};

interface LinkResult {
  linked: unknown[];
  conflicts: number;
  install_url: string | null;
}

function go(request: NextRequest, path: string) {
  const response = NextResponse.redirect(new URL(path, request.url));
  response.cookies.delete(GITHUB_NONCE_COOKIE);
  return response;
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const code = params.get("code");
  const state = params.get("state");
  const nonce = request.cookies.get(GITHUB_NONCE_COOKIE)?.value;
  const installing = request.cookies.has(GITHUB_INSTALLING_COOKIE);

  if (params.get("error")) return go(request, "/settings/github?error=denied");
  if (!code || !state) return go(request, "/settings/github?error=invalid");
  if (!nonce) return go(request, "/settings/github?error=state");

  const headers = new Headers(await apiHeaders());
  headers.set("Content-Type", "application/json");

  let res: Response;
  try {
    res = await fetch(`${API_URL}/github/link`, {
      method: "POST",
      cache: "no-store",
      headers,
      body: JSON.stringify({ code, state, nonce }),
    });
  } catch {
    return go(request, "/settings/github?error=unreachable");
  }

  if (res.status === 401) return go(request, "/auth/expired");
  if (!res.ok) {
    return go(request, `/settings/github?error=${FAILURES[res.status] ?? "github"}`);
  }

  const result = (await res.json()) as LinkResult;
  if (result.linked.length > 0) {
    const response = go(request, "/repositories");
    response.cookies.delete(GITHUB_INSTALLING_COOKIE);
    return response;
  }
  if (result.conflicts > 0) return go(request, "/settings/github?error=conflict");
  if (!result.install_url || installing) return go(request, "/settings/github?error=noinstall");

  const response = NextResponse.redirect(result.install_url);
  response.cookies.delete(GITHUB_NONCE_COOKIE);
  response.cookies.set(GITHUB_INSTALLING_COOKIE, "1", cookieOptions());
  return response;
}
