import { cookies } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";

import { apiHeaders } from "@/lib/api";
import { GITHUB_NONCE_COOKIE } from "@/lib/github";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const FAILURES: Record<number, string> = {
  400: "state",
  404: "notfound",
  409: "conflict",
  502: "github",
  503: "unconfigured",
};

function go(request: NextRequest, path: string) {
  return NextResponse.redirect(new URL(path, request.url));
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const installationId = Number(params.get("installation_id"));
  const state = params.get("state");
  const isUpdate = params.get("setup_action") === "update";

  const store = await cookies();
  const nonce = store.get(GITHUB_NONCE_COOKIE)?.value;
  store.delete(GITHUB_NONCE_COOKIE);

  if (!Number.isSafeInteger(installationId) || installationId <= 0) {
    return go(request, "/settings/github?error=invalid");
  }
  if (!state && !isUpdate) return go(request, "/settings/github?error=invalid");
  if (state && !nonce) return go(request, "/settings/github?error=state");

  const headers = new Headers(await apiHeaders());
  headers.set("Content-Type", "application/json");

  let res: Response;
  try {
    res = state
      ? await fetch(`${API_URL}/github/installations`, {
          method: "POST",
          cache: "no-store",
          headers,
          body: JSON.stringify({ installation_id: installationId, state, nonce }),
        })
      : await fetch(`${API_URL}/github/installations/${installationId}/reconnect`, {
          method: "POST",
          cache: "no-store",
          headers,
        });
  } catch {
    return go(request, "/settings/github?error=unreachable");
  }

  if (res.status === 401) return go(request, "/auth/expired");
  if (!res.ok) {
    return go(request, `/settings/github?error=${FAILURES[res.status] ?? "github"}`);
  }
  return go(request, "/repositories");
}
