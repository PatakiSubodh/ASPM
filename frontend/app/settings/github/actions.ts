"use server";

import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { apiHeaders, redirectIfUnauthorized } from "@/lib/api";
import { GITHUB_NONCE_COOKIE } from "@/lib/github";
import type { ActionResult } from "@/lib/repositories";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function post(path: string): Promise<Response | null> {
  try {
    return await fetch(`${API_URL}${path}`, {
      method: "POST",
      cache: "no-store",
      headers: await apiHeaders(),
    });
  } catch {
    return null;
  }
}

export async function connectGitHub(): Promise<ActionResult> {
  const res = await post("/github/install-url");
  if (!res) return { error: "The service isn't responding right now. Try again." };
  redirectIfUnauthorized(res.status);
  if (res.status === 503) return { error: "GitHub isn't set up on this server yet." };
  if (!res.ok) return { error: "Couldn't start the GitHub connection. Try again." };
  const { url, nonce } = (await res.json()) as { url: string; nonce: string };
  (await cookies()).set(GITHUB_NONCE_COOKIE, nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 600,
    path: "/",
  });
  redirect(url);
}

export async function disconnectGitHub(installationId: number): Promise<ActionResult> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/github/installations/${installationId}`, {
      method: "DELETE",
      cache: "no-store",
      headers: await apiHeaders(),
    });
  } catch {
    return { error: "The service isn't responding right now. Try again." };
  }
  redirectIfUnauthorized(res.status);
  if (res.status === 404) {
    revalidatePath("/settings/github");
    return { error: "This connection no longer exists. Refresh the page." };
  }
  if (!res.ok) return { error: "Couldn't disconnect. Try again." };
  revalidatePath("/settings/github");
  revalidatePath("/repositories");
  return { ok: true };
}

export async function refreshGitHubRepositories(): Promise<ActionResult> {
  const res = await post("/github/repositories/refresh");
  if (!res) return { error: "The service isn't responding right now. Try again." };
  redirectIfUnauthorized(res.status);
  if (!res.ok) return { error: "GitHub didn't answer. Try again in a moment." };
  revalidatePath("/settings/github");
  revalidatePath("/repositories");
  return { ok: true };
}
