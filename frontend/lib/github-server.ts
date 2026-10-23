import { apiHeaders } from "@/lib/api";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export const COOKIE_MAX_AGE = 600;

export function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: process.env.NODE_ENV === "production",
    maxAge: COOKIE_MAX_AGE,
    path: "/",
  };
}

export async function requestAuthorization(): Promise<
  { url: string; nonce: string } | { status: number }
> {
  try {
    const res = await fetch(`${API_URL}/github/authorize-url`, {
      method: "POST",
      cache: "no-store",
      headers: await apiHeaders(),
    });
    if (!res.ok) return { status: res.status };
    return (await res.json()) as { url: string; nonce: string };
  } catch {
    return { status: 0 };
  }
}
