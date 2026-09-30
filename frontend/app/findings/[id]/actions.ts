"use server";

import { refresh } from "next/cache";

import { apiHeaders } from "@/lib/api";
import { type FindingStatus, STATUSES } from "@/lib/findings";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function updateStatus(id: string, formData: FormData) {
  const status = String(formData.get("status") ?? "");
  if (!STATUSES.includes(status as FindingStatus)) {
    throw new Error(`Invalid status: ${status}`);
  }
  const headers = new Headers(apiHeaders());
  headers.set("Content-Type", "application/json");
  const res = await fetch(`${API_URL}/findings/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers,
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  refresh();
}
