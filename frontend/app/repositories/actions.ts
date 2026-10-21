"use server";

import { revalidatePath } from "next/cache";

import { apiHeaders, redirectIfUnauthorized } from "@/lib/api";
import type { ActionResult } from "@/lib/repositories";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function send(method: string, path: string, body?: unknown): Promise<number> {
  const headers = new Headers(await apiHeaders());
  headers.set("Content-Type", "application/json");
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  redirectIfUnauthorized(res.status);
  return res.status;
}

function text(formData: FormData, key: string): string {
  return String(formData.get(key) ?? "").trim();
}

function repositoryName(url: string): string | null {
  try {
    const last = new URL(url).pathname.split("/").filter(Boolean).at(-1);
    return last?.replace(/\.git$/i, "") || null;
  } catch {
    return null;
  }
}

function finish(status: number, expected: number, errors: Record<number, string> = {}): ActionResult {
  if (status === expected) {
    revalidatePath("/repositories");
    return { ok: true };
  }
  return { error: errors[status] ?? "Something went wrong. Try again." };
}

export async function createRepository(formData: FormData): Promise<ActionResult> {
  const url = text(formData, "url");
  const name = repositoryName(url);
  if (!name || !/^https?:\/\//i.test(url)) {
    return { error: "Enter the full repository address, starting with https://" };
  }
  const body: Record<string, string> = { name, url };
  const branch = text(formData, "branch");
  const language = text(formData, "language");
  if (branch) body.branch = branch;
  if (language) body.language = language;
  const status = await send("POST", "/repositories", body);
  return finish(status, 201, {
    409: `A repository called “${name}” is already on your list.`,
    422: "That address doesn't look right. Check it and try again.",
  });
}

export async function setRepositoryBranch(name: string, formData: FormData): Promise<ActionResult> {
  const branch = text(formData, "branch");
  const status = await send("PATCH", `/repositories/${encodeURIComponent(name)}`, {
    branch: branch || null,
  });
  return finish(status, 200, { 404: "This repository no longer exists. Refresh the page." });
}

export async function setRepositorySelected(name: string, selected: boolean): Promise<ActionResult> {
  const status = await send("PATCH", `/repositories/${encodeURIComponent(name)}`, { selected });
  return finish(status, 200, { 404: "This repository no longer exists. Refresh the page." });
}

export async function setRepositoryAssets(name: string, formData: FormData): Promise<ActionResult> {
  const assets = formData.getAll("assets").map(String);
  const status = await send("PUT", `/repositories/${encodeURIComponent(name)}/assets`, { assets });
  return finish(status, 200, {
    404: "This repository no longer exists. Refresh the page.",
    422: "One of those assets no longer exists. Refresh the page.",
  });
}

export async function createAsset(formData: FormData): Promise<ActionResult> {
  const body = {
    name: text(formData, "name"),
    environment: text(formData, "environment"),
    type: text(formData, "type"),
    internet_facing: formData.get("internet_facing") === "on",
  };
  if (!body.name || !body.environment || !body.type) {
    return { error: "Give the asset a name, an environment and a type." };
  }
  const status = await send("POST", "/assets", body);
  return finish(status, 201, {
    409: `An asset called “${body.name.toLowerCase()}” already exists.`,
    422: "That asset isn't valid. Check the fields and try again.",
  });
}

export async function updateAsset(name: string, formData: FormData): Promise<ActionResult> {
  const body = {
    environment: text(formData, "environment"),
    type: text(formData, "type"),
    internet_facing: formData.get("internet_facing") === "on",
  };
  if (!body.environment || !body.type) {
    return { error: "Pick an environment and a type." };
  }
  const status = await send("PATCH", `/assets/${encodeURIComponent(name)}`, body);
  return finish(status, 200, { 404: "This asset no longer exists. Refresh the page." });
}

export async function deleteAsset(name: string): Promise<ActionResult> {
  const status = await send("DELETE", `/assets/${encodeURIComponent(name)}`);
  return finish(status, 204, { 404: "This asset no longer exists. Refresh the page." });
}
