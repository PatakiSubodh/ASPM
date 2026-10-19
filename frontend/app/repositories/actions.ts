"use server";

import { redirect } from "next/navigation";

import { apiHeaders } from "@/lib/api";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function send(method: string, path: string, body?: unknown): Promise<number> {
  const headers = new Headers(await apiHeaders());
  headers.set("Content-Type", "application/json");
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
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

function done(message: string): never {
  redirect(`/repositories?message=${message}`);
}

function fail(error: string): never {
  redirect(`/repositories?error=${error}`);
}

export async function createRepository(formData: FormData) {
  const url = text(formData, "url");
  const name = repositoryName(url);
  if (!name) fail("repo-invalid");
  const body: Record<string, string> = { name, url };
  const branch = text(formData, "branch");
  const language = text(formData, "language");
  if (branch) body.branch = branch;
  if (language) body.language = language;
  const status = await send("POST", "/repositories", body);
  if (status === 201) done("repo-added");
  fail(status === 409 ? "repo-exists" : "repo-invalid");
}

export async function setRepositorySelected(name: string, selected: boolean) {
  const status = await send("PATCH", `/repositories/${encodeURIComponent(name)}`, { selected });
  if (status === 200) redirect("/repositories");
  fail("failed");
}

export async function setRepositoryBranch(name: string, formData: FormData) {
  const branch = text(formData, "branch");
  const status = await send("PATCH", `/repositories/${encodeURIComponent(name)}`, {
    branch: branch || null,
  });
  if (status === 200) done("branch-saved");
  fail(status === 404 ? "repo-unknown" : "failed");
}

export async function setRepositoryAssets(name: string, formData: FormData) {
  const assets = formData.getAll("assets").map(String);
  const status = await send("PUT", `/repositories/${encodeURIComponent(name)}/assets`, { assets });
  if (status === 200) done("assets-saved");
  fail(status === 422 ? "asset-unknown" : "failed");
}

export async function createAsset(formData: FormData) {
  const body = {
    name: text(formData, "name"),
    environment: text(formData, "environment"),
    type: text(formData, "type"),
    internet_facing: formData.get("internet_facing") === "on",
  };
  if (!body.name || !body.environment || !body.type) fail("asset-invalid");
  const status = await send("POST", "/assets", body);
  if (status === 201) done("asset-added");
  fail(status === 409 ? "asset-exists" : "asset-invalid");
}

export async function updateAsset(name: string, formData: FormData) {
  const body = {
    environment: text(formData, "environment"),
    type: text(formData, "type"),
    internet_facing: formData.get("internet_facing") === "on",
  };
  if (!body.environment || !body.type) fail("asset-invalid");
  const status = await send("PATCH", `/assets/${encodeURIComponent(name)}`, body);
  if (status === 200) done("asset-saved");
  fail(status === 404 ? "asset-unknown" : "failed");
}

export async function deleteAsset(name: string) {
  const status = await send("DELETE", `/assets/${encodeURIComponent(name)}`);
  if (status === 204) done("asset-deleted");
  fail(status === 404 ? "asset-unknown" : "failed");
}
