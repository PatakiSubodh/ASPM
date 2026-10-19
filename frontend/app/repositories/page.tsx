import { ArrowUpRight } from "lucide-react";

import { AuthNotice } from "@/components/auth-notice";
import { StateCard } from "@/components/state-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiHeaders } from "@/lib/api";
import { FIELD_INPUT, FIELD_LABEL } from "@/lib/auth-styles";
import {
  type Asset,
  type AssetSummary,
  type CatalogEntry,
  relativeTime,
} from "@/lib/findings";
import { cn } from "@/lib/utils";

import {
  createAsset,
  createRepository,
  deleteAsset,
  setRepositoryAssets,
  setRepositoryBranch,
  setRepositorySelected,
  updateAsset,
} from "./actions";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const MESSAGES: Record<string, string> = {
  "repo-added": "Repository added.",
  "assets-saved": "Deployments saved.",
  "branch-saved": "Branch saved.",
  "asset-added": "Asset added.",
  "asset-saved": "Asset saved.",
  "asset-deleted": "Asset deleted.",
};

const ERRORS: Record<string, string> = {
  "repo-invalid": "Enter a repository URL that starts with https:// or http://.",
  "repo-exists": "A repository with that name already exists.",
  "repo-unknown": "That repository no longer exists. Refresh the page and try again.",
  "asset-invalid": "An asset needs a name, an environment and a type.",
  "asset-exists": "An asset with that name already exists.",
  "asset-unknown": "That asset no longer exists. Refresh the page and try again.",
  failed: "Something went wrong. Try again.",
};

const SMALL_BUTTON =
  "brutal-lift h-8 border-2 border-foreground bg-card px-3 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm";
const PRIMARY_BUTTON = `${SMALL_BUTTON} bg-acid`;
const SUMMARY =
  "inline-flex h-8 items-center border-2 border-foreground bg-card px-3 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm";
const CHECKBOX = "size-4 accent-foreground";

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    cache: "no-store",
    headers: await apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function RepositoriesPage({ searchParams }: PageProps<"/repositories">) {
  const { error: errorKey, message: messageKey } = await searchParams;
  let entries: CatalogEntry[] = [];
  let assets: AssetSummary[] = [];
  let error: string | null = null;

  try {
    [entries, assets] = await Promise.all([
      getJson<CatalogEntry[]>("/repositories"),
      getJson<AssetSummary[]>("/assets"),
    ]);
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  const unmapped = entries.filter((e) => e.assets.length === 0).length;
  const errorText = ERRORS[String(errorKey)];
  const messageText = MESSAGES[String(messageKey)];

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          05 / Repositories
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Where code{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            runs
          </span>
          .
        </h1>
        <p className="max-w-xl font-mono text-sm text-muted-foreground">
          Your repositories and the assets each deploys to. Findings inherit these links automatically.
        </p>
      </section>

      {errorText && <AuthNotice tone="error">{errorText}</AuthNotice>}
      {messageText && <AuthNotice tone="info">{messageText}</AuthNotice>}

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load your repositories">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && (
        <Card className="brutal animate-rise gap-0 bg-card py-0" style={{ animationDelay: "60ms" }}>
          <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
            <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
              Add a repository
            </CardTitle>
          </CardHeader>
          <CardContent className="px-6 py-6">
            <form action={createRepository} className="grid items-end gap-4 md:grid-cols-[2fr_1fr_1fr_auto]">
              <div className="space-y-2">
                <Label htmlFor="repo-url" className={FIELD_LABEL}>
                  Repository URL
                </Label>
                <Input
                  id="repo-url"
                  name="url"
                  type="url"
                  required
                  placeholder="https://github.com/org/repo"
                  className={FIELD_INPUT}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="repo-branch" className={FIELD_LABEL}>
                  Branch
                </Label>
                <Input id="repo-branch" name="branch" placeholder="main" className={FIELD_INPUT} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="repo-language" className={FIELD_LABEL}>
                  Language
                </Label>
                <Input id="repo-language" name="language" placeholder="Python" className={FIELD_INPUT} />
              </div>
              <button type="submit" className={cn(PRIMARY_BUTTON, "h-11 px-4")}>
                Add
              </button>
            </form>
          </CardContent>
        </Card>
      )}

      {!error && entries.length === 0 && (
        <StateCard tone="empty" title="No repositories yet">
          Add a repository above. Scanned repositories also appear here automatically.
        </StateCard>
      )}

      {!error && unmapped > 0 && (
        <p
          className="animate-rise font-mono text-[11px] font-bold uppercase tracking-widest"
          style={{ animationDelay: "90ms" }}
        >
          <span className="mr-2 inline-flex h-6 min-w-8 items-center justify-center border-2 border-foreground bg-high px-1.5 tabular-nums shadow-brutal-sm">
            {String(unmapped).padStart(2, "0")}
          </span>
          {unmapped === 1 ? "repository isn't" : "repositories aren't"} linked to a deployment
        </p>
      )}

      {!error && entries.length > 0 && (
        <Card
          className="brutal animate-rise gap-0 bg-card py-0"
          style={{ animationDelay: "120ms" }}
        >
          <CardContent className="px-0">
            <Table>
              <TableHeader className="bg-foreground">
                <TableRow className="border-0 hover:bg-foreground">
                  {["Repository", "Scanning", "Deploys to", "Open", "Last scan"].map((h) => (
                    <TableHead
                      key={h}
                      className="h-11 px-4 font-mono text-[11px] font-bold uppercase tracking-widest text-background"
                    >
                      {h}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map(({ repository, assets: deployed, open_total }) => {
                  const selected = repository.selected !== false;
                  return (
                    <TableRow
                      key={repository.name}
                      className="border-b-2 border-foreground hover:bg-acid/25"
                    >
                      <TableCell className="px-4 py-5 align-top">
                        <a
                          href={repository.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="group inline-flex items-center gap-0.5 font-mono font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
                        >
                          {repository.name}
                          <ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                        </a>
                        <p className="mt-1 font-mono text-[11px] uppercase text-muted-foreground">
                          {[repository.language, repository.branch].filter(Boolean).join(" · ") || "—"}
                        </p>
                        <details className="mt-3">
                          <summary className={SUMMARY}>Branch</summary>
                          <form
                            action={setRepositoryBranch.bind(null, repository.name)}
                            className="mt-3 w-56 space-y-3 border-2 border-foreground bg-card p-3 shadow-brutal-sm"
                          >
                            <Input
                              name="branch"
                              defaultValue={repository.branch ?? ""}
                              placeholder="default branch"
                              aria-label="Branch"
                              className={FIELD_INPUT}
                            />
                            <button type="submit" className={PRIMARY_BUTTON}>
                              Save
                            </button>
                          </form>
                        </details>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <form action={setRepositorySelected.bind(null, repository.name, !selected)}>
                          <button
                            type="submit"
                            title={selected ? "Turn scanning off" : "Turn scanning on"}
                            className={cn(SMALL_BUTTON, selected && "bg-acid")}
                          >
                            {selected ? "● On" : "○ Off"}
                          </button>
                        </form>
                      </TableCell>
                      <TableCell className="min-w-64 whitespace-normal px-4 py-5 align-top">
                        <DeployedAssets assets={deployed} />
                        <details className="mt-3">
                          <summary className={SUMMARY}>Edit</summary>
                          <form
                            action={setRepositoryAssets.bind(null, repository.name)}
                            className="mt-3 space-y-3 border-2 border-foreground bg-card p-3 shadow-brutal-sm"
                          >
                            {assets.length === 0 ? (
                              <p className="font-mono text-[11px] uppercase text-muted-foreground">
                                Add an asset below first.
                              </p>
                            ) : (
                              <ul className="space-y-2">
                                {assets.map(({ asset }) => (
                                  <li key={asset.name}>
                                    <label className="flex items-center gap-2 font-mono text-sm">
                                      <input
                                        type="checkbox"
                                        name="assets"
                                        value={asset.name}
                                        defaultChecked={deployed.some((d) => d.name === asset.name)}
                                        className={CHECKBOX}
                                      />
                                      {asset.name}
                                      <span className="text-[11px] uppercase text-muted-foreground">
                                        {asset.environment}
                                      </span>
                                    </label>
                                  </li>
                                ))}
                              </ul>
                            )}
                            <button type="submit" className={PRIMARY_BUTTON}>
                              Save
                            </button>
                          </form>
                        </details>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <span
                          className={cn(
                            "inline-flex h-6 min-w-8 items-center justify-center border-2 border-foreground px-1.5 font-mono text-[11px] font-bold tabular-nums",
                            open_total > 0 ? "bg-acid shadow-brutal-sm" : "bg-card text-muted-foreground",
                          )}
                        >
                          {String(open_total).padStart(2, "0")}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-nowrap px-4 py-5 align-top font-mono text-sm">
                        {repository.last_scanned_at ? (
                          <span title={repository.last_scanned_at}>
                            {relativeTime(repository.last_scanned_at)}
                          </span>
                        ) : (
                          <span className="text-[11px] uppercase text-muted-foreground">Never</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {!error && (
        <section className="animate-rise space-y-4" style={{ animationDelay: "150ms" }}>
          <p className="font-mono text-[11px] font-bold uppercase tracking-widest">Assets</p>
          <Card className="brutal gap-0 bg-card py-0">
            <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
              <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
                Add an asset
              </CardTitle>
            </CardHeader>
            <CardContent className="px-6 py-6">
              <form
                action={createAsset}
                className="grid items-end gap-4 md:grid-cols-[1.5fr_1fr_1fr_auto_auto]"
              >
                <div className="space-y-2">
                  <Label htmlFor="asset-name" className={FIELD_LABEL}>
                    Name
                  </Label>
                  <Input
                    id="asset-name"
                    name="name"
                    required
                    placeholder="prod-api"
                    className={FIELD_INPUT}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="asset-environment" className={FIELD_LABEL}>
                    Environment
                  </Label>
                  <Input
                    id="asset-environment"
                    name="environment"
                    list="environments"
                    required
                    placeholder="production"
                    className={FIELD_INPUT}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="asset-type" className={FIELD_LABEL}>
                    Type
                  </Label>
                  <Input
                    id="asset-type"
                    name="type"
                    list="asset-types"
                    required
                    placeholder="Docker container"
                    className={FIELD_INPUT}
                  />
                </div>
                <label className="flex h-11 items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-widest">
                  <input type="checkbox" name="internet_facing" className={CHECKBOX} />
                  Public
                </label>
                <button type="submit" className={cn(PRIMARY_BUTTON, "h-11 px-4")}>
                  Add
                </button>
              </form>
              <datalist id="environments">
                <option value="production" />
                <option value="staging" />
                <option value="development" />
              </datalist>
              <datalist id="asset-types">
                <option value="Docker container" />
                <option value="Kubernetes Service" />
                <option value="VM" />
                <option value="Serverless function" />
              </datalist>
            </CardContent>
          </Card>

          {assets.length === 0 ? (
            <StateCard tone="empty" title="No assets yet">
              Add the services your code runs on, then link them to repositories above.
            </StateCard>
          ) : (
            <Card className="brutal gap-0 bg-card py-0">
              <CardContent className="px-0">
                <Table>
                  <TableHeader className="bg-foreground">
                    <TableRow className="border-0 hover:bg-foreground">
                      {["Asset", "Environment", "Type", "Open", ""].map((h, i) => (
                        <TableHead
                          key={`${h}-${i}`}
                          className="h-11 px-4 font-mono text-[11px] font-bold uppercase tracking-widest text-background"
                        >
                          {h}
                        </TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.map(({ asset, open_total }) => (
                      <TableRow
                        key={asset.name}
                        className="border-b-2 border-foreground hover:bg-acid/25"
                      >
                        <TableCell className="px-4 py-5 align-top">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-sm font-bold">{asset.name}</span>
                            {asset.internet_facing && (
                              <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
                                ● Public
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="px-4 py-5 align-top font-mono text-sm lowercase">
                          {asset.environment}
                        </TableCell>
                        <TableCell className="px-4 py-5 align-top font-mono text-[11px] uppercase text-muted-foreground">
                          {asset.type}
                        </TableCell>
                        <TableCell className="px-4 py-5 align-top font-mono text-sm tabular-nums">
                          {String(open_total).padStart(2, "0")}
                        </TableCell>
                        <TableCell className="min-w-56 whitespace-normal px-4 py-5 align-top">
                          <div className="flex flex-wrap items-start gap-2">
                            <details>
                              <summary className={SUMMARY}>Edit</summary>
                              <form
                                action={updateAsset.bind(null, asset.name)}
                                className="mt-3 w-64 space-y-3 border-2 border-foreground bg-card p-3 shadow-brutal-sm"
                              >
                                <Input
                                  name="environment"
                                  list="environments"
                                  required
                                  defaultValue={asset.environment}
                                  aria-label="Environment"
                                  className={FIELD_INPUT}
                                />
                                <Input
                                  name="type"
                                  list="asset-types"
                                  required
                                  defaultValue={asset.type}
                                  aria-label="Type"
                                  className={FIELD_INPUT}
                                />
                                <label className="flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-widest">
                                  <input
                                    type="checkbox"
                                    name="internet_facing"
                                    defaultChecked={asset.internet_facing}
                                    className={CHECKBOX}
                                  />
                                  Public
                                </label>
                                <button type="submit" className={PRIMARY_BUTTON}>
                                  Save
                                </button>
                              </form>
                            </details>
                            <form action={deleteAsset.bind(null, asset.name)}>
                              <button type="submit" className={cn(SMALL_BUTTON, "hover:bg-crit")}>
                                Delete
                              </button>
                            </form>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </section>
      )}
    </div>
  );
}

function DeployedAssets({ assets }: { assets: Asset[] }) {
  if (assets.length === 0) {
    return (
      <Badge
        variant="outline"
        title="This repository isn't linked to a deployment yet"
        className="h-6 border-2 border-dashed border-foreground bg-card px-2 font-mono text-[11px] font-bold uppercase"
      >
        Unmapped
      </Badge>
    );
  }
  return (
    <ul className="space-y-2">
      {assets.map((asset) => (
        <li key={asset.name} className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-bold">{asset.name}</span>
          <Badge
            variant="outline"
            className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
          >
            {asset.environment}
          </Badge>
          {asset.internet_facing && (
            <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
              ● Public
            </Badge>
          )}
          {asset.source === "docker" && (
            <Badge className="h-6 rotate-2 border-2 border-foreground bg-acid px-2 font-mono text-[11px] font-bold uppercase text-foreground shadow-brutal-sm">
              ● Docker
            </Badge>
          )}
          {asset.status === "decommissioned" && (
            <Badge
              title={asset.decommissioned_at}
              className="h-6 -rotate-2 border-2 border-foreground bg-low px-2 font-mono text-[11px] font-bold uppercase text-foreground line-through shadow-brutal-sm"
            >
              Decommissioned
            </Badge>
          )}
          {asset.source === "docker" && asset.last_discovered_at && (
            <span
              title={asset.last_discovered_at}
              className="font-mono text-[11px] uppercase text-muted-foreground"
            >
              Seen {relativeTime(asset.last_discovered_at)}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
