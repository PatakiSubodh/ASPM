import { ArrowUpRight, Check } from "lucide-react";
import Link from "next/link";
import { unstable_rethrow } from "next/navigation";

import { DismissibleNotice } from "@/components/dismissible-notice";
import { AddAssetButton, AddRepositoryButton } from "@/components/repositories/add-buttons";
import { ScanToggle } from "@/components/repositories/scan-toggle";
import { AssetActions, RepositoryActions } from "@/components/repositories/row-menus";
import { BUTTON_PRIMARY } from "@/components/repositories/styles";
import { StateCard } from "@/components/state-card";
import { apiHeaders, redirectIfUnauthorized } from "@/lib/api";
import {
  type Asset,
  type AssetSummary,
  type CatalogEntry,
  relativeTime,
} from "@/lib/findings";
import type { InstallationSummary } from "@/lib/github";
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

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    cache: "no-store",
    headers: await apiHeaders(),
  });
  redirectIfUnauthorized(res.status);
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function RepositoriesPage() {
  let entries: CatalogEntry[] = [];
  let assets: AssetSummary[] = [];
  let installations: InstallationSummary[] = [];
  let error: string | null = null;

  try {
    [entries, assets, installations] = await Promise.all([
      getJson<CatalogEntry[]>("/repositories"),
      getJson<AssetSummary[]>("/assets"),
      getJson<InstallationSummary[]>("/github/installations"),
    ]);
  } catch (e) {
    unstable_rethrow(e);
    error = e instanceof Error ? e.message : "Unknown error";
  }

  const assetOptions = assets.map(({ asset }) => asset);
  const usedBy = new Map<string, string[]>();
  for (const { repository, assets: deployed } of entries) {
    for (const asset of deployed) {
      usedBy.set(asset.name, [...(usedBy.get(asset.name) ?? []), repository.name]);
    }
  }

  const steps = [
    {
      title: "Add your code",
      body: "A repository is the source code ASPM checks for vulnerable packages and risky code.",
      done: entries.length > 0,
    },
    {
      title: "Add where it runs",
      body: "An asset is a service, container or server. Say which environment it is and whether the internet can reach it.",
      done: assets.length > 0,
    },
    {
      title: "Connect the two",
      body: "Use Link assets on a repository. Its vulnerabilities are then ranked by how exposed that asset is.",
      done: entries.some((e) => e.assets.length > 0),
    },
  ];
  const current = steps.findIndex((s) => !s.done);
  const revokedCount = entries.filter((e) => e.repository.access_revoked).length;
  const needsPicking =
    installations.some((i) => i.installation.repository_selection === "all") &&
    entries.some(
      (e) =>
        e.repository.source === "github" &&
        e.repository.selected === false &&
        !e.repository.access_revoked,
    );

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
        <p className="max-w-2xl font-mono text-sm text-muted-foreground">
          ASPM ranks every vulnerability by how exposed the place it runs is. To do that, it needs
          to know your code and where that code is deployed.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load your repositories">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && installations.length === 0 && (
        <section
          className="animate-rise brutal flex flex-wrap items-center justify-between gap-5 bg-acid p-6"
          style={{ animationDelay: "30ms" }}
        >
          <div className="max-w-xl space-y-2">
            <h2 className="text-2xl font-bold tracking-tight">Connect your GitHub</h2>
            <p className="text-sm leading-snug">
              Install the ASPM GitHub App, choose the repositories you want checked, and they
              appear here without typing any addresses.
            </p>
          </div>
          <Link
            href="/settings/github"
            className={cn(BUTTON_PRIMARY, "inline-flex items-center justify-center bg-card hover:bg-card")}
          >
            Connect GitHub
          </Link>
        </section>
      )}

      {!error && needsPicking && (
        <DismissibleNotice className="animate-rise brutal bg-acid p-5 text-sm leading-snug">
          You gave ASPM access to all your repositories, so none are scanned yet. Switch on{" "}
          <strong>Auto-scan</strong> for the ones you want checked.
        </DismissibleNotice>
      )}

      {!error && revokedCount > 0 && (
        <section className="animate-rise brutal bg-crit p-5 text-sm leading-snug">
          {revokedCount} {revokedCount === 1 ? "repository" : "repositories"} can no longer be
          reached, because GitHub was disconnected or access was removed on GitHub. Their findings
          stay visible, but they are not scanned. Reconnect or refresh in{" "}
          <Link href="/settings/github" className="font-bold underline decoration-2 underline-offset-4">
            GitHub settings
          </Link>
          .
        </section>
      )}

      {!error && current !== -1 && (
        <section
          className="animate-rise grid gap-5 md:grid-cols-3"
          style={{ animationDelay: "60ms" }}
          aria-label="How it works"
        >
          {steps.map((step, index) => (
            <div
              key={step.title}
              className={cn(
                "brutal relative flex flex-col gap-4 p-5",
                index === current ? "bg-acid" : "bg-card",
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-5xl font-bold tabular-nums tracking-tighter">
                  {String(index + 1).padStart(2, "0")}
                </span>
                {step.done ? (
                  <span className="inline-flex items-center gap-1 border-2 border-foreground bg-foreground px-2 py-1 font-mono text-[11px] font-bold uppercase tracking-widest text-acid">
                    <Check className="size-3.5" />
                    Done
                  </span>
                ) : index === current ? (
                  <span className="-rotate-3 border-2 border-foreground bg-foreground px-2 py-1 font-mono text-[11px] font-bold uppercase tracking-widest text-acid">
                    Start here
                  </span>
                ) : null}
              </div>
              <div className="space-y-2">
                <h2 className="text-xl font-bold tracking-tight">{step.title}</h2>
                <p className="text-sm leading-snug">{step.body}</p>
              </div>
              {index === 0 && (
                <div className="mt-auto">
                  <AddRepositoryButton action={createRepository} prominent={index === current} />
                </div>
              )}
              {index === 1 && (
                <div className="mt-auto">
                  <AddAssetButton action={createAsset} prominent={index === current} />
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      {!error && (
        <section className="animate-rise space-y-5" style={{ animationDelay: "120ms" }}>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="flex items-center gap-3 text-3xl font-bold tracking-tighter">
                Repositories
                <Count value={entries.length} />
              </h2>
              <p className="font-mono text-xs text-muted-foreground">
                The code ASPM watches. Automatic scans of repositories added here start once your
                GitHub account is connected.
              </p>
            </div>
            {current === -1 && <AddRepositoryButton action={createRepository} />}
          </div>

          {entries.length === 0 ? (
            <Empty>No repositories yet. Add your first one with the button in step 01.</Empty>
          ) : (
            <ul className="brutal divide-y-2 divide-foreground bg-card">
              {entries.map(({ repository, assets: deployed, open_total }) => {
                const selected = repository.selected !== false;
                return (
                  <li
                    key={repository.name}
                    className="grid gap-5 px-5 py-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1.6fr)_auto_auto] lg:items-center"
                  >
                    <div className="min-w-0 space-y-1">
                      <a
                        href={repository.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group inline-flex max-w-full items-center gap-0.5 font-mono text-base font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
                      >
                        <span className="truncate">{repository.name}</span>
                        <ArrowUpRight className="size-4 shrink-0 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                      </a>
                      <p className="font-mono text-[11px] uppercase text-muted-foreground">
                        {[repository.language, repository.branch ?? "default branch"]
                          .filter(Boolean)
                          .join(" · ")}
                        {repository.access_revoked && (
                          <span className="ml-2 inline-block -rotate-2 border-2 border-foreground bg-crit px-2 py-0.5 font-bold tracking-widest text-foreground shadow-brutal-sm">
                            Access revoked
                          </span>
                        )}
                      </p>
                    </div>

                    <div className="space-y-1.5">
                      <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                        Runs on
                      </p>
                      <AssetChips assets={deployed} />
                    </div>

                    <div className="space-y-1.5 lg:text-right">
                      <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                        Open findings
                      </p>
                      <p className="flex items-center gap-2 lg:justify-end">
                        <Count value={open_total} highlight={open_total > 0} />
                        <span
                          title={repository.last_scanned_at}
                          className="font-mono text-[11px] uppercase text-muted-foreground"
                        >
                          {repository.last_scanned_at
                            ? `Scanned ${relativeTime(repository.last_scanned_at)}`
                            : "Never scanned"}
                        </span>
                      </p>
                    </div>

                    <div className="flex items-center gap-5">
                      <div className="flex flex-col items-center gap-1.5">
                        <ScanToggle
                          name={repository.name}
                          selected={selected}
                          action={setRepositorySelected.bind(null, repository.name)}
                        />
                        <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                          Auto-scan
                        </span>
                      </div>
                      <RepositoryActions
                        name={repository.name}
                        url={repository.url}
                        branch={repository.branch}
                        assets={assetOptions}
                        linked={deployed.map((a) => a.name)}
                        branchAction={setRepositoryBranch.bind(null, repository.name)}
                        assetsAction={setRepositoryAssets.bind(null, repository.name)}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}

      {!error && (
        <section className="animate-rise space-y-5" style={{ animationDelay: "180ms" }}>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="flex items-center gap-3 text-3xl font-bold tracking-tighter">
                Assets
                <Count value={assets.length} />
              </h2>
              <p className="font-mono text-xs text-muted-foreground">
                The places your code runs. <strong>Public</strong> means the internet can reach it.
              </p>
            </div>
            {current !== 1 && <AddAssetButton action={createAsset} />}
          </div>

          {assets.length === 0 ? (
            <Empty>No assets yet. Add one with the button in step 02.</Empty>
          ) : (
            <ul className="brutal divide-y-2 divide-foreground bg-card">
              {assets.map(({ asset, open_total }) => {
                const repos = usedBy.get(asset.name) ?? [];
                return (
                  <li
                    key={asset.name}
                    className="grid gap-4 px-5 py-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1.6fr)_auto_auto] lg:items-center"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            "truncate font-mono text-base font-bold",
                            asset.status === "decommissioned" && "line-through",
                          )}
                        >
                          {asset.name}
                        </span>
                        {asset.internet_facing && <PublicSticker />}
                        <AssetStickers asset={asset} />
                      </div>
                      <p className="font-mono text-[11px] uppercase text-muted-foreground">
                        {asset.environment} · {asset.type}
                        {asset.source === "docker" && asset.last_discovered_at && (
                          <span title={asset.last_discovered_at}>
                            {" "}
                            · Seen {relativeTime(asset.last_discovered_at)}
                          </span>
                        )}
                      </p>
                    </div>

                    <div className="space-y-1.5">
                      <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                        Runs code from
                      </p>
                      {repos.length > 0 ? (
                        <p className="font-mono text-sm">{repos.join(", ")}</p>
                      ) : (
                        <p className="font-mono text-sm text-muted-foreground">
                          No repository linked yet
                        </p>
                      )}
                    </div>

                    <div className="space-y-1.5 lg:text-right">
                      <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                        Open findings
                      </p>
                      <Count value={open_total} highlight={open_total > 0} />
                    </div>

                    <AssetActions
                      asset={asset}
                      updateAction={updateAsset.bind(null, asset.name)}
                      deleteAction={deleteAsset.bind(null, asset.name)}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

function Count({ value, highlight }: { value: number; highlight?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-7 min-w-9 items-center justify-center border-2 border-foreground px-2 font-mono text-xs font-bold tabular-nums",
        highlight ? "bg-acid shadow-brutal-sm" : "bg-card text-muted-foreground",
      )}
    >
      {String(value).padStart(2, "0")}
    </span>
  );
}

function PublicSticker() {
  return (
    <span className="-rotate-3 border-2 border-foreground bg-foreground px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-widest text-acid">
      ● Public
    </span>
  );
}

function Empty({ children }: { children: string }) {
  return (
    <div className="border-2 border-dashed border-foreground bg-card p-8 font-mono text-sm text-muted-foreground">
      {children}
    </div>
  );
}

function AssetChips({ assets }: { assets: Asset[] }) {
  if (assets.length === 0) {
    return (
      <span
        title="Link an asset so findings can be ranked by where the code runs"
        className="inline-flex border-2 border-dashed border-foreground px-2 py-1 font-mono text-xs font-bold uppercase tracking-widest"
      >
        Not linked yet
      </span>
    );
  }
  return (
    <ul className="flex flex-wrap gap-2">
      {assets.map((asset) => (
        <li
          key={asset.name}
          title={asset.status === "decommissioned" ? "Decommissioned" : asset.type}
          className="inline-flex items-center gap-2 border-2 border-foreground bg-card px-2 py-1 shadow-brutal-sm"
        >
          <span
            className={cn(
              "font-mono text-xs font-bold",
              asset.status === "decommissioned" && "line-through",
            )}
          >
            {asset.name}
          </span>
          <span className="font-mono text-[11px] uppercase text-muted-foreground">
            {asset.environment}
          </span>
          {asset.internet_facing && <PublicSticker />}
          <AssetStickers asset={asset} />
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

function AssetStickers({ asset }: { asset: Asset }) {
  return (
    <>
      {asset.source === "docker" && (
        <span className="rotate-2 border-2 border-foreground bg-acid px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm">
          ● Docker
        </span>
      )}
      {asset.status === "decommissioned" && (
        <span
          title={asset.decommissioned_at}
          className="-rotate-2 border-2 border-foreground bg-low px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-widest line-through shadow-brutal-sm"
        >
          Decommissioned
        </span>
      )}
    </>
  );
}
