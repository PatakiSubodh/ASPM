import { Plug, RefreshCw } from "lucide-react";
import { unstable_rethrow } from "next/navigation";

import { GitHubActionButton } from "@/components/github/action-button";
import { DisconnectButton } from "@/components/github/disconnect-button";
import { StateCard } from "@/components/state-card";
import { apiHeaders, redirectIfUnauthorized } from "@/lib/api";
import { relativeTime } from "@/lib/findings";
import { INSTALL_ERRORS, type InstallationSummary, manageInstallationUrl } from "@/lib/github";
import { cn } from "@/lib/utils";

import { connectGitHub, disconnectGitHub, refreshGitHubRepositories } from "./actions";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getInstallations(): Promise<InstallationSummary[]> {
  const res = await fetch(`${API_URL}/github/installations`, {
    cache: "no-store",
    headers: await apiHeaders(),
  });
  redirectIfUnauthorized(res.status);
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function GitHubSettingsPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error: code } = await searchParams;
  let installations: InstallationSummary[] = [];
  let error: string | null = null;

  try {
    installations = await getInstallations();
  } catch (e) {
    unstable_rethrow(e);
    error = e instanceof Error ? e.message : "Unknown error";
  }

  const notice = code ? (INSTALL_ERRORS[code] ?? INSTALL_ERRORS.github) : null;
  const connected = installations.length > 0;

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          Settings / GitHub
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Your code,{" "}
          <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
            connected
          </span>
          .
        </h1>
        <p className="max-w-2xl font-mono text-sm text-muted-foreground">
          Install the ASPM GitHub App on the repositories you want checked. ASPM gets read-only
          access to code and nothing else, and you choose which repositories it can see.
        </p>
      </section>

      {notice && (
        <StateCard tone="error" title="GitHub connection failed">
          {notice}
        </StateCard>
      )}

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load your GitHub connections">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && (
        <section className="animate-rise space-y-5" style={{ animationDelay: "60ms" }}>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-3xl font-bold tracking-tighter">Connections</h2>
              <p className="font-mono text-xs text-muted-foreground">
                Each GitHub account or organization you installed the app on.
              </p>
            </div>
            <div className="flex flex-wrap items-start gap-4">
              {connected && (
                <GitHubActionButton
                  action={refreshGitHubRepositories}
                  pendingLabel="Refreshing…"
                  doneLabel="Repositories updated."
                >
                  <RefreshCw className="size-4" />
                  Refresh repositories
                </GitHubActionButton>
              )}
              <GitHubActionButton
                action={connectGitHub}
                pendingLabel="Opening GitHub…"
                prominent={!connected}
              >
                <Plug className="size-4" />
                {connected ? "Add another account" : "Connect GitHub"}
              </GitHubActionButton>
            </div>
          </div>

          {!connected ? (
            <div className="border-2 border-dashed border-foreground bg-card p-8 font-mono text-sm text-muted-foreground">
              Nothing connected yet. Choose Connect GitHub, pick the account and repositories on
              GitHub, and you come back here with your repositories listed.
            </div>
          ) : (
            <ul className="brutal divide-y-2 divide-foreground bg-card">
              {installations.map(({ installation, repositories, revoked }) => (
                <li
                  key={installation.id}
                  className="grid gap-4 px-5 py-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_auto] lg:items-center"
                >
                  <div className="min-w-0 space-y-1">
                    <p className="truncate font-mono text-base font-bold">
                      {installation.account_login ?? `Installation ${installation.id}`}
                    </p>
                    <p className="font-mono text-[11px] uppercase text-muted-foreground">
                      {installation.account_type ?? "Account"} ·{" "}
                      {installation.repository_selection === "all"
                        ? "All repositories"
                        : "Selected repositories"}
                      {installation.updated_at && ` · Synced ${relativeTime(installation.updated_at)}`}
                    </p>
                  </div>
                  <div className="space-y-1.5">
                    <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                      Repositories
                    </p>
                    <p className="font-mono text-sm">
                      {repositories} granted
                      {revoked > 0 && ` · ${revoked} no longer accessible`}
                    </p>
                  </div>
                  <div className="flex items-center gap-4">
                    <span
                      className={cn(
                        "inline-flex w-fit -rotate-2 border-2 border-foreground px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm",
                        installation.status === "active" ? "bg-acid" : "bg-low",
                      )}
                    >
                      {installation.status === "active" ? "● Active" : "Suspended"}
                    </span>
                    <DisconnectButton
                      account={installation.account_login ?? `installation ${installation.id}`}
                      manageUrl={manageInstallationUrl(installation)}
                      action={disconnectGitHub.bind(null, installation.id)}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
