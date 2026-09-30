import { ArrowDown, ArrowRight, ArrowUpRight } from "lucide-react";
import type { ReactNode } from "react";

import { RiskBadge } from "@/components/risk-badge";
import { StateCard } from "@/components/state-card";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiHeaders } from "@/lib/api";
import {
  type Asset,
  type FindingDetail,
  type Repository,
  type Risk,
  relativeTime,
  STATUSES,
  statusLabel,
  type Vulnerability,
} from "@/lib/findings";
import { severityBg } from "@/lib/graph";
import { cn } from "@/lib/utils";

import { updateStatus } from "./actions";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getFinding(id: string): Promise<FindingDetail | null> {
  const res = await fetch(`${API_URL}/findings/${encodeURIComponent(id)}`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function FindingPage({
  params,
}: PageProps<"/findings/[id]">) {
  const { id: rawId } = await params;
  let id = rawId;
  try {
    id = decodeURIComponent(rawId);
  } catch {}
  let finding: FindingDetail | null = null;
  let error: string | null = null;

  try {
    finding = await getFinding(id);
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  const vuln = finding?.vulnerability;

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          01 / Findings / {vuln?.id ?? id}
        </p>
        <h1 className="break-all text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
            {vuln?.cve ?? vuln?.id ?? id}
          </span>
          .
        </h1>
        {vuln && (
          <div className="flex flex-wrap items-center gap-3">
            {finding?.risk && <RiskBadge risk={finding.risk} />}
            <Badge
              className={cn(
                "h-6 border-2 border-foreground px-2 font-mono text-[11px] font-bold text-foreground shadow-brutal-sm",
                severityBg[vuln.severity],
              )}
            >
              {vuln.severity}
            </Badge>
            <StatusBadge status={vuln.status} />
            {vuln.cve && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cve)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="group inline-flex items-center gap-0.5 font-mono text-sm font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
              >
                NVD
                <ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
              </a>
            )}
          </div>
        )}
      </section>

      {error && (
        <StateCard tone="error" title="API unreachable">
          {error}. Start the backend on <code>{API_URL}</code> and Neo4j with{" "}
          <code>docker compose up -d</code>.
        </StateCard>
      )}

      {!error && !finding && (
        <StateCard tone="empty" title="Finding not found">
          No vulnerability with id <code>{id}</code> in the graph.
        </StateCard>
      )}

      {finding && vuln && (
        <>
          <Card
            className="brutal animate-rise bg-card"
            style={{ animationDelay: "80ms" }}
          >
            <CardHeader>
              <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest">
                Description
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="max-w-3xl text-lg leading-snug">
                {vuln.description}
              </p>
            </CardContent>
          </Card>

          <StatusCard vuln={vuln} />

          <section
            className="animate-rise space-y-4"
            style={{ animationDelay: "140ms" }}
          >
            <p className="font-mono text-[11px] font-bold uppercase tracking-widest">
              Attack path
            </p>
            <div className="grid items-stretch gap-4 md:grid-cols-[1fr_auto_1fr_auto_1fr]">
              <PathColumn title="Repository" count={finding.repositories.length}>
                {finding.repositories.map((repo) => (
                  <RepoRow key={repo.name} repo={repo} />
                ))}
              </PathColumn>
              <PathArrow />
              <PathColumn title="Vulnerability" count={1} className={severityBg[vuln.severity]}>
                <div className="px-4 py-3 font-mono text-sm font-bold">
                  {vuln.id}
                </div>
              </PathColumn>
              <PathArrow />
              <PathColumn title="Asset" count={finding.assets.length}>
                {finding.assets.map((asset) => (
                  <AssetRow
                    key={asset.name}
                    asset={asset}
                    risk={finding.asset_risks[asset.name]}
                  />
                ))}
              </PathColumn>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function StatusCard({ vuln }: { vuln: Vulnerability }) {
  const meta: [string, string][] = [
    ["First seen", relativeTime(vuln.first_seen)],
    ["Last seen", relativeTime(vuln.last_seen)],
    ["Scanner", vuln.scanner ?? "—"],
    ["Location", vuln.location ?? "—"],
  ];
  if (vuln.resolved_at) meta.push(["Resolved", relativeTime(vuln.resolved_at)]);
  if (vuln.reopened_at) meta.push(["Reopened", relativeTime(vuln.reopened_at)]);

  return (
    <Card
      className="brutal animate-rise bg-card"
      style={{ animationDelay: "110ms" }}
    >
      <CardHeader>
        <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest">
          Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <form
          key={vuln.status}
          action={updateStatus.bind(null, vuln.id)}
          className="flex flex-wrap items-center gap-3"
        >
          <select
            name="status"
            defaultValue={vuln.status}
            aria-label="Finding status"
            className="h-9 border-2 border-foreground bg-card px-3 font-mono text-xs font-bold uppercase tracking-widest shadow-brutal-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-acid"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {statusLabel[s]}
              </option>
            ))}
          </select>
          <button
            type="submit"
            className={cn(
              buttonVariants({ variant: "outline", size: "lg" }),
              "brutal brutal-lift shadow-brutal-sm bg-acid px-4 font-mono text-xs font-bold uppercase tracking-widest hover:bg-acid",
            )}
          >
            Update
          </button>
        </form>
        <dl className="grid gap-4 sm:grid-cols-3">
          {meta.map(([label, value]) => (
            <div key={label} className="space-y-1">
              <dt className="font-mono text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                {label}
              </dt>
              <dd className="break-all font-mono text-sm">{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function PathColumn({
  title,
  count,
  className,
  children,
}: {
  title: string;
  count: number;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Card className={cn("brutal gap-0 bg-card py-0", className)}>
      <div className="flex items-center justify-between border-b-2 border-foreground bg-foreground px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-widest text-background">
        <span>{title}</span>
        <span className="tabular-nums">{String(count).padStart(2, "0")}</span>
      </div>
      {count === 0 ? (
        <div className="px-4 py-3 font-mono text-[11px] uppercase text-muted-foreground">
          None linked
        </div>
      ) : (
        <div className="divide-y-2 divide-dashed divide-foreground/20">
          {children}
        </div>
      )}
    </Card>
  );
}

function PathArrow() {
  return (
    <div className="flex items-center justify-center">
      <ArrowRight className="hidden size-6 md:block" />
      <ArrowDown className="size-6 md:hidden" />
    </div>
  );
}

function RepoRow({ repo }: { repo: Repository }) {
  return (
    <div className="space-y-1 px-4 py-3">
      <a
        href={repo.url}
        target="_blank"
        rel="noopener noreferrer"
        className="group inline-flex items-center gap-0.5 font-mono text-sm font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
      >
        {repo.name}
        <ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
      </a>
      {repo.language && (
        <p className="font-mono text-[11px] uppercase text-muted-foreground">
          {repo.language}
        </p>
      )}
    </div>
  );
}

function AssetRow({ asset, risk }: { asset: Asset; risk?: Risk }) {
  return (
    <div className="space-y-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        {risk && <RiskBadge risk={risk} />}
        <span className="font-mono text-sm font-bold">{asset.name}</span>
        {asset.internet_facing && (
          <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
            ● Public
          </Badge>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant="outline"
          className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
        >
          {asset.environment}
        </Badge>
        <span className="font-mono text-[11px] uppercase text-muted-foreground">
          {asset.type}
        </span>
      </div>
    </div>
  );
}
