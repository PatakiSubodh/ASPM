import { ArrowRight, ArrowUpRight } from "lucide-react";
import Link from "next/link";

import { RiskBadge } from "@/components/risk-badge";
import { ScanWarning } from "@/components/scan-warning";
import { StateCard } from "@/components/state-card";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiHeaders } from "@/lib/api";
import { type FailingScan, type Finding, findingHref, relativeTime } from "@/lib/findings";
import { SEVERITIES, type Severity, severityBg } from "@/lib/graph";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const FILTERS = [
  { value: "active", label: "Active" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "All" },
];

async function getFindings(status: string): Promise<Finding[]> {
  const query = status === "active" ? "" : `?status=${encodeURIComponent(status)}`;
  const res = await fetch(`${API_URL}/findings${query}`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

async function getFailingScans(): Promise<FailingScan[]> {
  try {
    const res = await fetch(`${API_URL}/scans/failing`, {
      cache: "no-store",
      headers: apiHeaders(),
    });
    return res.ok ? await res.json() : [];
  } catch {
    return [];
  }
}

export default async function Home({ searchParams }: PageProps<"/">) {
  const { status: rawStatus } = await searchParams;
  const status =
    FILTERS.find((f) => f.value === rawStatus)?.value ?? FILTERS[0].value;
  let findings: Finding[] = [];
  let error: string | null = null;
  const failingPromise = getFailingScans();

  try {
    findings = await getFindings(status);
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }
  const failing = await failingPromise;

  findings.sort(
    (a, b) =>
      b.risk.score - a.risk.score ||
      SEVERITIES.indexOf(a.vulnerability.severity) -
        SEVERITIES.indexOf(b.vulnerability.severity),
  );

  const counts = Object.fromEntries(
    SEVERITIES.map((s) => [
      s,
      findings.filter((f) => f.vulnerability.severity === s).length,
    ]),
  ) as Record<Severity, number>;

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          01 / Findings
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          What&apos;s{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            exposed
          </span>
          .
        </h1>
        <p className="max-w-xl font-mono text-sm text-muted-foreground">
          Repository → vulnerability → production asset, ranked by risk.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load findings">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && <ScanWarning failing={failing} />}

      {!error && (
        <nav className="animate-rise flex flex-wrap gap-3">
          {FILTERS.map(({ value, label }) => (
            <Link
              key={value}
              href={value === "active" ? "/" : `/?status=${value}`}
              aria-current={value === status ? "page" : undefined}
              className={cn(
                "brutal-lift border-2 border-foreground px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm",
                value === status ? "bg-acid" : "bg-card",
              )}
            >
              {label}
            </Link>
          ))}
        </nav>
      )}

      {!error && findings.length === 0 && (
        <StateCard
          tone="empty"
          title={status === "active" ? "Nothing exposed" : "No matches"}
        >
          {status === "active"
            ? "No open findings right now. New issues appear here as soon as a scan reports them."
            : "No findings with this status. Try another filter."}
        </StateCard>
      )}

      {!error && findings.length > 0 && (
        <>
          <section className="grid grid-cols-2 gap-4 sm:grid-cols-4 sm:gap-6">
            {SEVERITIES.map((severity, i) => (
              <Card
                key={severity}
                style={{ animationDelay: `${80 + i * 60}ms` }}
                className={cn(
                  "brutal brutal-lift animate-rise gap-1 px-5 py-4",
                  counts[severity] > 0
                    ? severityBg[severity]
                    : "bg-card text-muted-foreground",
                )}
              >
                <span className="text-5xl font-bold tabular-nums tracking-tighter">
                  {String(counts[severity]).padStart(2, "0")}
                </span>
                <span className="font-mono text-[11px] font-bold uppercase tracking-widest">
                  {severity}
                </span>
              </Card>
            ))}
          </section>

          <Card
            className="brutal animate-rise gap-0 bg-card py-0"
            style={{ animationDelay: "360ms" }}
          >
            <CardContent className="px-0">
              <Table>
                <TableHeader className="bg-foreground">
                  <TableRow className="border-0 hover:bg-foreground">
                    {["Risk", "Sev", "Status", "Vulnerability", "Path", "Env", "Exposure", "Seen"].map(
                      (h) => (
                        <TableHead
                          key={h}
                          className="h-11 px-4 font-mono text-[11px] font-bold uppercase tracking-widest text-background"
                        >
                          {h}
                        </TableHead>
                      ),
                    )}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((f) => (
                    <TableRow
                      key={`${f.vulnerability.id}:${f.asset?.name ?? ""}`}
                      className="border-b-2 border-foreground hover:bg-acid/25"
                    >
                      <TableCell className="px-4 py-5 align-top">
                        <RiskBadge risk={f.risk} />
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <Badge
                          className={cn(
                            "h-6 border-2 border-foreground px-2 font-mono text-[11px] font-bold text-foreground shadow-brutal-sm",
                            severityBg[f.vulnerability.severity],
                          )}
                        >
                          {f.vulnerability.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <StatusBadge status={f.vulnerability.status} />
                      </TableCell>
                      <TableCell className="min-w-64 max-w-md whitespace-normal px-4 py-5 align-top">
                        <Link
                          href={findingHref(f.vulnerability.id)}
                          className="font-mono font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
                        >
                          {f.vulnerability.cve ?? f.vulnerability.id}
                        </Link>
                        <p className="mt-1 text-sm leading-snug text-muted-foreground">
                          {f.vulnerability.description}
                        </p>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <div className="flex items-center gap-2 font-mono text-sm">
                          <a
                            href={f.repository.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="group inline-flex items-center gap-0.5 font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
                          >
                            {f.repository.name}
                            <ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                          </a>
                          <ArrowRight className="size-4 shrink-0" />
                          {f.asset ? (
                            <span>{f.asset.name}</span>
                          ) : (
                            <Badge
                              variant="outline"
                              title="This repository isn't linked to a deployment yet"
                              className="h-6 border-2 border-dashed border-foreground bg-card px-2 font-mono text-[11px] font-bold uppercase"
                            >
                              Unmapped
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        {f.asset ? (
                          <Badge
                            variant="outline"
                            className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
                          >
                            {f.asset.environment}
                          </Badge>
                        ) : (
                          <span className="font-mono text-[11px] uppercase text-muted-foreground">
                            —
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        {f.asset?.internet_facing ? (
                          <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
                            ● Public
                          </Badge>
                        ) : (
                          <span className="font-mono text-[11px] uppercase text-muted-foreground">
                            Internal
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap px-4 py-5 align-top font-mono text-[11px] uppercase">
                        <div title={f.vulnerability.last_seen}>
                          {relativeTime(f.vulnerability.last_seen)}
                        </div>
                        <div
                          title={f.vulnerability.first_seen}
                          className="mt-1 text-muted-foreground"
                        >
                          first {relativeTime(f.vulnerability.first_seen)}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
