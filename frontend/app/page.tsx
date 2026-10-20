import { ArrowRight, ArrowUpRight, Network, Search } from "lucide-react";
import Link from "next/link";

import { FilterBar } from "@/components/filter-bar";
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
import {
  appendFilters,
  type FailingScan,
  FILTER_KEYS,
  type Filters,
  findingHref,
  type FindingsPage,
  graphHref,
  parseFilters,
  relativeTime,
} from "@/lib/findings";
import { SEVERITIES, severityBg } from "@/lib/graph";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const PAGE_SIZE = 50;

const FILTERS = [
  { value: "active", label: "Active" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In progress" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "All" },
];

function pageHref(status: string, q: string, filters: Filters, page: number): string {
  const params = new URLSearchParams();
  if (status !== "active") params.set("status", status);
  if (q) params.set("q", q);
  appendFilters(params, filters);
  if (page > 1) params.set("page", String(page));
  const query = params.toString();
  return query ? `/?${query}` : "/";
}

async function getFindings(
  status: string,
  q: string,
  filters: Filters,
  page: number,
): Promise<FindingsPage> {
  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String((page - 1) * PAGE_SIZE),
  });
  if (status !== "active") params.set("status", status);
  if (q) params.set("q", q);
  appendFilters(params, filters);
  const res = await fetch(`${API_URL}/findings?${params}`, {
    cache: "no-store",
    headers: await apiHeaders(),
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
      headers: await apiHeaders(),
    });
    return res.ok ? await res.json() : [];
  } catch {
    return [];
  }
}

export default async function Home({ searchParams }: PageProps<"/">) {
  const rawParams = await searchParams;
  const { status: rawStatus, q: rawQ, page: rawPage } = rawParams;
  const status =
    FILTERS.find((f) => f.value === rawStatus)?.value ?? FILTERS[0].value;
  const q = (typeof rawQ === "string" ? rawQ : "").trim().slice(0, 200);
  const filters = parseFilters(rawParams);
  const filtered = FILTER_KEYS.some((key) => filters[key]);
  const keep: Record<string, string> = {};
  if (status !== "active") keep.status = status;
  if (q) keep.q = q;
  const page = Math.max(1, Number.parseInt(String(rawPage), 10) || 1);
  let result: FindingsPage | null = null;
  let error: string | null = null;
  const failingPromise = getFailingScans();

  try {
    result = await getFindings(status, q, filters, page);
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }
  const failing = await failingPromise;

  const findings = result?.items ?? [];
  const total = result?.total ?? 0;
  const counts = result?.counts;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const firstRow = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const lastRow = Math.min(total, page * PAGE_SIZE);

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
        <form action="/" method="get" className="animate-rise flex flex-wrap gap-3">
          {status !== "active" && <input type="hidden" name="status" value={status} />}
          {FILTER_KEYS.filter((key) => filters[key]).map((key) => (
            <input key={key} type="hidden" name={key} value={filters[key]} />
          ))}
          <div className="relative min-w-64 flex-1 sm:max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2" />
            <input
              type="search"
              name="q"
              defaultValue={q}
              maxLength={200}
              placeholder="Search CVE, package, repo or asset"
              aria-label="Search findings"
              className="h-10 w-full border-2 border-foreground bg-card pl-9 pr-3 font-mono text-xs shadow-brutal-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-acid"
            />
          </div>
          <button
            type="submit"
            className="brutal-lift h-10 border-2 border-foreground bg-acid px-4 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
          >
            Search
          </button>
          {q && (
            <Link
              href={pageHref(status, "", filters, 1)}
              className="brutal-lift inline-flex h-10 items-center border-2 border-foreground bg-card px-4 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
            >
              Clear
            </Link>
          )}
        </form>
      )}

      {!error && (
        <FilterBar
          key={JSON.stringify(filters)}
          action="/"
          filters={filters}
          keep={keep}
        />
      )}

      {!error && (
        <nav className="animate-rise flex flex-wrap gap-3">
          {FILTERS.map(({ value, label }) => (
            <Link
              key={value}
              href={pageHref(value, q, filters, 1)}
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
          title={status === "active" && !q && !filtered ? "Nothing exposed" : "No matches"}
        >
          {q || filtered
            ? "No findings match these filters. Try another search or reset the filters."
            : status === "active"
              ? "No open findings right now. New issues appear here as soon as a scan reports them."
              : "No findings with this status. Try another filter."}
        </StateCard>
      )}

      {!error && findings.length > 0 && counts && (
        <>
          <section className="grid grid-cols-2 gap-4 sm:grid-cols-4 sm:gap-6">
            {SEVERITIES.map((severity, i) => (
              <Card
                key={severity}
                style={{ animationDelay: `${80 + i * 60}ms` }}
                className={cn(
                  "brutal brutal-lift animate-rise gap-1 px-5 py-4",
                  (counts[severity] ?? 0) > 0
                    ? severityBg[severity]
                    : "bg-card text-muted-foreground",
                )}
              >
                <span className="text-5xl font-bold tabular-nums tracking-tighter">
                  {String(counts[severity] ?? 0).padStart(2, "0")}
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
                        <Link
                          href={graphHref(f.vulnerability.id)}
                          className="mt-2 inline-flex items-center gap-1 font-mono text-[11px] font-bold uppercase tracking-widest underline decoration-2 underline-offset-4 hover:bg-acid"
                        >
                          <Network className="size-3.5" />
                          Show on graph
                        </Link>
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

          <nav
            aria-label="Pagination"
            className="animate-rise flex flex-wrap items-center justify-between gap-4"
          >
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              {firstRow}–{lastRow} of {total} · page {page} / {pageCount}
            </p>
            <div className="flex gap-3">
              {page > 1 && (
                <Link
                  href={pageHref(status, q, filters, page - 1)}
                  className="brutal-lift border-2 border-foreground bg-card px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
                >
                  ← Prev
                </Link>
              )}
              {page < pageCount && (
                <Link
                  href={pageHref(status, q, filters, page + 1)}
                  className="brutal-lift border-2 border-foreground bg-acid px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
                >
                  Next →
                </Link>
              )}
            </div>
          </nav>
        </>
      )}
    </div>
  );
}
