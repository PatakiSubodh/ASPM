import { ArrowUpRight } from "lucide-react";

import { StateCard } from "@/components/state-card";
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
import { relativeTime, type CatalogEntry } from "@/lib/findings";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getCatalog(): Promise<CatalogEntry[]> {
  const res = await fetch(`${API_URL}/catalog`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function CatalogPage() {
  let entries: CatalogEntry[] = [];
  let error: string | null = null;

  try {
    entries = await getCatalog();
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  const unmapped = entries.filter((e) => e.assets.length === 0).length;

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          05 / Catalog
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Where code{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            runs
          </span>
          .
        </h1>
        <p className="max-w-xl font-mono text-sm text-muted-foreground">
          Every repository and the assets it deploys to. Findings inherit these links automatically.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load the catalog">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && entries.length === 0 && (
        <StateCard tone="empty" title="No repositories yet">
          Repositories appear here once the catalog is loaded or the first scan arrives.
        </StateCard>
      )}

      {!error && unmapped > 0 && (
        <p
          className="animate-rise font-mono text-[11px] font-bold uppercase tracking-widest"
          style={{ animationDelay: "60ms" }}
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
                  {["Repository", "Deploys to", "Open", "Last scan"].map((h) => (
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
                {entries.map(({ repository, assets, open_total }) => (
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
                    </TableCell>
                    <TableCell className="min-w-64 whitespace-normal px-4 py-5 align-top">
                      {assets.length > 0 ? (
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
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <Badge
                          variant="outline"
                          title="This repository isn't linked to a deployment yet"
                          className="h-6 border-2 border-dashed border-foreground bg-card px-2 font-mono text-[11px] font-bold uppercase"
                        >
                          Unmapped
                        </Badge>
                      )}
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
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
