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
import { relativeTime, type Scan } from "@/lib/findings";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getScans(): Promise<Scan[]> {
  const res = await fetch(`${API_URL}/scans?limit=100`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

const COUNTS = [
  { key: "ingested", label: "Ingested", active: "bg-acid" },
  { key: "resolved", label: "Resolved", active: "bg-card" },
  { key: "reopened", label: "Reopened", active: "bg-high" },
] as const;

export default async function ScansPage() {
  let scans: Scan[] = [];
  let error: string | null = null;

  try {
    scans = await getScans();
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          04 / Scans
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          What we{" "}
          <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
            checked
          </span>
          .
        </h1>
        <p className="max-w-xl font-mono text-sm text-muted-foreground">
          Every scan run, newest first. Each run auto-resolves what it no longer reports.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load scans">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && scans.length === 0 && (
        <StateCard tone="empty" title="No scans yet">
          Scan runs appear here as soon as the first one finishes.
        </StateCard>
      )}

      {!error && scans.length > 0 && (
        <Card
          className="brutal animate-rise gap-0 bg-card py-0"
          style={{ animationDelay: "80ms" }}
        >
          <CardContent className="px-0">
            <Table>
              <TableHeader className="bg-foreground">
                <TableRow className="border-0 hover:bg-foreground">
                  {["When", "Repository", "Scanner", "Commit", ...COUNTS.map((c) => c.label)].map(
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
                {scans.map((scan) => (
                  <TableRow
                    key={scan.id}
                    className="border-b-2 border-foreground hover:bg-acid/25"
                  >
                    <TableCell className="whitespace-nowrap px-4 py-5 align-top font-mono text-sm">
                      <span title={scan.started_at}>{relativeTime(scan.started_at)}</span>
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top font-mono font-bold">
                      {scan.repository}
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge
                          variant="outline"
                          className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
                        >
                          {scan.scanner}
                        </Badge>
                        {scan.partial && (
                          <span className="font-mono text-[11px] uppercase text-muted-foreground">
                            Partial
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top font-mono text-sm">
                      {scan.commit ? (
                        <span title={scan.commit}>{scan.commit.slice(0, 7)}</span>
                      ) : (
                        <span className="text-[11px] uppercase text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    {COUNTS.map(({ key, active }) => {
                      const value = scan[key] ?? 0;
                      return (
                        <TableCell key={key} className="px-4 py-5 align-top">
                          <span
                            className={cn(
                              "inline-flex h-6 min-w-8 items-center justify-center border-2 border-foreground px-1.5 font-mono text-[11px] font-bold tabular-nums",
                              value > 0
                                ? cn(active, "shadow-brutal-sm")
                                : "bg-card text-muted-foreground",
                            )}
                          >
                            {String(value).padStart(2, "0")}
                          </span>
                        </TableCell>
                      );
                    })}
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
