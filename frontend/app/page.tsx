import { ArrowRight, ArrowUpRight } from "lucide-react";
import Link from "next/link";

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
import { type Finding, findingHref } from "@/lib/findings";
import { SEVERITIES, type Severity, severityBg } from "@/lib/graph";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getFindings(): Promise<Finding[]> {
  const res = await fetch(`${API_URL}/findings`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function Home() {
  let findings: Finding[] = [];
  let error: string | null = null;

  try {
    findings = await getFindings();
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  findings.sort(
    (a, b) =>
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
          Repository → vulnerability → production asset. Live from Neo4j.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="API unreachable">
          {error}. Start the backend on <code>{API_URL}</code> and Neo4j with{" "}
          <code>docker compose up -d</code>.
        </StateCard>
      )}

      {!error && findings.length === 0 && (
        <StateCard tone="empty" title="Nothing here yet">
          Ingest one via <code>POST /findings</code> and it shows up here.
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
                    {["Sev", "Vulnerability", "Path", "Env", "Exposure"].map(
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
                      key={`${f.vulnerability.id}:${f.asset.name}`}
                      className="border-b-2 border-foreground hover:bg-acid/25"
                    >
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
                          <span>{f.asset.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        <Badge
                          variant="outline"
                          className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
                        >
                          {f.asset.environment}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 py-5 align-top">
                        {f.asset.internet_facing ? (
                          <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
                            ● Public
                          </Badge>
                        ) : (
                          <span className="font-mono text-[11px] uppercase text-muted-foreground">
                            Internal
                          </span>
                        )}
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
