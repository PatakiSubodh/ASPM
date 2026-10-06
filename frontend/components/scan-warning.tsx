import { ArrowRight, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { type FailingScan, relativeTime } from "@/lib/findings";

export function ScanWarning({ failing }: { failing: FailingScan[] }) {
  if (failing.length === 0) return null;

  const repositories = new Set(failing.map((f) => f.repository)).size;

  return (
    <Card role="alert" className="brutal animate-rise gap-0 bg-crit px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="flex items-center gap-2 font-mono text-sm font-bold uppercase tracking-widest">
          <TriangleAlert className="size-4 shrink-0" />
          {repositories === 1
            ? "1 repository wasn't scanned"
            : `${repositories} repositories weren't scanned`}
        </p>
        <Link
          href="/scans"
          className="brutal-lift inline-flex items-center gap-1 border-2 border-foreground bg-card px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
        >
          View scans
          <ArrowRight className="size-3.5" />
        </Link>
      </div>
      <ul className="mt-3 divide-y-2 divide-dashed divide-foreground/30">
        {failing.map((f) => (
          <li
            key={`${f.repository}:${f.scanner}`}
            className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2"
          >
            <span className="font-mono font-bold">{f.repository}</span>
            <Badge
              variant="outline"
              className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
            >
              {f.scanner}
            </Badge>
            <span className="text-sm">
              failed <span title={f.failed_at}>{relativeTime(f.failed_at)}</span>
              {f.error ? `: ${f.error}` : ""}
            </span>
            <span className="font-mono text-[11px] uppercase">
              {f.last_succeeded_at ? (
                <>
                  Last good scan{" "}
                  <span title={f.last_succeeded_at}>{relativeTime(f.last_succeeded_at)}</span>
                </>
              ) : (
                "Never scanned successfully"
              )}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-sm">
        Findings for {repositories === 1 ? "this repository" : "these repositories"} may be out
        of date until the next successful scan.
      </p>
    </Card>
  );
}
