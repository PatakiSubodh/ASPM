import { RiskBadge } from "@/components/risk-badge";
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
import type { AssetSummary } from "@/lib/findings";
import { SEVERITIES, severityBg } from "@/lib/graph";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getAssets(): Promise<AssetSummary[]> {
  const res = await fetch(`${API_URL}/assets`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function AssetsPage() {
  let assets: AssetSummary[] = [];
  let error: string | null = null;

  try {
    assets = await getAssets();
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  assets.sort((a, b) => {
    const riskDiff = (b.risk?.score ?? -1) - (a.risk?.score ?? -1);
    if (riskDiff !== 0) return riskDiff;
    for (const s of SEVERITIES) {
      const diff = b.open_by_severity[s] - a.open_by_severity[s];
      if (diff !== 0) return diff;
    }
    return Number(b.asset.internet_facing) - Number(a.asset.internet_facing);
  });

  return (
    <div className="space-y-12">
      <section className="animate-rise space-y-4">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          03 / Assets
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          What&apos;s{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            running
          </span>
          .
        </h1>
        <p className="max-w-xl font-mono text-sm text-muted-foreground">
          Every asset, ranked by the riskiest open vulnerability that hits it.
        </p>
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load assets">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {!error && assets.length === 0 && (
        <StateCard tone="empty" title="No assets yet">
          Assets appear here once a scan links your code to where it runs.
        </StateCard>
      )}

      {!error && assets.length > 0 && (
        <Card
          className="brutal animate-rise gap-0 bg-card py-0"
          style={{ animationDelay: "80ms" }}
        >
          <CardContent className="px-0">
            <Table>
              <TableHeader className="bg-foreground">
                <TableRow className="border-0 hover:bg-foreground">
                  {["Risk", "Asset", "Env", "Exposure", ...SEVERITIES, "Open"].map(
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
                {assets.map(({ asset, open_by_severity, open_total, risk }) => (
                  <TableRow
                    key={asset.name}
                    className="border-b-2 border-foreground hover:bg-acid/25"
                  >
                    <TableCell className="px-4 py-5 align-top">
                      {risk ? (
                        <RiskBadge risk={risk} />
                      ) : (
                        <span className="font-mono text-[11px] uppercase text-muted-foreground">
                          None
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top">
                      <div className="font-mono font-bold">{asset.name}</div>
                      <p className="mt-1 font-mono text-[11px] uppercase text-muted-foreground">
                        {asset.type}
                      </p>
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top">
                      <Badge
                        variant="outline"
                        className="h-6 border-2 border-foreground bg-card px-2 font-mono text-[11px] lowercase"
                      >
                        {asset.environment}
                      </Badge>
                    </TableCell>
                    <TableCell className="px-4 py-5 align-top">
                      {asset.internet_facing ? (
                        <Badge className="h-6 -rotate-3 border-2 border-foreground bg-foreground px-2 font-mono text-[11px] font-bold uppercase text-acid">
                          ● Public
                        </Badge>
                      ) : (
                        <span className="font-mono text-[11px] uppercase text-muted-foreground">
                          Internal
                        </span>
                      )}
                    </TableCell>
                    {SEVERITIES.map((s) => (
                      <TableCell key={s} className="px-4 py-5 align-top">
                        <span
                          className={cn(
                            "inline-flex h-6 min-w-8 items-center justify-center border-2 border-foreground px-1.5 font-mono text-[11px] font-bold tabular-nums",
                            open_by_severity[s] > 0
                              ? cn(severityBg[s], "shadow-brutal-sm")
                              : "bg-card text-muted-foreground",
                          )}
                        >
                          {String(open_by_severity[s]).padStart(2, "0")}
                        </span>
                      </TableCell>
                    ))}
                    <TableCell className="px-4 py-5 align-top">
                      <span className="text-2xl font-bold tabular-nums tracking-tighter">
                        {String(open_total).padStart(2, "0")}
                      </span>
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
