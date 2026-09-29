import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

interface Repository {
  name: string;
  url: string;
  language?: string;
}

interface Vulnerability {
  id: string;
  cve?: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  status: string;
}

interface Asset {
  name: string;
  environment: string;
  type: string;
  internet_facing: boolean;
}

interface Finding {
  repository: Repository;
  vulnerability: Vulnerability;
  asset: Asset;
}

const severityColor: Record<Vulnerability["severity"], string> = {
  CRITICAL: "bg-red-600 text-white hover:bg-red-600",
  HIGH: "bg-orange-500 text-white hover:bg-orange-500",
  MEDIUM: "bg-yellow-500 text-black hover:bg-yellow-500",
  LOW: "bg-zinc-400 text-white hover:bg-zinc-400",
};

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

  return (
    <div className="min-h-screen bg-zinc-50 p-8 dark:bg-black">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">
              ASPM — Security Findings
            </h1>
            <p className="text-zinc-600 dark:text-zinc-400">
              Repository → Vulnerability → Production Asset, sourced live from
              the Neo4j graph.
            </p>
          </div>
          <Link href="/graph" className="text-sm underline">
            Graph view →
          </Link>
        </div>

        {error && (
          <Card className="border-red-300">
            <CardHeader>
              <CardTitle className="text-red-600">
                Could not reach the API
              </CardTitle>
              <CardDescription>
                {error}. Make sure the FastAPI backend is running on{" "}
                {API_URL} and Neo4j is up (<code>docker compose up -d</code>
                ).
              </CardDescription>
            </CardHeader>
          </Card>
        )}

        {!error && findings.length === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>No findings yet</CardTitle>
              <CardDescription>
                Ingest one via <code>POST /findings</code> to see it here.
              </CardDescription>
            </CardHeader>
          </Card>
        )}

        {!error && findings.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Attack Path Findings</CardTitle>
              <CardDescription>
                {findings.length} finding(s) mapped from code to production
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Vulnerability</TableHead>
                    <TableHead>Repository</TableHead>
                    <TableHead>Exposed Asset</TableHead>
                    <TableHead>Environment</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((f) => (
                    <TableRow key={f.vulnerability.id}>
                      <TableCell>
                        <Badge className={severityColor[f.vulnerability.severity]}>
                          {f.vulnerability.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">
                          {f.vulnerability.cve ?? f.vulnerability.id}
                        </div>
                        <div className="text-sm text-zinc-500">
                          {f.vulnerability.description}
                        </div>
                      </TableCell>
                      <TableCell>
                        <a
                          href={f.repository.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline"
                        >
                          {f.repository.name}
                        </a>
                      </TableCell>
                      <TableCell>
                        {f.asset.name}
                        {f.asset.internet_facing && (
                          <Badge variant="outline" className="ml-2">
                            internet-facing
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>{f.asset.environment}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
