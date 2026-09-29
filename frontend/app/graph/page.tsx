import Link from "next/link";

import FindingsGraph from "@/components/graph-view";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { GraphData } from "@/lib/graph";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getGraph(): Promise<GraphData> {
  const res = await fetch(`${API_URL}/graph`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function GraphPage() {
  let graph: GraphData | null = null;
  let error: string | null = null;

  try {
    graph = await getGraph();
  } catch (e) {
    error = e instanceof Error ? e.message : "Unknown error";
  }

  return (
    <div className="min-h-screen bg-zinc-50 p-8 dark:bg-black">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">
              ASPM — Attack Path Graph
            </h1>
            <p className="text-zinc-600 dark:text-zinc-400">
              Explore how vulnerable code reaches production assets.
            </p>
          </div>
          <Link href="/" className="text-sm underline">
            ← Table view
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

        {graph && graph.nodes.length === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Graph is empty</CardTitle>
              <CardDescription>
                Ingest a finding via <code>POST /findings</code> to see it here.
              </CardDescription>
            </CardHeader>
          </Card>
        )}

        {graph && graph.nodes.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Graph</CardTitle>
              <CardDescription>
                {graph.nodes.length} node(s), {graph.links.length}{" "}
                relationship(s). Drag to pan, scroll to zoom, click a node for
                details.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FindingsGraph data={graph} />
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
