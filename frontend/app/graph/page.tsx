import FindingsGraph from "@/components/graph-view";
import { StateCard } from "@/components/state-card";
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
    <div className="space-y-10">
      <section className="animate-rise flex flex-wrap items-end justify-between gap-6">
        <div className="space-y-4">
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
            02 / Graph
          </p>
          <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
            Follow the{" "}
            <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
              path
            </span>
            .
          </h1>
        </div>
        {graph && graph.nodes.length > 0 && (
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {graph.nodes.length} nodes · {graph.links.length} edges
          </p>
        )}
      </section>

      {error && (
        <StateCard tone="error" title="API unreachable">
          {error}. Start the backend on <code>{API_URL}</code> and Neo4j with{" "}
          <code>docker compose up -d</code>.
        </StateCard>
      )}

      {graph && graph.nodes.length === 0 && (
        <StateCard tone="empty" title="Graph is empty">
          Ingest one via <code>POST /findings</code> and it shows up here.
        </StateCard>
      )}

      {graph && graph.nodes.length > 0 && <FindingsGraph data={graph} />}
    </div>
  );
}
