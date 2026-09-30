import FindingsGraph from "@/components/graph-view";
import { StateCard } from "@/components/state-card";
import { apiHeaders } from "@/lib/api";
import type { GraphData } from "@/lib/graph";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getGraph(): Promise<GraphData> {
  const res = await fetch(`${API_URL}/graph`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
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
          <p className="max-w-xl font-mono text-sm text-muted-foreground">
            How open issues in your code reach running assets. Click a node to trace it.
          </p>
        </div>
        {graph && graph.nodes.length > 0 && (
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {graph.nodes.length} nodes · {graph.links.length} edges
          </p>
        )}
      </section>

      {error && (
        <StateCard tone="error" title="Couldn&apos;t load the graph">
          The service isn&apos;t responding right now. Refresh the page to try again.
        </StateCard>
      )}

      {graph && graph.nodes.length === 0 && (
        <StateCard tone="empty" title="Nothing to map yet">
          Once your first scan finishes, the path from code to running assets is drawn here.
        </StateCard>
      )}

      {graph && graph.nodes.length > 0 && <FindingsGraph data={graph} />}
    </div>
  );
}
