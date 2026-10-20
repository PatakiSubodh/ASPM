import { FilterBar } from "@/components/filter-bar";
import FindingsGraph from "@/components/graph-view";
import { StateCard } from "@/components/state-card";
import { apiHeaders } from "@/lib/api";
import { appendFilters, FILTER_KEYS, type Filters, parseFilters } from "@/lib/findings";
import type { GraphData } from "@/lib/graph";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getGraph(focus: string | null, filters: Filters): Promise<GraphData> {
  const params = new URLSearchParams();
  if (focus) params.set("status", "all");
  appendFilters(params, filters);
  const query = params.toString() ? `?${params}` : "";
  const res = await fetch(`${API_URL}/graph${query}`, {
    cache: "no-store",
    headers: await apiHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Backend responded with ${res.status}`);
  }
  return res.json();
}

export default async function GraphPage({ searchParams }: PageProps<"/graph">) {
  const rawParams = await searchParams;
  const { focus: rawFocus } = rawParams;
  const focus = typeof rawFocus === "string" && rawFocus ? rawFocus : null;
  const filters = parseFilters(rawParams);
  const filtered = FILTER_KEYS.some((key) => filters[key]);
  let graph: GraphData | null = null;
  let error: string | null = null;

  try {
    graph = await getGraph(focus, filters);
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

      {!error && (
        <FilterBar key={JSON.stringify(filters)} action="/graph" filters={filters} />
      )}

      {graph && graph.nodes.length === 0 && (
        <StateCard tone="empty" title={filtered ? "No matches" : "Nothing to map yet"}>
          {filtered
            ? "No findings match these filters. Try other values or reset the filters."
            : "Once your first scan finishes, the path from code to running assets is drawn here."}
        </StateCard>
      )}

      {graph && graph.nodes.length > 0 && (
        <FindingsGraph
          key={`${focus ?? ""}|${JSON.stringify(filters)}`}
          data={graph}
          focusId={focus}
        />
      )}
    </div>
  );
}
