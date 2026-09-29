"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, {
  type ForceGraphMethods,
  type NodeObject,
} from "react-force-graph-2d";

import { Badge } from "@/components/ui/badge";
import {
  type GraphData,
  type GraphNode,
  labelHex,
  nodeColor,
  nodeTitle,
  severityHex,
} from "@/lib/graph";

const HEIGHT = 600;
const NODE_RADIUS: Record<GraphNode["label"], number> = {
  Repository: 7,
  Vulnerability: 6,
  Asset: 7,
};

type Node = NodeObject<GraphNode>;

function endId(end: unknown): string {
  return typeof end === "object" && end !== null
    ? String((end as Node).id)
    : String(end);
}

export default function FindingsGraph({ data }: { data: GraphData }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<ForceGraphMethods<Node> | undefined>(undefined);
  const [width, setWidth] = useState(0);
  const [textColor, setTextColor] = useState("#18181b");
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      setWidth(entry.contentRect.width);
      setTextColor(getComputedStyle(el).color);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo(
    () => ({
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.links.map((l) => ({ ...l })),
    }),
    [data],
  );

  const neighbours = useMemo(() => {
    if (!selected) return null;
    const ids = new Set([selected.id]);
    for (const l of data.links) {
      if (l.source === selected.id) ids.add(l.target);
      if (l.target === selected.id) ids.add(l.source);
    }
    return ids;
  }, [selected, data.links]);

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
      <div
        ref={containerRef}
        className="relative overflow-hidden rounded-lg border bg-white text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100"
      >
        <Legend />
        {width > 0 && (
          <ForceGraph2D<GraphNode>
            ref={graphRef}
            graphData={graphData}
            width={width}
            height={HEIGHT}
            nodeLabel={(n) => `${n.label}: ${nodeTitle(n)}`}
            nodeRelSize={1}
            nodeVal={(n) => NODE_RADIUS[n.label] ** 2}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkLabel="type"
            linkColor={(l) =>
              !neighbours ||
              (neighbours.has(endId(l.source)) && neighbours.has(endId(l.target)))
                ? "#a1a1aa"
                : "rgba(161,161,170,0.15)"
            }
            cooldownTicks={100}
            onEngineStop={() => graphRef.current?.zoomToFit(400, 60)}
            onNodeClick={(n) => setSelected(n)}
            onBackgroundClick={() => setSelected(null)}
            nodeCanvasObject={(n, ctx, scale) => {
              const x = n.x ?? 0;
              const y = n.y ?? 0;
              const r = NODE_RADIUS[n.label];
              const dimmed = neighbours !== null && !neighbours.has(n.id);
              ctx.globalAlpha = dimmed ? 0.15 : 1;

              ctx.beginPath();
              if (n.label === "Repository") {
                ctx.rect(x - r, y - r, r * 2, r * 2);
              } else if (n.label === "Vulnerability") {
                ctx.moveTo(x, y - r * 1.2);
                ctx.lineTo(x + r * 1.2, y);
                ctx.lineTo(x, y + r * 1.2);
                ctx.lineTo(x - r * 1.2, y);
                ctx.closePath();
              } else {
                ctx.arc(x, y, r, 0, 2 * Math.PI);
              }
              ctx.fillStyle = nodeColor(n);
              ctx.fill();

              if (n.label === "Asset" && n.properties.internet_facing) {
                ctx.lineWidth = 2 / scale;
                ctx.strokeStyle = "#dc2626";
                ctx.stroke();
              }
              if (selected?.id === n.id) {
                ctx.lineWidth = 3 / scale;
                ctx.strokeStyle = textColor;
                ctx.stroke();
              }

              ctx.font = `${12 / scale}px sans-serif`;
              ctx.textAlign = "center";
              ctx.textBaseline = "top";
              ctx.fillStyle = textColor;
              ctx.fillText(nodeTitle(n), x, y + r * 1.2 + 2 / scale);
              ctx.globalAlpha = 1;
            }}
            nodePointerAreaPaint={(n, color, ctx) => {
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(n.x ?? 0, n.y ?? 0, NODE_RADIUS[n.label] + 2, 0, 2 * Math.PI);
              ctx.fill();
            }}
          />
        )}
      </div>

      <NodeDetails node={selected} />
    </div>
  );
}

function Legend() {
  return (
    <div className="absolute left-3 top-3 z-10 space-y-1 rounded-md border bg-white/90 p-2 text-xs dark:bg-zinc-900/90">
      <LegendItem shape="square" color={labelHex.Repository} text="Repository" />
      <LegendItem shape="diamond" color={severityHex.CRITICAL} text="Vulnerability (by severity)" />
      <LegendItem shape="circle" color={labelHex.Asset} text="Asset" />
      <LegendItem shape="ring" color="#dc2626" text="Internet-facing" />
    </div>
  );
}

function LegendItem({
  shape,
  color,
  text,
}: {
  shape: "square" | "diamond" | "circle" | "ring";
  color: string;
  text: string;
}) {
  const shapeClass = {
    square: "",
    diamond: "rotate-45",
    circle: "rounded-full",
    ring: "rounded-full",
  }[shape];
  const style =
    shape === "ring" ? { border: `2px solid ${color}` } : { backgroundColor: color };
  return (
    <div className="flex items-center gap-2">
      <span className={`inline-block size-2.5 ${shapeClass}`} style={style} />
      {text}
    </div>
  );
}

function NodeDetails({ node }: { node: GraphNode | null }) {
  if (!node) {
    return (
      <div className="rounded-lg border p-4 text-sm text-zinc-500">
        Click a node to see its details and highlight its connections.
      </div>
    );
  }
  return (
    <div className="space-y-3 rounded-lg border p-4 text-sm">
      <div>
        <Badge style={{ backgroundColor: nodeColor(node) }} className="text-white">
          {node.label}
        </Badge>
        <div className="mt-2 break-words font-medium">{nodeTitle(node)}</div>
      </div>
      <dl className="space-y-2">
        {Object.entries(node.properties).map(([key, value]) => (
          <div key={key}>
            <dt className="text-xs uppercase text-zinc-500">{key}</dt>
            <dd className="break-words">
              {key === "url" && typeof value === "string" ? (
                <a href={value} target="_blank" rel="noopener noreferrer" className="underline">
                  {value}
                </a>
              ) : (
                String(value)
              )}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
