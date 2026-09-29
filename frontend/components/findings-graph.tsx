"use client";

import { Maximize2, Shuffle, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, {
  type ForceGraphMethods,
  type NodeObject,
} from "react-force-graph-2d";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  type GraphData,
  type GraphNode,
  INK,
  labelHex,
  nodeColor,
  nodeTitle,
  severityHex,
} from "@/lib/graph";
import { cn } from "@/lib/utils";

const PAPER = "#ffffff";
const NODE_RADIUS: Record<GraphNode["label"], number> = {
  Repository: 7,
  Vulnerability: 7,
  Asset: 7,
};

type Node = NodeObject<GraphNode>;

function endId(end: unknown): string {
  return typeof end === "object" && end !== null
    ? String((end as Node).id)
    : String(end);
}

function tracePath(ctx: CanvasRenderingContext2D, n: Node, x: number, y: number) {
  const r = NODE_RADIUS[n.label];
  ctx.beginPath();
  if (n.label === "Repository") {
    ctx.rect(x - r, y - r, r * 2, r * 2);
  } else if (n.label === "Vulnerability") {
    ctx.moveTo(x, y - r * 1.3);
    ctx.lineTo(x + r * 1.3, y);
    ctx.lineTo(x, y + r * 1.3);
    ctx.lineTo(x - r * 1.3, y);
    ctx.closePath();
  } else {
    ctx.arc(x, y, r, 0, 2 * Math.PI);
  }
}

export default function FindingsGraph({ data }: { data: GraphData }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<ForceGraphMethods<Node> | undefined>(undefined);
  const [width, setWidth] = useState(0);
  const [monoFont, setMonoFont] = useState("monospace");
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    setMonoFont(
      getComputedStyle(el).getPropertyValue("--font-jetbrains").trim() ||
        "monospace",
    );
    const observer = new ResizeObserver(([entry]) => {
      setWidth(entry.contentRect.width);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const ready = width > 0;

  useEffect(() => {
    const graph = graphRef.current;
    if (!ready || !graph) return;
    graph.d3Force("charge")?.strength?.(-260);
    graph.d3Force("link")?.distance?.(70);
    graph.d3ReheatSimulation();
  }, [ready]);

  const height = Math.round(Math.min(620, Math.max(420, width * 0.7)));

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

  const linkActive = (source: unknown, target: unknown) =>
    !neighbours || (neighbours.has(endId(source)) && neighbours.has(endId(target)));

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
      <Card className="brutal relative gap-0 overflow-hidden bg-card py-0">
        <div
          ref={containerRef}
          className="relative [background-image:radial-gradient(color-mix(in_oklab,var(--foreground)_14%,transparent)_1px,transparent_1px)] [background-size:22px_22px]"
        >
          <div className="absolute right-3 top-3 z-10 flex gap-2">
            <Button
              variant="outline"
              size="icon"
              aria-label="Shake layout"
              title="Shake layout"
              onClick={() => graphRef.current?.d3ReheatSimulation()}
              className="brutal brutal-lift bg-card shadow-brutal-sm hover:bg-acid"
            >
              <Shuffle />
            </Button>
            <Button
              variant="outline"
              size="icon"
              aria-label="Fit to view"
              title="Fit to view"
              onClick={() => graphRef.current?.zoomToFit(400, 60)}
              className="brutal brutal-lift bg-card shadow-brutal-sm hover:bg-acid"
            >
              <Maximize2 />
            </Button>
          </div>
          <Legend />
          {width > 0 && (
            <ForceGraph2D<GraphNode>
              ref={graphRef}
              graphData={graphData}
              width={width}
              height={height}
              backgroundColor="rgba(0,0,0,0)"
              nodeLabel={(n) => `${n.label}: ${nodeTitle(n)}`}
              nodeRelSize={1}
              nodeVal={(n) => NODE_RADIUS[n.label] ** 2}
              linkWidth={(l) => (linkActive(l.source, l.target) ? 1.6 : 0.8)}
              linkColor={(l) =>
                linkActive(l.source, l.target) ? INK : "rgba(17,17,17,0.12)"
              }
              linkDirectionalArrowLength={5}
              linkDirectionalArrowRelPos={0.92}
              linkDirectionalArrowColor={(l) =>
                linkActive(l.source, l.target) ? INK : "rgba(17,17,17,0.12)"
              }
              linkLabel="type"
              cooldownTicks={100}
              onEngineStop={() => graphRef.current?.zoomToFit(400, 60)}
              onNodeClick={(n) => setSelected(n)}
              onBackgroundClick={() => setSelected(null)}
              nodeCanvasObject={(n, ctx, scale) => {
                const x = n.x ?? 0;
                const y = n.y ?? 0;
                const r = NODE_RADIUS[n.label];
                const dimmed = neighbours !== null && !neighbours.has(n.id);
                const offset = 2.2;
                ctx.globalAlpha = dimmed ? 0.15 : 1;

                tracePath(ctx, n, x + offset, y + offset);
                ctx.fillStyle = INK;
                ctx.fill();

                tracePath(ctx, n, x, y);
                ctx.fillStyle = nodeColor(n);
                ctx.fill();
                ctx.lineWidth = selected?.id === n.id ? 2.4 : 1.4;
                ctx.strokeStyle = INK;
                ctx.stroke();

                if (n.label === "Asset" && n.properties.internet_facing) {
                  ctx.beginPath();
                  ctx.arc(x, y, r + 3.5, 0, 2 * Math.PI);
                  ctx.setLineDash([2, 1.5]);
                  ctx.lineWidth = 1.2;
                  ctx.stroke();
                  ctx.setLineDash([]);
                }

                const fontSize = Math.max(11 / scale, 3);
                ctx.font = `600 ${fontSize}px ${monoFont}`;
                ctx.textAlign = "center";
                ctx.textBaseline = "top";
                const label = nodeTitle(n);
                const ty = y + r * 1.3 + 4;
                ctx.lineWidth = 3 / scale;
                ctx.strokeStyle = PAPER;
                ctx.lineJoin = "round";
                ctx.strokeText(label, x, ty);
                ctx.fillStyle = INK;
                ctx.fillText(label, x, ty);
                ctx.globalAlpha = 1;
              }}
              nodePointerAreaPaint={(n, color, ctx) => {
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(n.x ?? 0, n.y ?? 0, NODE_RADIUS[n.label] + 3, 0, 2 * Math.PI);
                ctx.fill();
              }}
            />
          )}
        </div>
      </Card>

      <NodeDetails node={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function Legend() {
  return (
    <div className="absolute bottom-3 left-3 z-10 space-y-1.5 border-2 border-foreground bg-card px-3 py-2 font-mono text-[11px] shadow-brutal-sm">
      <LegendItem shape="square" color={labelHex.Repository} text="repository" />
      <LegendItem shape="diamond" color={severityHex.CRITICAL} text="vuln · by severity" />
      <LegendItem shape="circle" color={labelHex.Asset} text="asset" />
      <LegendItem shape="ring" color={INK} text="internet-facing" />
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
    square: "border-2 border-foreground",
    diamond: "rotate-45 border-2 border-foreground",
    circle: "rounded-full border-2 border-foreground",
    ring: "rounded-full border-2 border-dashed",
  }[shape];
  const style =
    shape === "ring" ? { borderColor: color } : { backgroundColor: color };
  return (
    <div className="flex items-center gap-2">
      <span className={cn("inline-block size-3", shapeClass)} style={style} />
      {text}
    </div>
  );
}

function NodeDetails({
  node,
  onClose,
}: {
  node: GraphNode | null;
  onClose: () => void;
}) {
  if (!node) {
    return (
      <Card className="h-fit gap-3 border-2 border-dashed border-foreground bg-transparent px-5 py-5 ring-0">
        <CardTitle className="font-mono text-xs font-bold uppercase tracking-widest">
          Inspector
        </CardTitle>
        <ul className="space-y-2 font-mono text-sm text-muted-foreground">
          <li>→ click a node</li>
          <li>→ drag to rearrange</li>
          <li>→ scroll to zoom</li>
        </ul>
      </Card>
    );
  }

  return (
    <Card key={node.id} className="brutal h-fit animate-rise gap-0 bg-card py-0">
      <CardHeader
        className="flex items-center justify-between border-b-2 border-foreground px-4 py-3"
        style={{ backgroundColor: nodeColor(node) }}
      >
        <span className="font-mono text-[11px] font-bold uppercase tracking-widest">
          {node.label}
        </span>
        <Button
          variant="ghost"
          size="icon-xs"
          aria-label="Close"
          onClick={onClose}
          className="hover:bg-foreground hover:text-background"
        >
          <X />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 px-4 py-4">
        <div className="break-words text-2xl font-bold leading-tight tracking-tight">
          {nodeTitle(node)}
        </div>
        <dl className="divide-y-2 divide-dashed divide-foreground/20">
          {Object.entries(node.properties).map(([key, value]) => (
            <div key={key} className="grid grid-cols-[96px_1fr] gap-3 py-2 text-sm">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                {key.replace("_", " ")}
              </dt>
              <dd className="break-words">
                <PropertyValue name={key} value={value} />
              </dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function PropertyValue({
  name,
  value,
}: {
  name: string;
  value: GraphNode["properties"][string];
}) {
  if (name === "url" && typeof value === "string") {
    return (
      <a
        href={value}
        target="_blank"
        rel="noopener noreferrer"
        className="underline decoration-2 underline-offset-4 hover:bg-acid"
      >
        {value.replace(/^https?:\/\//, "")}
      </a>
    );
  }
  if (typeof value === "boolean") {
    return (
      <Badge
        className={cn(
          "h-5 border-2 border-foreground px-1.5 font-mono text-[10px] font-bold uppercase",
          value ? "bg-foreground text-acid" : "bg-card text-foreground",
        )}
      >
        {value ? "yes" : "no"}
      </Badge>
    );
  }
  if (name === "severity" && typeof value === "string") {
    return (
      <Badge
        className="h-5 border-2 border-foreground px-1.5 font-mono text-[10px] font-bold text-foreground"
        style={{ backgroundColor: severityHex[value] }}
      >
        {value}
      </Badge>
    );
  }
  return <span className="font-mono">{String(value)}</span>;
}
