"use client";

import { forceX, forceY } from "d3-force";
import { Maximize2, Shuffle, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, {
  type ForceGraphMethods,
  type NodeObject,
} from "react-force-graph-2d";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import {
  ACID,
  FADED,
  type GraphData,
  type GraphNode,
  INK,
  labelHex,
  nodeColor,
  nodeTitle,
  PAPER,
  severityHex,
} from "@/lib/graph";
import { cn } from "@/lib/utils";

type Node = NodeObject<GraphNode>;

interface Settings {
  center: number;
  repel: number;
  link: number;
  distance: number;
  nodeSize: number;
  labelFade: number;
  arrows: boolean;
}

const DEFAULTS: Settings = {
  center: 0.06,
  repel: 180,
  link: 0.5,
  distance: 60,
  nodeSize: 1,
  labelFade: 1.2,
  arrows: true,
};

function endId(end: unknown): string {
  return typeof end === "object" && end !== null
    ? String((end as Node).id)
    : String(end);
}

function tracePath(
  ctx: CanvasRenderingContext2D,
  label: GraphNode["label"],
  x: number,
  y: number,
  r: number,
) {
  ctx.beginPath();
  if (label === "Repository") {
    ctx.rect(x - r, y - r, r * 2, r * 2);
  } else if (label === "Vulnerability") {
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
  const fittedRef = useRef(false);
  const mountedAtRef = useRef(0);
  const [width, setWidth] = useState(0);
  const [monoFont, setMonoFont] = useState("monospace");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [settings, setSettings] = useState<Settings>(DEFAULTS);
  const [panelOpen, setPanelOpen] = useState(false);

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
    if (!ready) return;
    mountedAtRef.current = performance.now();
  }, [ready]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!ready || !graph) return;
    graph.d3Force("charge")?.strength?.(-settings.repel);
    graph.d3Force("link")?.distance?.(settings.distance);
    graph.d3Force("link")?.strength?.(settings.link);
    graph.d3Force("center", null);
    graph.d3Force("x", forceX(0).strength(settings.center) as never);
    graph.d3Force("y", forceY(0).strength(settings.center) as never);
    graph.d3ReheatSimulation();
  }, [ready, settings.repel, settings.distance, settings.link, settings.center]);

  const height = Math.round(Math.min(640, Math.max(440, width * 0.7)));

  const graphData = useMemo(
    () => ({
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.links.map((l) => ({ ...l })),
    }),
    [data],
  );

  const degree = useMemo(() => {
    const counts = new Map<string, number>();
    for (const l of data.links) {
      counts.set(l.source, (counts.get(l.source) ?? 0) + 1);
      counts.set(l.target, (counts.get(l.target) ?? 0) + 1);
    }
    return counts;
  }, [data.links]);

  const radius = (id: string) =>
    (4 + Math.sqrt(degree.get(id) ?? 0) * 3) * settings.nodeSize;

  const focusId = hovered ?? selected?.id ?? null;

  const neighbours = useMemo(() => {
    if (!focusId) return null;
    const ids = new Set([focusId]);
    for (const l of data.links) {
      if (l.source === focusId) ids.add(l.target);
      if (l.target === focusId) ids.add(l.source);
    }
    return ids;
  }, [focusId, data.links]);

  const linkActive = (source: unknown, target: unknown) =>
    !neighbours || (neighbours.has(endId(source)) && neighbours.has(endId(target)));

  const linkFocused = (source: unknown, target: unknown) =>
    neighbours !== null && linkActive(source, target);

  const update = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    setSettings((s) => ({ ...s, [key]: value }));

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
      <Card className="brutal relative gap-0 overflow-hidden bg-card py-0">
        <div
          ref={containerRef}
          className={cn(
            "relative [background-image:radial-gradient(color-mix(in_oklab,var(--foreground)_14%,transparent)_1px,transparent_1px)] [background-size:22px_22px]",
            hovered && "cursor-pointer",
          )}
        >
          <div className="absolute right-3 top-3 z-10 flex gap-2">
            <Button
              variant="outline"
              size="icon"
              aria-label="Graph settings"
              title="Graph settings"
              aria-pressed={panelOpen}
              onClick={() => setPanelOpen((o) => !o)}
              className={cn(
                "brutal brutal-lift shadow-brutal-sm hover:bg-acid",
                panelOpen ? "bg-acid" : "bg-card",
              )}
            >
              <SlidersHorizontal />
            </Button>
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
              onClick={() => graphRef.current?.zoomToFit(400, 70)}
              className="brutal brutal-lift bg-card shadow-brutal-sm hover:bg-acid"
            >
              <Maximize2 />
            </Button>
          </div>
          {panelOpen && (
            <SettingsPanel
              settings={settings}
              onChange={update}
              onReset={() => setSettings(DEFAULTS)}
            />
          )}
          <Legend />
          {ready && (
            <ForceGraph2D<GraphNode>
              ref={graphRef}
              graphData={graphData}
              width={width}
              height={height}
              backgroundColor="rgba(0,0,0,0)"
              nodeLabel={() => ""}
              nodeRelSize={1}
              nodeVal={(n) => radius(n.id) ** 2}
              d3VelocityDecay={0.25}
              d3AlphaDecay={0.012}
              cooldownTime={20000}
              warmupTicks={120}
              onEngineTick={() => {
                if (fittedRef.current) return;
                if (performance.now() - mountedAtRef.current > 2500) {
                  fittedRef.current = true;
                  return;
                }
                graphRef.current?.zoomToFit(0, 70);
              }}
              onEngineStop={() => {
                if (fittedRef.current) return;
                fittedRef.current = true;
                graphRef.current?.zoomToFit(600, 70);
              }}
              linkWidth={(l) =>
                linkFocused(l.source, l.target) ? 2.2 : linkActive(l.source, l.target) ? 1.2 : 0.6
              }
              linkColor={(l) => (linkActive(l.source, l.target) ? INK : FADED)}
              linkDirectionalArrowLength={settings.arrows ? 4 : 0}
              linkDirectionalArrowRelPos={1}
              linkDirectionalArrowColor={(l) =>
                linkActive(l.source, l.target) ? INK : FADED
              }
              linkLabel="type"
              onNodeHover={(n) => setHovered(n ? n.id : null)}
              onNodeClick={(n) => setSelected(n)}
              onBackgroundClick={() => setSelected(null)}
              onNodeDragEnd={(n) => {
                n.fx = undefined;
                n.fy = undefined;
              }}
              nodeCanvasObject={(n, ctx, scale) => {
                const x = n.x ?? 0;
                const y = n.y ?? 0;
                const r = radius(n.id);
                const inFocus = neighbours?.has(n.id) ?? false;
                const dimmed = neighbours !== null && !inFocus;
                const isFocus = n.id === focusId;
                ctx.globalAlpha = dimmed ? 0.12 : 1;

                if (isFocus) {
                  ctx.beginPath();
                  ctx.arc(x, y, r * 1.3 + 5, 0, 2 * Math.PI);
                  ctx.fillStyle = ACID;
                  ctx.fill();
                  ctx.lineWidth = 1.2;
                  ctx.strokeStyle = INK;
                  ctx.stroke();
                }

                tracePath(ctx, n.label, x + 2, y + 2, r);
                ctx.fillStyle = INK;
                ctx.fill();

                tracePath(ctx, n.label, x, y, r);
                ctx.fillStyle = nodeColor(n);
                ctx.fill();
                ctx.lineWidth = isFocus ? 2.2 : 1.4;
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

                const zoomAlpha = Math.min(
                  1,
                  Math.max(0, (scale - settings.labelFade) / 0.5 + 1),
                );
                const labelAlpha = inFocus ? 1 : dimmed ? 0 : zoomAlpha;
                if (labelAlpha > 0) {
                  ctx.globalAlpha = labelAlpha;
                  const fontSize = Math.max(11 / scale, 2.5);
                  ctx.font = `${isFocus ? 700 : 500} ${fontSize}px ${monoFont}`;
                  ctx.textAlign = "center";
                  ctx.textBaseline = "top";
                  const label = nodeTitle(n);
                  const ty = y + r * 1.3 + (isFocus ? 8 : 4);
                  ctx.lineWidth = 3 / scale;
                  ctx.strokeStyle = PAPER;
                  ctx.lineJoin = "round";
                  ctx.strokeText(label, x, ty);
                  ctx.fillStyle = INK;
                  ctx.fillText(label, x, ty);
                }
                ctx.globalAlpha = 1;
              }}
              nodePointerAreaPaint={(n, color, ctx) => {
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(n.x ?? 0, n.y ?? 0, radius(n.id) * 1.3 + 3, 0, 2 * Math.PI);
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

function SettingsPanel({
  settings,
  onChange,
  onReset,
}: {
  settings: Settings;
  onChange: <K extends keyof Settings>(key: K, value: Settings[K]) => void;
  onReset: () => void;
}) {
  return (
    <div className="absolute left-3 top-3 z-20 w-64 animate-rise border-2 border-foreground bg-card shadow-brutal">
      <div className="flex items-center justify-between border-b-2 border-foreground bg-acid px-3 py-2">
        <span className="font-mono text-[11px] font-bold uppercase tracking-widest">
          Graph settings
        </span>
        <Button
          variant="ghost"
          size="xs"
          onClick={onReset}
          className="font-mono text-[10px] uppercase tracking-widest hover:bg-foreground hover:text-background"
        >
          Reset
        </Button>
      </div>
      <div className="space-y-4 px-3 py-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
          Forces
        </p>
        <SettingSlider
          label="Center force"
          value={settings.center}
          min={0}
          max={0.3}
          step={0.01}
          onChange={(v) => onChange("center", v)}
        />
        <SettingSlider
          label="Repel force"
          value={settings.repel}
          min={20}
          max={600}
          step={10}
          onChange={(v) => onChange("repel", v)}
        />
        <SettingSlider
          label="Link force"
          value={settings.link}
          min={0.05}
          max={1}
          step={0.05}
          onChange={(v) => onChange("link", v)}
        />
        <SettingSlider
          label="Link distance"
          value={settings.distance}
          min={20}
          max={200}
          step={5}
          onChange={(v) => onChange("distance", v)}
        />
        <p className="border-t-2 border-dashed border-foreground/20 pt-3 font-mono text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
          Display
        </p>
        <SettingSlider
          label="Node size"
          value={settings.nodeSize}
          min={0.5}
          max={2}
          step={0.1}
          onChange={(v) => onChange("nodeSize", v)}
        />
        <SettingSlider
          label="Text fade"
          value={settings.labelFade}
          min={0.3}
          max={3}
          step={0.1}
          onChange={(v) => onChange("labelFade", v)}
        />
        <label className="flex items-center justify-between font-mono text-[11px]">
          Arrows
          <Switch
            checked={settings.arrows}
            onCheckedChange={(checked) => onChange("arrows", checked)}
          />
        </label>
      </div>
    </div>
  );
}

function SettingSlider({
  label,
  value,
  min,
  max,
  step,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between font-mono text-[11px]">
        <span>{label}</span>
        <span className="tabular-nums text-muted-foreground">{value}</span>
      </div>
      <Slider
        value={[value]}
        min={min}
        max={max}
        step={step}
        onValueChange={(v) => onChange(Array.isArray(v) ? v[0] : (v as number))}
      />
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
      <p className="pt-1 text-muted-foreground">size = connections</p>
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
          <li>→ hover to trace links</li>
          <li>→ click a node to pin it</li>
          <li>→ drag to pull neighbours</li>
          <li>→ zoom in to reveal labels</li>
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
