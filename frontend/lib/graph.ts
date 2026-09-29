export type NodeLabel = "Repository" | "Vulnerability" | "Asset";

export interface GraphNode {
  id: string;
  label: NodeLabel;
  properties: Record<string, string | number | boolean | null>;
}

export interface GraphLink {
  source: string;
  target: string;
  type: "CONTAINS" | "AFFECTS";
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export const INK = "#111111";

export const PAPER = "#ffffff";

export const ACID = "#c8ff2e";

export const FADED = "rgba(17,17,17,0.1)";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export type Severity = (typeof SEVERITIES)[number];

export const severityHex: Record<string, string> = {
  CRITICAL: "#ff4f2e",
  HIGH: "#ff9a1f",
  MEDIUM: "#ffd83d",
  LOW: "#cfcbc0",
};

export const severityBg: Record<Severity, string> = {
  CRITICAL: "bg-crit",
  HIGH: "bg-high",
  MEDIUM: "bg-medium",
  LOW: "bg-low",
};

export const labelHex: Record<NodeLabel, string> = {
  Repository: "#6c8cff",
  Vulnerability: "#ff4f2e",
  Asset: "#c8ff2e",
};

export function nodeColor(node: GraphNode): string {
  if (node.label === "Vulnerability") {
    return severityHex[String(node.properties.severity)] ?? labelHex.Vulnerability;
  }
  return labelHex[node.label];
}

export function nodeTitle(node: GraphNode): string {
  const p = node.properties;
  if (node.label === "Vulnerability") return String(p.cve ?? p.id);
  return String(p.name);
}
