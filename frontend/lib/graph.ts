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

export const severityHex: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#a1a1aa",
};

export const labelHex: Record<NodeLabel, string> = {
  Repository: "#3b82f6",
  Vulnerability: "#dc2626",
  Asset: "#10b981",
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
