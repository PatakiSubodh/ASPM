import type { Severity } from "@/lib/graph";

export const PRIORITIES = ["P1", "P2", "P3", "P4"] as const;

export type Priority = (typeof PRIORITIES)[number];

export interface Risk {
  score: number;
  priority: Priority;
  factors: {
    severity: number;
    environment: number;
    exposure: number;
  };
}

export const priorityBg: Record<Priority, string> = {
  P1: "bg-crit",
  P2: "bg-high",
  P3: "bg-medium",
  P4: "bg-low",
};

export interface Repository {
  name: string;
  url: string;
  language?: string;
}

export interface Vulnerability {
  id: string;
  cve?: string;
  severity: Severity;
  description: string;
  status: string;
}

export interface Asset {
  name: string;
  environment: string;
  type: string;
  internet_facing: boolean;
}

export interface Finding {
  repository: Repository;
  vulnerability: Vulnerability;
  asset: Asset;
  risk: Risk;
}

export interface FindingDetail {
  vulnerability: Vulnerability;
  repositories: Repository[];
  assets: Asset[];
  risk: Risk | null;
  asset_risks: Record<string, Risk>;
}

export interface AssetSummary {
  asset: Asset;
  open_by_severity: Record<Severity, number>;
  open_total: number;
  risk: Risk | null;
}

export function findingHref(id: string): string {
  return `/findings/${encodeURIComponent(id)}`;
}
