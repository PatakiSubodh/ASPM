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

export const STATUSES = [
  "open",
  "in_progress",
  "resolved",
  "accepted_risk",
  "false_positive",
] as const;

export type FindingStatus = (typeof STATUSES)[number];

export const statusLabel: Record<FindingStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
};

export const statusClass: Record<FindingStatus, string> = {
  open: "bg-foreground text-background",
  in_progress: "bg-acid text-foreground",
  resolved: "bg-card text-foreground",
  accepted_risk: "bg-low text-foreground",
  false_positive: "bg-card text-muted-foreground line-through",
};

export interface Repository {
  name: string;
  url: string;
  language?: string;
  branch?: string;
  last_scanned_at?: string;
}

export interface Vulnerability {
  id: string;
  cve?: string;
  severity: Severity;
  description: string;
  status: FindingStatus;
  scanner?: string;
  type?: string;
  package?: string;
  installed_version?: string;
  fixed_version?: string;
  location?: string;
  first_seen?: string;
  last_seen?: string;
  resolved_at?: string;
  reopened_at?: string;
  status_changed_at?: string;
}

export interface Asset {
  name: string;
  environment: string;
  type: string;
  internet_facing: boolean;
  source?: string;
}

export interface CatalogEntry {
  repository: Repository;
  assets: Asset[];
  open_total: number;
}

export interface Finding {
  repository: Repository;
  vulnerability: Vulnerability;
  asset: Asset | null;
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

export interface Scan {
  id: string;
  repository: string;
  scanner: string;
  commit?: string;
  partial?: boolean;
  started_at: string;
  finished_at?: string;
  ingested?: number;
  resolved?: number;
  reopened?: number;
  skipped?: number;
}

export function findingHref(id: string): string {
  return `/findings/${encodeURIComponent(id)}`;
}

const RELATIVE_UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["week", 604_800],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

export function relativeTime(iso?: string): string {
  if (!iso) return "—";
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  const seconds = Math.round((time - Date.now()) / 1000);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return "just now";
}
