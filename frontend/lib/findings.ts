import type { Severity } from "@/lib/graph";

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
}

export interface FindingDetail {
  vulnerability: Vulnerability;
  repositories: Repository[];
  assets: Asset[];
}

export interface AssetSummary {
  asset: Asset;
  open_by_severity: Record<Severity, number>;
  open_total: number;
}

export function findingHref(id: string): string {
  return `/findings/${encodeURIComponent(id)}`;
}
