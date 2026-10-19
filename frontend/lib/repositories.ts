export type ActionResult = { ok?: true; error?: string };

export interface Option {
  value: string;
  label: string;
}

export const ENVIRONMENTS: Option[] = [
  { value: "production", label: "Production" },
  { value: "staging", label: "Staging" },
  { value: "development", label: "Development" },
];

export const ASSET_TYPES: Option[] = [
  { value: "Docker container", label: "Docker container" },
  { value: "Kubernetes service", label: "Kubernetes service" },
  { value: "Virtual machine", label: "Virtual machine" },
  { value: "Serverless function", label: "Serverless function" },
  { value: "Database", label: "Database" },
];

export function withCurrent(options: Option[], current?: string): Option[] {
  if (!current || options.some((o) => o.value === current)) return options;
  return [{ value: current, label: current }, ...options];
}
