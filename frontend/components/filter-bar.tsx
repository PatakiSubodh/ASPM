"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import type { FormEvent, ReactNode } from "react";

import {
  type Filters,
  FILTER_KEYS,
  PRIORITIES,
  SCANNERS,
} from "@/lib/findings";
import { SEVERITIES } from "@/lib/graph";

const CONTROL =
  "h-10 w-full border-2 border-foreground bg-card px-3 font-mono text-xs shadow-brutal-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-acid";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-36 flex-1 flex-col gap-1.5">
      <span className="font-mono text-[11px] font-bold uppercase tracking-widest">
        {label}
      </span>
      {children}
    </label>
  );
}

export function FilterBar({
  action,
  filters,
  keep = {},
}: {
  action: string;
  filters: Filters;
  keep?: Record<string, string>;
}) {
  const router = useRouter();
  const active = FILTER_KEYS.some((key) => filters[key]);
  const reset = new URLSearchParams(keep).toString();
  const resetHref = reset ? `${action}?${reset}` : action;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const params = new URLSearchParams(keep);
    for (const key of FILTER_KEYS) {
      const value = data.get(key);
      if (typeof value === "string" && value.trim()) params.set(key, value.trim());
    }
    const query = params.toString();
    router.push(query ? `${action}?${query}` : action);
  }

  return (
    <form
      onSubmit={submit}
      aria-label="Filter findings"
      className="animate-rise brutal flex flex-wrap items-end gap-4 bg-card p-4"
    >
      <Field label="Severity">
        <select name="severity" defaultValue={filters.severity ?? ""} className={CONTROL}>
          <option value="">Any</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Priority">
        <select name="priority" defaultValue={filters.priority ?? ""} className={CONTROL}>
          <option value="">Any</option>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Environment">
        <input
          type="text"
          name="environment"
          defaultValue={filters.environment ?? ""}
          maxLength={200}
          placeholder="production"
          className={CONTROL}
        />
      </Field>
      <Field label="Exposure">
        <select
          name="internet_facing"
          defaultValue={filters.internet_facing ?? ""}
          className={CONTROL}
        >
          <option value="">Any</option>
          <option value="true">Public</option>
          <option value="false">Internal</option>
        </select>
      </Field>
      <Field label="Scanner">
        <select name="scanner" defaultValue={filters.scanner ?? ""} className={CONTROL}>
          <option value="">Any</option>
          {SCANNERS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Repository">
        <input
          type="text"
          name="repo"
          defaultValue={filters.repo ?? ""}
          maxLength={200}
          placeholder="repo-name"
          className={CONTROL}
        />
      </Field>
      <div className="flex gap-3">
        <button
          type="submit"
          className="brutal-lift h-10 border-2 border-foreground bg-acid px-4 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
        >
          Apply
        </button>
        {active && (
          <Link
            href={resetHref}
            className="brutal-lift inline-flex h-10 items-center border-2 border-foreground bg-card px-4 font-mono text-[11px] font-bold uppercase tracking-widest shadow-brutal-sm"
          >
            Reset
          </Link>
        )}
      </div>
    </form>
  );
}
