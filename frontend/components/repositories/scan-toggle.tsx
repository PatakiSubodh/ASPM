"use client";

import { useOptimistic, useTransition } from "react";

import { Switch } from "@/components/ui/switch";
import type { ActionResult } from "@/lib/repositories";

import { SWITCH } from "./styles";

export function ScanToggle({
  name,
  selected,
  action,
}: {
  name: string;
  selected: boolean;
  action: (selected: boolean) => Promise<ActionResult>;
}) {
  const [optimistic, setOptimistic] = useOptimistic(selected);
  const [, startTransition] = useTransition();

  return (
    <Switch
      checked={optimistic}
      aria-label={`Automatic scans for ${name}`}
      className={SWITCH}
      onCheckedChange={(next) =>
        startTransition(async () => {
          setOptimistic(next);
          await action(next);
        })
      }
    />
  );
}
