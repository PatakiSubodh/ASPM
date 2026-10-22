"use client";

import { useState, useTransition, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { BUTTON_PRIMARY, BUTTON_SECONDARY } from "@/components/repositories/styles";
import type { ActionResult } from "@/lib/repositories";

export function GitHubActionButton({
  action,
  pendingLabel,
  doneLabel,
  prominent,
  children,
}: {
  action: () => Promise<ActionResult>;
  pendingLabel: string;
  doneLabel?: string;
  prominent?: boolean;
  children: ReactNode;
}) {
  const [pending, startTransition] = useTransition();
  const [result, setResult] = useState<ActionResult | null>(null);

  return (
    <div className="space-y-2">
      <Button
        variant="outline"
        disabled={pending}
        className={prominent ? BUTTON_PRIMARY : BUTTON_SECONDARY}
        onClick={() =>
          startTransition(async () => {
            setResult(null);
            setResult(await action());
          })
        }
      >
        {pending ? pendingLabel : children}
      </Button>
      {result?.error && (
        <p role="alert" className="font-mono text-xs font-bold">
          ✕ {result.error}
        </p>
      )}
      {result?.ok && doneLabel && <p className="font-mono text-xs font-bold">✓ {doneLabel}</p>}
    </div>
  );
}
