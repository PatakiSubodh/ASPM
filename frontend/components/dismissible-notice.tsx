"use client";

import { X } from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "@/lib/utils";

export function DismissibleNotice({
  children,
  className,
  seconds = 8,
}: {
  children: React.ReactNode;
  className?: string;
  seconds?: number;
}) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setVisible(false), seconds * 1000);
    return () => clearTimeout(timer);
  }, [seconds]);

  if (!visible) return null;

  return (
    <section className={cn("flex items-start justify-between gap-4", className)}>
      <p>{children}</p>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => setVisible(false)}
        className="grid size-6 shrink-0 place-items-center border-2 border-foreground bg-card shadow-brutal-sm"
      >
        <X className="size-3.5" />
      </button>
    </section>
  );
}
