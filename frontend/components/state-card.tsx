import type { ReactNode } from "react";

import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function StateCard({
  tone,
  title,
  children,
}: {
  tone: "error" | "empty";
  title: string;
  children: ReactNode;
}) {
  return (
    <Card
      className={cn(
        "brutal animate-rise max-w-2xl",
        tone === "error" ? "bg-crit" : "bg-card",
      )}
    >
      <CardHeader>
        <CardTitle className="font-mono text-sm font-bold uppercase tracking-widest">
          {tone === "error" ? "✕ " : "∅ "}
          {title}
        </CardTitle>
        <CardDescription className="text-base text-foreground [&_code]:bg-foreground [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:font-mono [&_code]:text-sm [&_code]:text-acid">
          {children}
        </CardDescription>
      </CardHeader>
    </Card>
  );
}
