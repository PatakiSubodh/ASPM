import { Badge } from "@/components/ui/badge";
import { priorityBg, type Risk } from "@/lib/findings";
import { cn } from "@/lib/utils";

export function RiskBadge({ risk }: { risk: Risk }) {
  const { severity, environment, exposure } = risk.factors;
  return (
    <Badge
      title={`Risk ${risk.score}/100 = severity ${severity} × environment ${environment} × exposure ${exposure}`}
      className={cn(
        "h-6 gap-1.5 border-2 border-foreground px-2 font-mono text-[11px] font-bold text-foreground tabular-nums shadow-brutal-sm",
        priorityBg[risk.priority],
      )}
    >
      {risk.priority}
      <span className="font-normal">{String(risk.score).padStart(2, "0")}</span>
    </Badge>
  );
}
