import { Badge } from "@/components/ui/badge";
import { type FindingStatus, statusClass, statusLabel } from "@/lib/findings";
import { cn } from "@/lib/utils";

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge
      className={cn(
        "h-6 border-2 border-foreground px-2 font-mono text-[11px] font-bold uppercase shadow-brutal-sm",
        statusClass[status] ?? "bg-card text-foreground",
      )}
    >
      {statusLabel[status] ?? status}
    </Badge>
  );
}
