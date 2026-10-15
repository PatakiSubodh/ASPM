import { cn } from "@/lib/utils";

export function AuthNotice({
    tone,
    children,
    }: {
    tone: "error" | "info";
    children: string;
    }) {
    return (
        <p
        role={tone === "error" ? "alert" : "status"}
        className={cn(
            "border-2 border-foreground px-3 py-2 font-mono text-xs shadow-brutal-sm",
            tone === "error" ? "bg-crit" : "bg-acid",
        )}
        >
        {children}
        </p>
    );
}
