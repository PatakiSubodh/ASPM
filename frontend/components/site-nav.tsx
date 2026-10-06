"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/", label: "Findings" },
  { href: "/graph", label: "Graph" },
  { href: "/assets", label: "Assets" },
  { href: "/scans", label: "Scans" },
  { href: "/catalog", label: "Catalog" },
  { href: "/login", label: "Login" },
];

export function SiteNav() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-30 border-b-2 border-foreground bg-background/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <Link href="/" className="flex items-baseline gap-2">
          <span className="text-2xl font-bold tracking-tighter">ASPM</span>
          <span className="inline-block h-5 w-2.5 translate-y-0.5 animate-blink bg-acid ring-2 ring-foreground" />
          <span className="hidden font-mono text-[11px] uppercase tracking-widest text-muted-foreground sm:inline">
            code → cloud
          </span>
        </Link>
        <nav className="flex items-center gap-3">
          {LINKS.map(({ href, label }) => {
            const active = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  buttonVariants({ variant: "outline", size: "lg" }),
                  "brutal brutal-lift shadow-brutal-sm px-4 font-mono text-xs font-bold uppercase tracking-widest",
                  active
                    ? "bg-acid hover:bg-acid"
                    : "bg-card hover:bg-card",
                )}
              >
                {label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
