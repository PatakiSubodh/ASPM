"use client";

import { ArrowRight, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ProfileMenu, type Profile } from "@/components/profile-menu";
import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/", label: "Findings", note: "Ranked attack paths" },
  { href: "/graph", label: "Graph", note: "Code → cloud, as a map" },
  { href: "/assets", label: "Assets", note: "What runs where, by risk" },
  { href: "/scans", label: "Scans", note: "Every scan run and result" },
  { href: "/repositories", label: "Repositories", note: "Repos, assets and where they deploy" },
];

const AUTH_PAGES = ["/login", "/signup", "/forgot-password", "/reset-password"];

function isActive(href: string, pathname: string) {
  return href === "/" ? pathname === "/" || pathname.startsWith("/findings") : pathname.startsWith(href);
}

function number(index: number) {
  return String(index + 1).padStart(2, "0");
}

export function SiteNav({ profile }: { profile: Profile | null }) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const signedIn = Boolean(profile) && !AUTH_PAGES.includes(pathname);
  const current = LINKS.findIndex(({ href }) => isActive(href, pathname));

  useEffect(() => {
    if (!signedIn) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") return setOpen(false);
      const target = event.target as HTMLElement;
      if (event.metaKey || event.ctrlKey || event.altKey || target.isContentEditable) return;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      const link = LINKS[Number(event.key) - 1];
      if (!link) return;
      setOpen(false);
      router.push(link.href);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [signedIn, router]);

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
  }, [open]);

  return (
    <>
      <header className="sticky top-0 z-30 border-b-2 border-foreground bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex min-w-0 items-baseline gap-4">
            <Link href="/" onClick={() => setOpen(false)} className="flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tighter">ASPM</span>
              <span className="inline-block h-5 w-2.5 translate-y-0.5 animate-blink bg-acid ring-2 ring-foreground" />
            </Link>
            {signedIn && current >= 0 && (
              <span className="truncate font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                {number(current)} / {LINKS[current].label}
              </span>
            )}
          </div>
          {signedIn && profile && (
            <div className="flex items-center gap-4">
              <button
                type="button"
                aria-expanded={open}
                aria-controls="site-index"
                onClick={() => setOpen((value) => !value)}
                className={cn(
                  "flex h-10 items-center gap-3 border-2 border-foreground px-3 font-mono text-xs font-bold uppercase tracking-widest shadow-brutal-sm transition-[translate,box-shadow,background-color] duration-150 hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-brutal",
                  open ? "bg-foreground text-acid" : "bg-acid",
                )}
              >
                {open ? "Close" : "Index"}
                {open ? (
                  <X className="size-4" />
                ) : (
                  <span aria-hidden className="flex flex-col gap-0.75">
                    <span className="h-0.5 w-4 bg-foreground" />
                    <span className="h-0.5 w-3 bg-foreground" />
                    <span className="h-0.5 w-4 bg-foreground" />
                  </span>
                )}
              </button>
              <ProfileMenu profile={profile} />
            </div>
          )}
        </div>
      </header>

      {signedIn && (
        <div
          id="site-index"
          inert={!open}
          className={cn(
            "fixed inset-x-0 top-16 bottom-0 z-30 overflow-y-auto border-t-2 border-foreground bg-foreground text-background transition-[opacity,translate] duration-300 ease-out",
            open ? "translate-y-0 opacity-100" : "pointer-events-none -translate-y-6 opacity-0",
          )}
        >
          <nav className="mx-auto flex min-h-full max-w-6xl flex-col px-4 py-10 sm:px-6">
            <p className="font-mono text-xs uppercase tracking-[0.3em] text-background/60">00 / Index</p>
            <ul className="mt-6 flex-1 divide-y-2 divide-dashed divide-background/20 border-y-2 border-background/20">
              {LINKS.map(({ href, label, note }, index) => {
                const active = index === current;
                return (
                  <li
                    key={href}
                    className={cn("transition-[opacity,translate] duration-300 ease-out", open ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0")}
                    style={{ transitionDelay: open ? `${80 + index * 60}ms` : "0ms" }}
                  >
                    <Link
                      href={href}
                      onClick={() => setOpen(false)}
                      aria-current={active ? "page" : undefined}
                      className="group grid grid-cols-[3rem_1fr_auto] items-center gap-4 px-2 py-4 transition-colors hover:bg-acid hover:text-foreground sm:grid-cols-[4rem_1fr_16rem_auto] sm:py-5"
                    >
                      <span className={cn("font-mono text-sm font-bold tabular-nums", active ? "text-acid group-hover:text-foreground" : "text-background/50 group-hover:text-foreground")}>
                        {number(index)}
                      </span>
                      <span className="flex items-center gap-4">
                        <span className="text-5xl font-bold leading-none tracking-tighter transition-transform duration-200 group-hover:translate-x-3 sm:text-7xl">
                          {label}
                        </span>
                        {active && (
                          <span className="-rotate-3 border-2 border-acid px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-acid group-hover:border-foreground group-hover:text-foreground">
                            ● You are here
                          </span>
                        )}
                      </span>
                      <span className="hidden font-mono text-xs text-background/60 group-hover:text-foreground sm:block">{note}</span>
                      <ArrowRight className="size-6 -translate-x-2 opacity-0 transition-[opacity,translate] duration-200 group-hover:translate-x-0 group-hover:opacity-100" />
                    </Link>
                  </li>
                );
              })}
            </ul>
            <p className="mt-6 font-mono text-[11px] uppercase tracking-widest text-background/60">
              Press <kbd className="border border-background/40 px-1.5 text-background">1</kbd>–<kbd className="border border-background/40 px-1.5 text-background">5</kbd> anywhere to jump · <kbd className="border border-background/40 px-1.5 text-background">Esc</kbd> to close
            </p>
          </nav>
        </div>
      )}
    </>
  );
}
