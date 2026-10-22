"use client";

import { ChevronDown, LogOut, Plug } from "lucide-react";
import { useRouter } from "next/navigation";

import { signOut } from "@/app/auth/actions";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type Profile = { email: string; name: string | null };

function initials({ email, name }: Profile) {
  const words = (name ?? "").trim().split(/\s+/).filter(Boolean);
  const letters = words.length ? words.slice(0, 2).map((word) => word[0]).join("") : email.slice(0, 1);
  return letters.toUpperCase() || "?";
}

export function ProfileMenu({ profile }: { profile: Profile }) {
  const router = useRouter();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label="Account"
        className="group flex h-10 shrink-0 items-center gap-2 border-2 border-foreground bg-card pr-2 pl-2 shadow-brutal-sm transition-[translate,box-shadow,background-color] duration-150 outline-none hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-brutal focus-visible:bg-acid/30 data-popup-open:bg-acid"
      >
        <span className="flex size-6 -rotate-6 items-center justify-center border-2 border-foreground bg-acid font-mono text-[10px] font-bold transition-transform group-hover:rotate-0 group-data-popup-open:rotate-0 group-data-popup-open:bg-card">
          {initials(profile)}
        </span>
        <ChevronDown className="size-4 transition-transform duration-150 group-data-popup-open:rotate-180" />
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        sideOffset={10}
        className="brutal w-72 rounded-none bg-card p-0 ring-0"
      >
        <div className="space-y-1 bg-foreground px-4 py-3">
          <p className="font-mono text-[11px] font-bold uppercase tracking-widest text-acid">
            Signed in as
          </p>
          <p className="truncate text-lg font-bold tracking-tight text-background">
            {profile.name ?? profile.email.split("@")[0]}
          </p>
          <p className="truncate font-mono text-xs text-background/70">{profile.email}</p>
        </div>
        <DropdownMenuSeparator className="mx-0 my-0 h-0.5 bg-foreground" />
        <DropdownMenuItem
          onClick={() => router.push("/settings/github")}
          className="m-1 gap-2 rounded-none px-3 py-2.5 font-mono text-[11px] font-bold uppercase tracking-widest focus:bg-acid"
        >
          <Plug className="size-4" />
          GitHub
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => signOut()}
          className="m-1 gap-2 rounded-none px-3 py-2.5 font-mono text-[11px] font-bold uppercase tracking-widest focus:bg-acid"
        >
          <LogOut className="size-4" />
          Logout
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
