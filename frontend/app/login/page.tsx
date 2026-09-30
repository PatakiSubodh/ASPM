import { ArrowRight, KeyRound } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const FIELD_LABEL = "font-mono text-[11px] font-bold uppercase tracking-widest";
const FIELD_INPUT =
  "h-11 border-2 border-foreground bg-card px-3 font-mono text-sm shadow-brutal-sm placeholder:text-muted-foreground/70 focus-visible:border-foreground focus-visible:ring-0 focus-visible:bg-acid/15";
const BUTTON =
  "brutal brutal-lift h-11 w-full gap-2 font-mono text-xs font-bold uppercase tracking-widest";

const HIGHLIGHTS = [
  "Every open issue ranked by real exposure",
  "Trace code to the assets it runs on",
  "Scans keep status up to date on their own",
];

export default function LoginPage() {
  return (
    <div className="grid items-center gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-16">
      <section className="animate-rise space-y-6">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          00 / Sign in
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Welcome{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            back
          </span>
          .
        </h1>
        <p className="max-w-md font-mono text-sm text-muted-foreground">
          Sign in to see what&apos;s exposed across your code and cloud.
        </p>
        <ul className="hidden space-y-3 pt-2 lg:block">
          {HIGHLIGHTS.map((item, i) => (
            <li
              key={item}
              style={{ animationDelay: `${120 + i * 60}ms` }}
              className="animate-rise flex items-center gap-3 font-mono text-sm"
            >
              <span className="inline-flex size-6 shrink-0 items-center justify-center border-2 border-foreground bg-card text-[11px] font-bold tabular-nums shadow-brutal-sm">
                {String(i + 1).padStart(2, "0")}
              </span>
              {item}
            </li>
          ))}
        </ul>
      </section>

      <Card
        className="brutal animate-rise w-full max-w-md gap-0 bg-card py-0 lg:justify-self-end"
        style={{ animationDelay: "80ms" }}
      >
        <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
          <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
            Account
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 px-6 py-6">
          <form className="space-y-5" noValidate>
            <div className="space-y-2">
              <Label htmlFor="email" className={FIELD_LABEL}>
                Work email
              </Label>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                className={FIELD_INPUT}
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password" className={FIELD_LABEL}>
                  Password
                </Label>
                <Link
                  href="#"
                  className="font-mono text-[11px] underline decoration-2 underline-offset-4 hover:bg-acid"
                >
                  Forgot password?
                </Link>
              </div>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                placeholder="••••••••••"
                className={FIELD_INPUT}
              />
            </div>

            <Label className="cursor-pointer gap-3 font-mono text-xs">
              <Checkbox
                name="remember"
                className="size-5 rounded-none border-2 border-foreground bg-card data-checked:border-foreground data-checked:bg-acid data-checked:text-foreground focus-visible:ring-0 focus-visible:ring-offset-0"
              />
              Keep me signed in for 30 days
            </Label>

            <Button type="button" className={`${BUTTON} bg-acid text-foreground hover:bg-acid`}>
              Sign in
              <ArrowRight className="size-4" />
            </Button>
          </form>

          <div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            <span className="h-0.5 flex-1 bg-foreground/20" />
            or
            <span className="h-0.5 flex-1 bg-foreground/20" />
          </div>

          <Button
            type="button"
            variant="outline"
            className={`${BUTTON} bg-card hover:bg-card`}
          >
            <KeyRound className="size-4" />
            Continue with SSO
          </Button>
        </CardContent>
        <div className="border-t-2 border-dashed border-foreground/20 px-6 py-4 font-mono text-[11px] text-muted-foreground">
          No account yet? Ask your workspace admin for an invite.
        </div>
      </Card>
    </div>
  );
}
