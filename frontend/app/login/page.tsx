import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { signIn } from "@/app/auth/actions";
import { AuthNotice } from "@/components/auth-notice";
import { OAuthButtons } from "@/components/oauth-buttons";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BUTTON, FIELD_INPUT, FIELD_LABEL } from "@/lib/auth-styles";

const ERRORS: Record<string, string> = {
  credentials: "Wrong email or password, or the email is not confirmed yet.",
  oauth: "Google / GitHub sign-in failed. Try again.",
  confirm: "The confirmation link is invalid or has expired.",
};

const MESSAGES: Record<string, string> = {
  "check-email": "Check your inbox to confirm your account, then sign in.",
};

const HIGHLIGHTS = [

  "Every open issue ranked by real exposure",
  "Trace code to the assets it runs on",
  "Scans keep status up to date on their own",
];

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { error, message } = await searchParams;
  const errorText = ERRORS[String(error)];
  const messageText = MESSAGES[String(message)];

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
          {errorText && <AuthNotice tone="error">{errorText}</AuthNotice>}
          {messageText && <AuthNotice tone="info">{messageText}</AuthNotice>}
          <form action={signIn} className="space-y-5" noValidate>
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

            <Button type="submit" className={`${BUTTON} bg-acid text-foreground hover:bg-acid`}>
              Sign in
              <ArrowRight className="size-4" />
            </Button>
          </form>

          <div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            <span className="h-0.5 flex-1 bg-foreground/20" />
            or
            <span className="h-0.5 flex-1 bg-foreground/20" />
          </div>

          <OAuthButtons />
        </CardContent>
        <div className="border-t-2 border-dashed border-foreground/20 px-6 py-4 font-mono text-[11px] text-muted-foreground">
          No account yet?{" "}
          <Link
            href="/signup"
            className="underline decoration-2 underline-offset-4 hover:bg-acid"
          >
            Create one
          </Link>
        </div>
      </Card>
    </div>
  );
}
