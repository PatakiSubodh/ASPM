import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { signUp } from "@/app/auth/actions";
import { AuthNotice } from "@/components/auth-notice";
import { OAuthButtons } from "@/components/oauth-buttons";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BUTTON, FIELD_INPUT, FIELD_LABEL } from "@/lib/auth-styles";

const ERRORS: Record<string, string> = {
  mismatch: "Passwords do not match.",
  signup: "Could not create the account. Use a valid email and a password of at least 6 characters.",
};

export default async function SignupPage({ searchParams }: PageProps<"/signup">) {
  const { error } = await searchParams;
  const errorText = ERRORS[String(error)];

  return (
    <div className="grid items-center gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-16">
      <section className="animate-rise space-y-6">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          00 / Sign up
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Create an{" "}
          <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
            account
          </span>
          .
        </h1>
        <p className="max-w-md font-mono text-sm text-muted-foreground">
          Use your work email, or continue with Google or GitHub.
        </p>
      </section>

      <Card
        className="brutal animate-rise w-full max-w-md gap-0 bg-card py-0 lg:justify-self-end"
        style={{ animationDelay: "80ms" }}
      >
        <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
          <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
            New account
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 px-6 py-6">
          {errorText && <AuthNotice tone="error">{errorText}</AuthNotice>}
          <form action={signUp} className="space-y-5" noValidate>
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
              <Label htmlFor="password" className={FIELD_LABEL}>
                Password
              </Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                placeholder="••••••••••"
                className={FIELD_INPUT}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm" className={FIELD_LABEL}>
                Confirm password
              </Label>
              <Input
                id="confirm"
                name="confirm"
                type="password"
                autoComplete="new-password"
                placeholder="••••••••••"
                className={FIELD_INPUT}
              />
            </div>

            <Button type="submit" className={`${BUTTON} bg-acid text-foreground hover:bg-acid`}>
              Create account
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
          Already have an account?{" "}
          <Link
            href="/login"
            className="underline decoration-2 underline-offset-4 hover:bg-acid"
          >
            Sign in
          </Link>
        </div>
      </Card>
    </div>
  );
}
