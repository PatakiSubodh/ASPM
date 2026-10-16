import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { requestPasswordReset } from "@/app/auth/actions";
import { AuthNotice } from "@/components/auth-notice";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BUTTON, FIELD_INPUT, FIELD_LABEL } from "@/lib/auth-styles";

const ERRORS: Record<string, string> = {
  email: "Enter the email of your account.",
  limit: "You've asked for 3 reset links in the last hour. Use the newest email, or try again later.",
  wait: "A reset link was just sent to this email. Try again in a few minutes.",
  rate: "Too many reset emails were sent. Wait a few minutes and try again.",
};

export default async function ForgotPasswordPage({ searchParams }: PageProps<"/forgot-password">) {
  const { error } = await searchParams;
  const errorText = ERRORS[String(error)];

  return (
    <div className="grid items-center gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-16">
      <section className="animate-rise space-y-6">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          00 / Forgot password
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Reset your{" "}
          <span className="inline-block -rotate-2 border-2 border-foreground bg-acid px-3 shadow-brutal">
            password
          </span>
          .
        </h1>
        <p className="max-w-md font-mono text-sm text-muted-foreground">
          We&apos;ll email you a link to set a new password. Signed up with Google or GitHub? This adds a password to the same account.
        </p>
      </section>

      <Card
        className="brutal animate-rise w-full max-w-md gap-0 bg-card py-0 lg:justify-self-end"
        style={{ animationDelay: "80ms" }}
      >
        <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
          <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
            Reset link
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 px-6 py-6">
          {errorText && <AuthNotice tone="error">{errorText}</AuthNotice>}
          <form action={requestPasswordReset} className="space-y-5" noValidate>
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

            <Button type="submit" className={`${BUTTON} bg-acid text-foreground hover:bg-acid`}>
              Send reset link
              <ArrowRight className="size-4" />
            </Button>
          </form>
        </CardContent>
        <div className="border-t-2 border-dashed border-foreground/20 px-6 py-4 font-mono text-[11px] text-muted-foreground">
          Remembered it?{" "}
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
