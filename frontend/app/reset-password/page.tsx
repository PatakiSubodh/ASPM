import { ArrowRight } from "lucide-react";

import { updatePassword } from "@/app/auth/actions";
import { AuthNotice } from "@/components/auth-notice";
import { PasswordInput } from "@/components/password-input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { BUTTON, FIELD_INPUT, FIELD_LABEL } from "@/lib/auth-styles";

const ERRORS: Record<string, string> = {
  mismatch: "Passwords do not match.",
  update: "Could not update the password. Use at least 6 characters, different from your old password.",
};

export default async function ResetPasswordPage({ searchParams }: PageProps<"/reset-password">) {
  const { error } = await searchParams;
  const errorText = ERRORS[String(error)];

  return (
    <div className="grid items-center gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-16">
      <section className="animate-rise space-y-6">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
          00 / New password
        </p>
        <h1 className="text-5xl font-bold leading-[0.9] tracking-tighter sm:text-7xl">
          Set a new{" "}
          <span className="inline-block rotate-1 border-2 border-foreground bg-acid px-3 shadow-brutal">
            password
          </span>
          .
        </h1>
        <p className="max-w-md font-mono text-sm text-muted-foreground">
          After saving you&apos;ll be signed out. Sign in again with the new password.
        </p>
      </section>

      <Card
        className="brutal animate-rise w-full max-w-md gap-0 bg-card py-0 lg:justify-self-end"
        style={{ animationDelay: "80ms" }}
      >
        <CardHeader className="border-b-2 border-foreground bg-foreground px-6 py-3">
          <CardTitle className="font-mono text-[11px] font-bold uppercase tracking-widest text-background">
            New password
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 px-6 py-6">
          {errorText && <AuthNotice tone="error">{errorText}</AuthNotice>}
          <form action={updatePassword} className="space-y-5" noValidate>
            <div className="space-y-2">
              <Label htmlFor="password" className={FIELD_LABEL}>
                New password
              </Label>
              <PasswordInput
                id="password"
                name="password"
                autoComplete="new-password"
                placeholder="••••••••••"
                className={FIELD_INPUT}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm" className={FIELD_LABEL}>
                Confirm password
              </Label>
              <PasswordInput
                id="confirm"
                name="confirm"
                autoComplete="new-password"
                placeholder="••••••••••"
                className={FIELD_INPUT}
              />
            </div>

            <Button type="submit" className={`${BUTTON} bg-acid text-foreground hover:bg-acid`}>
              Save password
              <ArrowRight className="size-4" />
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
