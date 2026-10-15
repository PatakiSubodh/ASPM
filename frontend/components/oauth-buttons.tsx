import { ArrowRight } from "lucide-react";

import { signInWithGithub, signInWithGoogle } from "@/app/auth/actions";
import { Button } from "@/components/ui/button";
import { BUTTON } from "@/lib/auth-styles";


export function OAuthButtons() {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <form action={signInWithGoogle}>
        <Button type="submit" variant="outline" className={`${BUTTON} bg-card hover:bg-card`}>
          Google
          <ArrowRight className="size-4" />
        </Button>
      </form>
      <form action={signInWithGithub}>
        <Button type="submit" variant="outline" className={`${BUTTON} bg-card hover:bg-card`}>
          GitHub
          <ArrowRight className="size-4" />
        </Button>
      </form>

    </div>
  );
}
