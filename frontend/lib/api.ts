import { createClient } from "@/lib/supabase/server";

export async function apiHeaders(): Promise<HeadersInit> {
  const supabase = await createClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  return { Authorization: `Bearer ${session?.access_token ?? ""}` };
}
