"use server";

import type { Provider } from "@supabase/supabase-js";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";

function credentials(formData: FormData) {
    return {
        email: String(formData.get("email") ?? ""),
        password: String(formData.get("password") ?? ""),
    };
}

export async function signIn(formData: FormData) {
    const supabase = await createClient();
    const { error } = await supabase.auth.signInWithPassword(credentials(formData));
    if (error) redirect("/login?error=credentials");
    redirect("/");
}

export async function signUp(formData: FormData) {
    if (formData.get("password") !== formData.get("confirm")) {
        redirect("/signup?error=mismatch");
    }
    const supabase = await createClient();
    const { error } = await supabase.auth.signUp(credentials(formData));
    if (error) redirect("/signup?error=signup");
    redirect("/login?message=check-email");
}

async function signInWith(provider: Provider) {
    const supabase = await createClient();
    const origin = (await headers()).get("origin");
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider,
        options: { redirectTo: `${origin}/auth/callback` },
    });
    if (error) redirect("/login?error=oauth");
    redirect(data.url);
}

export async function signInWithGoogle() {
    await signInWith("google");
}

export async function signInWithGithub() {
    await signInWith("github");
}

export async function signOut() {
    const supabase = await createClient();
    await supabase.auth.signOut();
    redirect("/login");
}
