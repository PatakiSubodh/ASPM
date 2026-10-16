import type { Metadata } from "next";
import { JetBrains_Mono, Space_Grotesk } from "next/font/google";

import { SiteNav } from "@/components/site-nav";
import { createClient } from "@/lib/supabase/server";
import "./globals.css";

const grotesk = Space_Grotesk({
  variable: "--font-grotesk",
  subsets: ["latin"],
});

const jetbrains = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ASPM",
  description: "Attack paths from code to production, straight from the graph.",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  const meta = user?.user_metadata ?? {};
  const profile = user
    ? { email: user.email ?? "", name: meta.full_name ?? meta.name ?? meta.user_name ?? null }
    : null;

  return (
    <html
      lang="en"
      className={`${grotesk.variable} ${jetbrains.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col">
        <SiteNav profile={profile} />
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-10 sm:px-6 sm:py-14">
          {children}
        </main>
      </body>
    </html>
  );
}
