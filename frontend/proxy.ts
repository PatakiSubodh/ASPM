import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

const AUTH_PAGES = ["/login", "/signup", "/forgot-password"];
const PUBLIC_PATHS = [...AUTH_PAGES, "/auth/"];

function redirectTo(path: string, request: NextRequest, response: NextResponse) {
    const redirect = NextResponse.redirect(new URL(path, request.url));
    response.cookies.getAll().forEach((cookie) => redirect.cookies.set(cookie));
    return redirect;
}

export async function proxy(request: NextRequest) {
    let response = NextResponse.next({ request });
    const supabase = createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
        {
        cookies: {
            getAll() {
            return request.cookies.getAll();
            },
            setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
            response = NextResponse.next({ request });
            cookiesToSet.forEach(({ name, value, options }) =>
                response.cookies.set(name, value, options),
            );
            },
        },
        },
    );

    const {
        data: { user },
    } = await supabase.auth.getUser();

    const path = request.nextUrl.pathname;
    if (!user && !PUBLIC_PATHS.some((p) => path.startsWith(p))) {
        return redirectTo("/login", request, response);
    }
    if (user && AUTH_PAGES.includes(path)) {
        return redirectTo("/", request, response);
    }
    return response;
}

export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
