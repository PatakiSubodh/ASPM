# ASPM Frontend

Next.js 16 (App Router) UI for ASPM, behind Supabase login. All data is fetched on the Next.js server with the signed-in user's Supabase token.

Setup, environment files and run commands are in the root [`README.md`](../README.md#local-development-recommended-for-coding).

```bash
npm install
npm run dev
npm run lint
npm run build
```

Needs `frontend/.env.local` (copy from `.env.local.example`): `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`.
