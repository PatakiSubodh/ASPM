export function apiHeaders(): HeadersInit {
  return { "X-API-Key": process.env.ASPM_API_KEY ?? "" };
}
