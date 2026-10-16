const LIMIT = 3;
const WINDOW_MS = 60 * 60 * 1000;
const requests = new Map<string, number[]>();

export function allowReset(email: string) {
    const now = Date.now();
    for (const [key, times] of requests) {
        const recent = times.filter((time) => now - time < WINDOW_MS);
        if (recent.length) requests.set(key, recent);
        else requests.delete(key);
    }
    return (requests.get(email.toLowerCase())?.length ?? 0) < LIMIT;
}

export function recordReset(email: string) {
    const key = email.toLowerCase();
    requests.set(key, [...(requests.get(key) ?? []), Date.now()]);
}
