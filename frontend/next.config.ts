import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async redirects() {
    return [{ source: "/catalog", destination: "/repositories", permanent: false }];
  },
};

export default nextConfig;
