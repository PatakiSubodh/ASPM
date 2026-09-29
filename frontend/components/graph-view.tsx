"use client";

import dynamic from "next/dynamic";

const FindingsGraph = dynamic(() => import("./findings-graph"), {
  ssr: false,
  loading: () => (
    <div className="flex h-[600px] items-center justify-center text-sm text-zinc-500">
      Loading graph…
    </div>
  ),
});

export default FindingsGraph;
