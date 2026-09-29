"use client";

import dynamic from "next/dynamic";

const FindingsGraph = dynamic(() => import("./findings-graph"), {
  ssr: false,
  loading: () => (
    <div className="brutal flex h-[520px] items-center justify-center bg-card font-mono text-xs uppercase tracking-widest">
      <span className="animate-blink">Loading graph_</span>
    </div>
  ),
});

export default FindingsGraph;
