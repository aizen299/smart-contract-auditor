"use client";

import { useState } from "react";
import { ChevronDown, Wrench, Brain } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "@/types";

interface FindingCardProps {
  finding: Finding;
  index: number;
}

function MLBadge({ exploitability, confidence }: { exploitability: string; confidence: number }) {
  const colorMap: Record<string, string> = {
    CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
    HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    LOW: "text-sky-400 bg-sky-500/10 border-sky-500/20",
  };

  const colors = colorMap[exploitability] || "text-white/30 bg-white/5 border-white/10";
  const pct = Math.round(confidence * 100);

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[10px] font-semibold tracking-wide ${colors}`}>
      <Brain className="w-2.5 h-2.5" />
      ML: {exploitability} · {pct}%
    </div>
  );
}

function L2Badge({ chain }: { chain: string }) {
  return (
    <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[10px] font-semibold tracking-wide text-sky-400 bg-sky-500/10 border-sky-500/20">
      <svg className="w-2.5 h-2.5" viewBox="0 0 10 10" fill="currentColor">
        <circle cx="5" cy="5" r="4" />
      </svg>
      {chain.toUpperCase()}
    </div>
  );
}

export function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const hasML = (finding as any).ml_exploitability && (finding as any).ml_exploitability !== "unknown";
  const isL2 = (finding as any).l2_detected === true;
  const chain = (finding as any).chain || "l2";

  return (
    <div
      className="group rounded-2xl border transition-all duration-300 overflow-hidden border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.035] hover:border-white/[0.12]"
      style={{ animationDelay: `${index * 80}ms` }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-white/[0.05] border border-white/[0.07] flex items-center justify-center text-[10px] font-semibold text-white/30 font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="text-sm font-medium text-white/90">{finding.title}</span>
          {isL2 && (
            <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold tracking-wider uppercase">
              {chain}
            </span>
          )}
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <SeverityBadge severity={finding.severity} size="sm" />
          <ChevronDown
            className={`w-4 h-4 text-white/30 transition-transform duration-300 ${expanded ? "rotate-180" : ""}`}
          />
        </div>
      </button>

      <div
        className={`transition-all duration-300 ease-in-out overflow-hidden ${
          expanded ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <div className="px-5 pb-5 space-y-4 border-t border-white/[0.05] pt-4">

          {/* ML Prediction */}
          {hasML && (
            <div className="flex items-center gap-2">
              <MLBadge
                exploitability={(finding as any).ml_exploitability}
                confidence={(finding as any).ml_confidence}
              />
              <span className="text-[10px] text-white/25">
                ML-predicted exploitability
              </span>
            </div>
          )}

          {/* L2 Chain Badge */}
          {isL2 && (
            <div className="flex items-center gap-2">
              <L2Badge chain={chain} />
              <span className="text-[10px] text-white/25">
                L2-specific finding — detected {chain} identifiers
              </span>
            </div>
          )}

          {/* Description */}
          <div>
            <p className="text-[10px] uppercase tracking-widest text-white/25 mb-2 font-semibold">
              Description
            </p>
            <p className="text-sm text-white/60 leading-relaxed">{finding.description}</p>
          </div>

          {/* Fix */}
          <div className="rounded-xl bg-[#00ff88]/[0.04] border border-[#00ff88]/[0.12] p-4">
            <div className="flex items-center gap-2 mb-2">
              <Wrench className="w-3 h-3 text-[#00ff88]/70" />
              <p className="text-[10px] uppercase tracking-widest text-[#00ff88]/60 font-semibold">
                Recommended Fix
              </p>
            </div>
            <p className="text-sm text-white/65 leading-relaxed">{finding.fix}</p>
          </div>

        </div>
      </div>
    </div>
  );
}