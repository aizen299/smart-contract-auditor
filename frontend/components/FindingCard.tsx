"use client";

import { useState } from "react";
import { ChevronDown, Wrench } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "@/types";

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={`group rounded-2xl border transition-all duration-300 overflow-hidden
        border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.035] hover:border-white/[0.12]
      `}
      style={{ animationDelay: `${index * 80}ms` }}
    >
      {/* Header row */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        {/* Index */}
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-white/[0.05] border border-white/[0.07] flex items-center justify-center text-[10px] font-semibold text-white/30 font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-white/90">{finding.title}</span>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <SeverityBadge severity={finding.severity} size="sm" />
          <ChevronDown
            className={`w-4 h-4 text-white/30 transition-transform duration-300 ${expanded ? "rotate-180" : ""}`}
          />
        </div>
      </button>

      {/* Expanded content */}
      <div
        className={`transition-all duration-300 ease-in-out overflow-hidden ${
          expanded ? "max-h-96 opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <div className="px-5 pb-5 space-y-4 border-t border-white/[0.05] pt-4">
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