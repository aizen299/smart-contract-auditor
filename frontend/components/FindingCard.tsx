"use client";

import { useState } from "react";
import { ChevronDown, Wrench, Brain, Hash } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "@/types";

interface FindingCardProps {
  finding: Finding;
  index: number;
}

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: "border-l-red-500/60",
  HIGH:     "border-l-orange-500/60",
  MEDIUM:   "border-l-yellow-500/60",
  LOW:      "border-l-blue-500/60",
};

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: "hover:bg-red-500/[0.03]",
  HIGH:     "hover:bg-orange-500/[0.03]",
  MEDIUM:   "hover:bg-yellow-500/[0.03]",
  LOW:      "hover:bg-blue-500/[0.03]",
};

const CHAIN_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  ethereum: { text: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  evm:      { text: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  solana:   { text: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/20"  },
  arbitrum: { text: "text-sky-400",    bg: "bg-sky-500/10",    border: "border-sky-500/20"    },
  optimism: { text: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/20"    },
  base:     { text: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20"   },
  polygon:  { text: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  l2:       { text: "text-sky-400",    bg: "bg-sky-500/10",    border: "border-sky-500/20"    },
};

function getChainColors(chain: string) {
  return CHAIN_COLORS[chain.toLowerCase()] ?? { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/20" };
}

function MLBadge({ exploitability, confidence }: { exploitability: string; confidence: number }) {
  const colorMap: Record<string, string> = {
    CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
    HIGH:     "text-orange-400 bg-orange-500/10 border-orange-500/20",
    MEDIUM:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    LOW:      "text-sky-400 bg-sky-500/10 border-sky-500/20",
  };
  const colors = colorMap[exploitability] ?? "text-white/30 bg-white/5 border-white/10";
  const pct = Math.round(confidence * 100);

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[10px] font-semibold tracking-wide ${colors}`}>
      <Brain className="w-2.5 h-2.5" />
      ML: {exploitability} · {pct}%
    </div>
  );
}

function ChainBadge({ chain }: { chain: string }) {
  const c = getChainColors(chain);
  return (
    <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-semibold tracking-wider uppercase border ${c.bg} ${c.text} ${c.border}`}>
      {chain}
    </span>
  );
}

export function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const hasML           = !!(finding as any).ml_exploitability && (finding as any).ml_exploitability !== "unknown";
  // Default to "ethereum" so pure EVM findings always have a chain label
  const chain           = ((finding as any).chain as string | undefined) ?? "ethereum";
  const isChainSpecific = true; // always show chain badge — every finding belongs to a chain
  const occurrences     = (finding as any).occurrences as number | undefined;
  const sev           = finding.severity;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, duration: 0.2 }}
      className={`rounded-2xl border border-white/[0.07] border-l-2 overflow-hidden transition-colors duration-200
        bg-white/[0.02] ${SEVERITY_BG[sev] ?? "hover:bg-white/[0.035]"} ${SEVERITY_BORDER[sev] ?? "border-l-white/10"}`}
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

        {/* Title + chain badge */}
        <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-white/90 leading-snug">{finding.title}</span>
          {isChainSpecific && chain && <ChainBadge chain={chain} />}
        </div>

        {/* Right side — occurrences + severity + chevron */}
        <div className="flex items-center gap-2.5 flex-shrink-0">
          {occurrences && occurrences > 1 && (
            <div className="hidden sm:flex items-center gap-1 text-[10px] text-white/25 font-mono">
              <Hash className="w-2.5 h-2.5" />
              {occurrences}
            </div>
          )}
          <SeverityBadge severity={sev} size="sm" />
          <ChevronDown
            className={`w-4 h-4 text-white/30 transition-transform duration-300 ${expanded ? "rotate-180" : ""}`}
          />
        </div>
      </button>

      {/* Expanded content */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 pt-4 space-y-4 border-t border-white/[0.05]">

              {/* ML + Chain badges row */}
              {(hasML || isChainSpecific) && (
                <div className="flex flex-wrap items-center gap-2">
                  {hasML && (
                    <MLBadge
                      exploitability={(finding as any).ml_exploitability}
                      confidence={(finding as any).ml_confidence}
                    />
                  )}
                  {isChainSpecific && chain && (
                    <div className="flex items-center gap-1.5">
                      <ChainBadge chain={chain} />
                      <span className="text-[10px] text-white/25">
                        {chain === "solana"
                          ? "Solana-specific finding"
                          : chain === "ethereum" || chain === "evm"
                          ? "EVM / Solidity finding"
                          : `${chain}-specific finding`}
                      </span>
                    </div>
                  )}
                  {occurrences && occurrences > 1 && (
                    <span className="sm:hidden text-[10px] text-white/25 font-mono">
                      {occurrences}× occurrences
                    </span>
                  )}
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
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
