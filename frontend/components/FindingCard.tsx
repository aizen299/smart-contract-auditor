"use client";

import { useState } from "react";
import { ChevronDown, Wrench, Brain, Hash } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SeverityBadge } from "./SeverityBadge";
import { SEVERITY_ORDER, severityClasses, severityMeta } from "@/lib/severity";
import { chainBadgeStyle, chainDisplay } from "@/lib/chains";
import type { Finding, Severity } from "@/types";

interface FindingCardProps {
  finding: Finding;
  index: number;
}


function MLBadge({ exploitability, confidence }: { exploitability: string; confidence: number }) {
  // ML exploitability reuses the finding severity scale, so it reads from the
  // same table rather than carrying its own copy of the colours.
  const known = SEVERITY_ORDER.includes(exploitability as Severity);
  const c = known ? severityClasses(exploitability as Severity) : null;
  const colors = c
    ? `${c.text} ${c.bg} ${c.border}`
    : "text-muted-foreground bg-elevated border-border";
  const pct = Math.round(confidence * 100);

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border text-xs font-semibold tracking-wide ${colors}`}>
      <Brain className="w-2.5 h-2.5" />
      ML: {exploitability} · {pct}%
    </div>
  );
}

function ChainBadge({ chain }: { chain: string }) {
  const { label } = chainDisplay(chain);
  return (
    <span
      className="rounded-full border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wider"
      style={chainBadgeStyle(chain)}
    >
      {label}
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
  const sevHex        = severityMeta(sev).hex;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, duration: 0.2 }}
      className="overflow-hidden rounded-lg border border-border/70 bg-card transition-colors duration-fast hover:bg-elevated"
      style={{ borderLeftWidth: "var(--finding-accent-w)", borderLeftColor: `${sevHex}99` }}
    >
      {/* Header row */}
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        {/* Index */}
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-elevated border border-border flex items-center justify-center text-xs font-semibold text-muted-foreground font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* Title + chain badge */}
        <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-foreground leading-snug">{finding.title}</span>
          {isChainSpecific && chain && <ChainBadge chain={chain} />}
        </div>

        {/* Right side — occurrences + severity + chevron */}
        <div className="flex items-center gap-2.5 flex-shrink-0">
          {occurrences && occurrences > 1 && (
            <div className="hidden sm:flex items-center gap-1 text-xs text-subtle font-mono">
              <Hash className="w-2.5 h-2.5" />
              {occurrences}
            </div>
          )}
          <SeverityBadge severity={sev} size="sm" />
          <ChevronDown
            className={`w-4 h-4 text-muted-foreground transition-transform duration-300 ${expanded ? "rotate-180" : ""}`}
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
            <div className="px-5 pb-5 pt-4 space-y-4 border-t border-border">

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
                      <span className="text-xs text-subtle">
                        {chain === "solana"
                          ? "Solana-specific finding"
                          : chain === "ethereum" || chain === "evm"
                          ? "EVM / Solidity finding"
                          : `${chain}-specific finding`}
                      </span>
                    </div>
                  )}
                  {occurrences && occurrences > 1 && (
                    <span className="sm:hidden text-xs text-subtle font-mono">
                      {occurrences}× occurrences
                    </span>
                  )}
                </div>
              )}

              {/* Description */}
              <div>
                <p className="text-xs uppercase tracking-widest text-subtle mb-2 font-semibold">
                  Description
                </p>
                <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
              </div>

              {/* Fix */}
              <div className="rounded-md bg-primary/[0.04] border border-primary/[0.12] p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Wrench className="w-3 h-3 text-primary/70" />
                  <p className="text-xs uppercase tracking-widest text-primary/60 font-semibold">
                    Recommended Fix
                  </p>
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed">{finding.fix}</p>
              </div>

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
