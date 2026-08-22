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

/**
 * Risk rail colours. Rendered as a crisp glowing edge rather than a shadow
 * shift, so severity survives at a glance and at low contrast sensitivity.
 */
const RAIL: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

const CHAIN_COLOR: Record<string, string> = {
  ethereum: "#a78bfa",
  evm: "#a78bfa",
  solana: "#ffb340",
  arbitrum: "#5ac8fa",
  optimism: "#ff6961",
  base: "#64a9ff",
  polygon: "#c084fc",
  bnb: "#ffd60a",
  avalanche: "#ff6961",
  l2: "#5ac8fa",
};

function chainColor(chain: string) {
  return CHAIN_COLOR[chain.toLowerCase()] ?? "var(--sev-low)";
}

function ChainBadge({ chain }: { chain: string }) {
  const color = chainColor(chain);
  return (
    <span
      className="sev-outline inline-flex items-center px-1.5 py-[2px] text-[9px]"
      style={{ borderColor: `${color}88`, color }}
    >
      {chain}
    </span>
  );
}

function MLBadge({
  exploitability,
  confidence,
}: {
  exploitability: string;
  confidence: number;
}) {
  const color = RAIL[exploitability] ?? "var(--text-muted)";
  const pct = Math.round(confidence * 100);
  return (
    <div className="neu-chip inline-flex items-center gap-2 px-2.5 py-1.5">
      <Brain className="w-3 h-3" style={{ color }} />
      <span className="text-[10px] tracking-wider text-ink-muted uppercase">ML</span>
      {/* Prediction and confidence are data: flat, full contrast. */}
      <span className="data-strong text-[11px] font-bold" style={{ color }}>
        {exploitability}
      </span>
      <span className="data-strong text-[11px] text-ink-primary">{pct}%</span>
    </div>
  );
}

export function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const anyFinding = finding as any;
  const hasML =
    !!anyFinding.ml_exploitability && anyFinding.ml_exploitability !== "unknown";
  const chain = (anyFinding.chain as string | undefined) ?? "ethereum";
  const occurrences = anyFinding.occurrences as number | undefined;
  const filesAffected = anyFinding.files_affected as string[] | undefined;
  const sev = finding.severity;
  const rail = RAIL[sev] ?? "var(--text-faint)";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.035, 0.3), duration: 0.25 }}
      className="neu-panel risk-rail overflow-hidden"
      style={{ ["--rail" as string]: rail }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        {/* Index — a sunken track holding flat mono digits. */}
        <span className="code-ref flex-shrink-0 w-7 h-7 flex items-center justify-center text-[11px] font-bold">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
          {/* Title is primary data: stark white, no shadow. */}
          <span className="data-strong text-sm font-semibold leading-snug">
            {finding.title}
          </span>
          <ChainBadge chain={chain} />
        </div>

        <div className="flex items-center gap-2.5 flex-shrink-0">
          {occurrences && occurrences > 1 && (
            <span className="code-ref hidden sm:flex items-center gap-1 px-2 py-1 text-[10px] font-bold">
              <Hash className="w-2.5 h-2.5 opacity-60" />
              {occurrences}
            </span>
          )}
          <SeverityBadge severity={sev} size="sm" />
          <ChevronDown
            className={`w-4 h-4 text-ink-muted transition-transform duration-300 ${
              expanded ? "rotate-180" : ""
            }`}
          />
        </div>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.24, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 pt-1 space-y-4">
              {(hasML || occurrences) && (
                <div className="flex flex-wrap items-center gap-2">
                  {hasML && (
                    <MLBadge
                      exploitability={anyFinding.ml_exploitability}
                      confidence={anyFinding.ml_confidence}
                    />
                  )}
                  {occurrences && occurrences > 1 && (
                    <span className="sm:hidden code-ref px-2 py-1 text-[10px] font-bold">
                      {occurrences}× occurrences
                    </span>
                  )}
                </div>
              )}

              <div className="neu-well px-4 py-3.5">
                <p className="text-[10px] uppercase tracking-[0.18em] text-ink-muted mb-2 font-bold">
                  Description
                </p>
                <p className="text-[13px] text-ink-secondary leading-relaxed">
                  {finding.description}
                </p>
              </div>

              {filesAffected && filesAffected.length > 0 && (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] uppercase tracking-[0.18em] text-ink-muted font-bold">
                    Files
                  </span>
                  {filesAffected.map((f) => (
                    <span key={f} className="code-ref px-2 py-1 text-[10px]">
                      {f}
                    </span>
                  ))}
                </div>
              )}

              {/* The fix is the actionable payload — flagged with the safe accent. */}
              <div
                className="neu-well px-4 py-3.5"
                style={{ boxShadow: `var(--press-sm), inset 0 0 0 1px var(--sev-safe)33` }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Wrench className="w-3 h-3" style={{ color: "var(--sev-safe)" }} />
                  <p
                    className="text-[10px] uppercase tracking-[0.18em] font-bold"
                    style={{ color: "var(--sev-safe)" }}
                  >
                    Recommended Fix
                  </p>
                </div>
                <p className="text-[13px] text-ink-secondary leading-relaxed">
                  {finding.fix}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
