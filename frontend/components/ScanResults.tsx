"use client";

import { useMemo, useCallback } from "react";
import { FileCode, RotateCcw, Download, Shield } from "lucide-react";
import { motion } from "framer-motion";
import { RiskScore } from "./RiskScore";
import { FindingCard } from "./FindingCard";
import { SeverityBadge } from "./SeverityBadge";
import type { ScanResult, Severity } from "@/types";
import { escapeHtml } from "@/lib/escape-html";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

// On-screen severity tones. Flat design tokens — the PDF export keeps its
// own literal hex palette below, since a print document cannot read CSS vars.
const SEVERITY_TONE: Record<Severity, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH:     "var(--sev-high)",
  MEDIUM:   "var(--sev-medium)",
  LOW:      "var(--sev-low)",
};

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "#2d0a0a", text: "#f87171", border: "#7f1d1d" },
  HIGH:     { bg: "#2d1500", text: "#fb923c", border: "#7c2d12" },
  MEDIUM:   { bg: "#2d2500", text: "#facc15", border: "#713f12" },
  LOW:      { bg: "#0a1a2d", text: "#60a5fa", border: "#1e3a5f" },
};

const CHAIN_DISPLAY: Record<string, { label: string; color: string; bg: string; border: string }> = {
  ethereum: { label: "Ethereum",  color: "#a78bfa", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  arbitrum: { label: "Arbitrum",  color: "#38bdf8", bg: "bg-sky-500/10",    border: "border-sky-500/20"    },
  optimism: { label: "Optimism",  color: "#f87171", bg: "bg-red-500/10",    border: "border-red-500/20"    },
  base:     { label: "Base",      color: "#60a5fa", bg: "bg-blue-500/10",   border: "border-blue-500/20"   },
  polygon:  { label: "Polygon",   color: "#c084fc", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  bnb:      { label: "BNB Chain", color: "#facc15", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  avalanche:{ label: "Avalanche", color: "#f87171", bg: "bg-red-500/10",    border: "border-red-500/20"    },
  solana:   { label: "Solana",    color: "#fb923c", bg: "bg-amber-500/10",  border: "border-amber-500/20"  },
};

function getRiskColor(s: number) {
  if (s >= 80) return "#ef4444";
  if (s >= 60) return "#f97316";
  if (s >= 40) return "#eab308";
  return "#00ff88";
}
function getRiskLabel(s: number) {
  if (s >= 80) return "Critical Risk";
  if (s >= 60) return "High Risk";
  if (s >= 40) return "Medium Risk";
  return "Low Risk";
}

interface ScanResultsProps {
  result: ScanResult;
  fileName: string;
  onRescan: () => void;
}

export function ScanResults({ result, fileName, onRescan }: ScanResultsProps) {
  const chain     = ((result as any).chain as string | undefined) ?? "ethereum";
  const isAnchor  = (result as any).is_anchor === true;
  const chainInfo = CHAIN_DISPLAY[chain] ?? CHAIN_DISPLAY.ethereum;
  const isSolana  = chain === "solana";

  const grouped = useMemo(() => {
    const groups: Record<Severity, typeof result.findings> = {
      CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
    };
    result.findings.forEach((f) => groups[f.severity as Severity]?.push(f));
    return groups;
  }, [result]);

  const counts = useMemo(() => ({
    CRITICAL: grouped.CRITICAL.length,
    HIGH:     grouped.HIGH.length,
    MEDIUM:   grouped.MEDIUM.length,
    LOW:      grouped.LOW.length,
  }), [grouped]);

  const date = new Date().toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });

  const handleExport = useCallback(() => {
    const riskColor = getRiskColor(result.risk_score);
    const riskLabel = getRiskLabel(result.risk_score);

    const findingsHtml = SEVERITY_ORDER.flatMap((sev) =>
      grouped[sev].map((f, i) => {
        const c = SEVERITY_COLORS[sev];
        const fChain = (f as any).chain as string | undefined;
        const chainTag = fChain && fChain !== "evm" && fChain !== "ethereum"
          ? `<span style="font-size:9px;padding:2px 6px;border-radius:20px;background:#2d1f00;color:#f59e0b;border:1px solid #92400e;margin-left:8px;">${escapeHtml(fChain.toUpperCase())}</span>`
          : "";
        return `
          <div style="margin-bottom:16px;border:1px solid ${c.border};border-radius:10px;overflow:hidden;">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid ${c.border}40;background:${c.bg}30;">
              <div style="display:flex;align-items:center;gap:12px;">
                <span style="font-size:11px;color:#555;font-family:monospace;">${String(i + 1).padStart(2, "0")}</span>
                <span style="font-size:14px;font-weight:600;color:#e5e5e5;">${escapeHtml(f.title)}${chainTag}</span>
              </div>
              <span style="font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:20px;background:${c.bg};color:${c.text};border:1px solid ${c.border};">${sev}</span>
            </div>
            <div style="padding:14px 18px;background:#0d0d0d;">
              <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#555;margin:0 0 6px 0;">Description</p>
              <p style="font-size:13px;color:#aaa;line-height:1.7;margin:0 0 14px 0;">${escapeHtml(f.description)}</p>
              <div style="background:#0a1f0f;border:1px solid #1a4d2a;border-radius:8px;padding:12px 16px;">
                <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#2d7a45;margin:0 0 6px 0;">Recommended Fix</p>
                <p style="font-size:13px;color:#aaa;line-height:1.7;margin:0;">${escapeHtml(f.fix)}</p>
              </div>
            </div>
          </div>`;
      })
    ).join("");

    const severityBreakdown = SEVERITY_ORDER.map((sev) => {
      const c = SEVERITY_COLORS[sev];
      return `<div style="flex:1;text-align:center;padding:14px 8px;background:#111;border:1px solid #222;border-radius:10px;">
        <div style="font-size:24px;font-weight:700;font-family:monospace;color:${counts[sev] === 0 ? "#333" : c.text};">${counts[sev]}</div>
        <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;margin-top:4px;color:${counts[sev] === 0 ? "#333" : c.text};">${sev}</div>
      </div>`;
    }).join("");

    const chainInfoHtml = chain
      ? `<div style="margin-bottom:24px;padding:12px 18px;background:#111;border:1px solid #333;border-radius:10px;display:flex;align-items:center;gap:10px;">
          <span style="font-size:10px;font-weight:700;letter-spacing:1.5px;padding:3px 10px;border-radius:20px;background:#1a1a1a;color:#aaa;border:1px solid #333;">${escapeHtml(chainInfo.label.toUpperCase())}${isAnchor ? " · ANCHOR" : ""}</span>
          <span style="font-size:12px;color:#666;">${isSolana ? "Scanned via cargo-audit + pattern analysis" : chain === "ethereum" ? "EVM / Solidity contract" : "L2/EVM chain detected"}</span>
        </div>`
      : "";

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
      <title>Audit Report — ${escapeHtml(fileName)}</title>
      <style>*{box-sizing:border-box;margin:0;padding:0;}body{background:#0a0a0a;color:#e5e5e5;font-family:'Courier New',monospace;padding:48px;}@media print{body{padding:32px;}}</style>
    </head><body>
      <div style="display:flex;align-items:flex-start;justify-content:space-between;padding-bottom:24px;border-bottom:1px solid #1a1a1a;margin-bottom:36px;">
        <div>
          <div style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#555;margin-bottom:6px;">Security Audit Report</div>
          <div style="font-size:22px;font-weight:700;color:#fff;">${escapeHtml(fileName)}</div>
          <div style="font-size:12px;color:#444;margin-top:4px;">${date} · ChainAudit</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:52px;font-weight:700;font-family:monospace;color:${riskColor};line-height:1;">${result.risk_score}</div>
          <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:${riskColor};margin-top:4px;">${riskLabel}</div>
        </div>
      </div>
      ${chainInfoHtml}
      <div style="margin-bottom:36px;">
        <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:12px;">Severity Breakdown</div>
        <div style="display:flex;gap:10px;">${severityBreakdown}</div>
      </div>
      <div style="background:#111;border:1px solid #1a1a1a;border-radius:10px;padding:18px 22px;margin-bottom:36px;">
        <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:8px;">Summary</div>
        <p style="font-size:14px;color:#aaa;line-height:1.7;">Found <strong style="color:#fff;">${result.findings.length} issue${result.findings.length !== 1 ? "s" : ""}</strong> across <strong style="color:#fff;">${Object.values(counts).filter(Boolean).length}</strong> severity levels. ${counts.CRITICAL > 0 ? "Immediate remediation required before deployment." : counts.HIGH > 0 ? "High severity issues should be resolved before mainnet." : "No critical issues found."}</p>
      </div>
      <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:16px;">Findings</div>
      ${findingsHtml}
      <div style="margin-top:48px;padding-top:24px;border-top:1px solid #1a1a1a;display:flex;justify-content:space-between;">
        <span style="font-size:11px;color:#333;">Generated by ChainAudit</span>
        <span style="font-size:11px;color:#333;">${date}</span>
      </div>
      <script>window.onload=()=>window.print();</script>
    </body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url  = URL.createObjectURL(blob);
    const win  = window.open(url, "_blank");
    if (win) win.onafterprint = () => URL.revokeObjectURL(url);
  }, [result, fileName, date, grouped, counts, chain, chainInfo, isAnchor, isSolana]);
  return (
    <div className="relative z-10 min-h-screen pt-24 pb-24 px-6">
      <div className="max-w-3xl mx-auto">

        {/* Meta bar */}
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between gap-4 mb-7 flex-wrap"
        >
          <div className="flex items-center gap-2 flex-wrap">
            <FileCode className="w-3.5 h-3.5 text-ink-faint" />
            {/* Scanned filename is data. */}
            <span className="data-strong text-xs font-semibold truncate max-w-[220px]">
              {fileName}
            </span>
            {chain && (
              <span
                className="sev-outline px-2 py-[3px] text-[9px]"
                style={{ borderColor: `${chainInfo.color}77`, color: chainInfo.color }}
              >
                {chainInfo.label}
              </span>
            )}
            {isAnchor && (
              <span
                className="sev-outline px-2 py-[3px] text-[9px]"
                style={{ borderColor: "var(--sev-high)", color: "var(--sev-high)" }}
              >
                Anchor
              </span>
            )}
            <span className="text-[11px] text-ink-faint">{date}</span>
          </div>

          <button
            onClick={onRescan}
            className="neu-btn flex items-center gap-2 px-3.5 py-2 text-[10px] tracking-[0.16em] uppercase text-ink-muted"
          >
            <RotateCcw className="w-3 h-3" />
            New Scan
          </button>
        </motion.div>

        {/* Hero: score dial + summary */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="neu-panel-lg p-8 mb-6 flex flex-col md:flex-row items-center gap-8"
        >
          <RiskScore score={result.risk_score} />

          <div className="flex-1 space-y-5 w-full">
            <div>
              <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted mb-2 font-bold">
                Scan Summary
              </p>
              <p className="text-ink-secondary text-[13px] leading-relaxed">
                Found{" "}
                <span className="data-strong font-bold">
                  {result.findings.length} issue{result.findings.length !== 1 ? "s" : ""}
                </span>{" "}
                across{" "}
                <span className="data-strong font-bold">
                  {Object.values(counts).filter(Boolean).length}
                </span>{" "}
                severity level{Object.values(counts).filter(Boolean).length !== 1 ? "s" : ""}.{" "}
                {counts.CRITICAL > 0
                  ? "Immediate remediation required before deployment."
                  : counts.HIGH > 0
                  ? "High severity issues should be resolved before mainnet."
                  : "No critical issues found. Review remaining findings."}
              </p>
            </div>

            {isSolana && (result as any).scanners_used && (
              <div className="flex items-center gap-2 flex-wrap">
                {[
                  ["cargo-audit", (result as any).scanners_used.cargo_audit],
                  ["pattern scan", (result as any).scanners_used.pattern_scan],
                  ["cargo-geiger", (result as any).scanners_used.cargo_geiger],
                ]
                  .filter(([, on]) => on)
                  .map(([name]) => (
                    <span
                      key={String(name)}
                      className="neu-chip px-2.5 py-1 text-[9px] uppercase tracking-[0.14em] text-ink-muted"
                    >
                      {name}
                    </span>
                  ))}
              </div>
            )}

            {/* Severity tally. Counts are flat, coloured, tabular. */}
            <div className="grid grid-cols-4 gap-2.5">
              {SEVERITY_ORDER.map((sev) => {
                const color = SEVERITY_TONE[sev];
                const zero = counts[sev] === 0;
                return (
                  <div
                    key={sev}
                    className="neu-well flex flex-col items-center gap-2 px-2 py-3"
                  >
                    <span
                      className="data-strong text-2xl font-bold leading-none"
                      style={{ color: zero ? "var(--text-faint)" : color }}
                    >
                      {counts[sev]}
                    </span>
                    <span
                      className="text-[9px] font-bold uppercase tracking-[0.12em]"
                      style={{ color: zero ? "var(--text-faint)" : color }}
                    >
                      {sev}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </motion.div>

        {/* Findings grouped by severity */}
        <div className="space-y-8">
          {SEVERITY_ORDER.map((sev, si) => {
            const findings = grouped[sev];
            if (!findings.length) return null;
            return (
              <motion.section
                key={sev}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 + si * 0.05 }}
              >
                <div className="flex items-center gap-3 mb-3.5">
                  <SeverityBadge severity={sev} />
                  <div
                    className="flex-1 h-px"
                    style={{ background: "var(--neu-dark)" }}
                  />
                  <span className="data-strong text-[11px] text-ink-muted">
                    {findings.length} finding{findings.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="space-y-3">
                  {findings.map((finding, i) => (
                    <FindingCard key={`${sev}-${i}`} finding={finding} index={i} />
                  ))}
                </div>
              </motion.section>
            );
          })}
        </div>

        {result.findings.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="neu-panel-lg p-12 text-center"
          >
            <div
              className="neu-chip w-14 h-14 mx-auto mb-5 flex items-center justify-center"
              style={{ color: "var(--sev-safe)" }}
            >
              <Shield className="w-6 h-6" />
            </div>
            <p className="data-strong text-sm font-semibold">No vulnerabilities detected.</p>
            <p className="text-ink-muted text-xs mt-1.5">
              Contract passed all security checks.
            </p>
          </motion.div>
        )}

        {/* Export */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-12 neu-panel p-6 flex flex-col sm:flex-row items-center justify-between gap-4"
        >
          <div>
            <p className="data-strong text-sm font-semibold">Want the full audit report?</p>
            <p className="text-xs text-ink-muted mt-1">
              Export as PDF with all findings and fixes
            </p>
          </div>
          <button
            onClick={handleExport}
            className="neu-btn flex items-center gap-2 px-5 py-3 text-[11px] font-bold tracking-[0.14em] uppercase"
            style={{ color: "var(--accent)" }}
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </motion.div>

      </div>
    </div>
  );
}
