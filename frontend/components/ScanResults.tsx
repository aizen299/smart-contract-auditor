"use client";

import { useMemo, useCallback } from "react";
import { FileCode, RotateCcw, Download, Shield } from "lucide-react";
import { motion } from "framer-motion";
import { RiskScore } from "./RiskScore";
import { FindingCard } from "./FindingCard";
import { SeverityBadge } from "./SeverityBadge";
import type { ScanResult, Severity } from "@/types";
import { escapeHtml } from "@/lib/escape-html";
import {
  SEVERITY_ORDER,
  riskColorHex,
  riskLabelLong,
  severityClasses,
  severityExportPalette,
} from "@/lib/severity";
import { chainBadgeStyle, chainDisplay } from "@/lib/chains";


interface ScanResultsProps {
  result: ScanResult;
  fileName: string;
  onRescan: () => void;
}

export function ScanResults({ result, fileName, onRescan }: ScanResultsProps) {
  const chain     = ((result as any).chain as string | undefined) ?? "ethereum";
  const isAnchor  = (result as any).is_anchor === true;
  const chainInfo = chainDisplay(chain);
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
    const riskColor = riskColorHex(result.risk_score);
    const riskLabel = riskLabelLong(result.risk_score);

    const findingsHtml = SEVERITY_ORDER.flatMap((sev) =>
      grouped[sev].map((f, i) => {
        const c = severityExportPalette(sev);
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
      const c = severityExportPalette(sev);
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
    <div className="min-h-screen pt-20 pb-20 px-6">
      <div className="max-w-3xl mx-auto">

        {/* Top meta bar */}
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8"
        >
          <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-subtle flex-wrap">
            <FileCode className="w-3 h-3" />
            <span className="text-muted-foreground font-medium truncate max-w-[200px]">{fileName}</span>

            {/* Chain badge — always shown for every chain including EVM/Ethereum */}
            {chain && (
              <span
                className="rounded-full border px-1.5 py-0.5 text-xs font-semibold"
                style={chainBadgeStyle(chain)}
              >
                {chainInfo.label}
              </span>
            )}
            {isAnchor && (
              <span className="px-1.5 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/25 font-semibold text-xs">
                ANCHOR
              </span>
            )}

            <span>·</span>
            <span>{date}</span>
          </div>

          <button
            onClick={onRescan}
            className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-muted-foreground hover:text-foreground transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            New Scan
          </button>
        </motion.div>

        {/* Hero score section */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-lg border border-border bg-card p-8 mb-6 flex flex-col md:flex-row items-center gap-8"
        >
          <RiskScore score={result.risk_score} />
          <div className="hidden md:block w-px self-stretch bg-elevated" />
          <div className="flex-1 space-y-4 w-full">
            <div>
              <p className="text-xs uppercase tracking-widest text-subtle mb-1.5">Scan Summary</p>
              <p className="text-muted-foreground text-sm leading-relaxed">
                Found{" "}
                <span className="text-foreground font-semibold">
                  {result.findings.length} issue{result.findings.length !== 1 ? "s" : ""}
                </span>{" "}
                across{" "}
                <span className="text-foreground font-semibold">
                  {Object.values(counts).filter(Boolean).length}
                </span>{" "}
                severity levels.{" "}
                {isSolana && (
                  <span className="text-warning">
                    Solana program — scanned via cargo-audit + pattern analysis.{" "}
                  </span>
                )}
                {counts.CRITICAL > 0
                  ? "Immediate remediation required before deployment."
                  : counts.HIGH > 0
                  ? "High severity issues should be resolved before mainnet."
                  : "No critical issues found. Review remaining findings."}
              </p>
            </div>

            {/* Solana scanner pills */}
            {isSolana && (result as any).scanners_used && (
              <div className="flex items-center gap-2 flex-wrap">
                {(result as any).scanners_used.cargo_audit && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/25 uppercase tracking-wider">
                    cargo-audit
                  </span>
                )}
                {(result as any).scanners_used.pattern_scan && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/25 uppercase tracking-wider">
                    pattern scan
                  </span>
                )}
                {(result as any).scanners_used.cargo_geiger && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/25 uppercase tracking-wider">
                    cargo-geiger
                  </span>
                )}
              </div>
            )}

            {/* Severity breakdown grid */}
            <div className="grid grid-cols-4 gap-2">
              {SEVERITY_ORDER.map((sev) => (
                <div
                  key={sev}
                  className="flex flex-col items-center gap-1.5 p-2.5 rounded-md bg-card border border-border"
                >
                  <span className={`text-xl font-bold font-mono ${severityClasses(sev).text} ${counts[sev] === 0 ? "opacity-20" : ""}`}>
                    {counts[sev]}
                  </span>
                  <SeverityBadge severity={sev} size="sm" />
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Findings by severity */}
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
                <div className="flex items-center gap-3 mb-3">
                  <SeverityBadge severity={sev} />
                  <div className="flex-1 h-px bg-elevated" />
                  <span className="text-xs text-subtle tabular-nums">
                    {findings.length} finding{findings.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="space-y-2">
                  {findings.map((finding, i) => (
                    <FindingCard key={`${sev}-${i}`} finding={finding} index={i} />
                  ))}
                </div>
              </motion.section>
            );
          })}
        </div>

        {/* No findings state */}
        {result.findings.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="rounded-lg border border-border bg-card p-12 text-center"
          >
            <Shield className="w-10 h-10 text-primary/40 mx-auto mb-4" />
            <p className="text-muted-foreground text-sm">No vulnerabilities detected.</p>
            <p className="text-muted-foreground text-xs mt-1">Contract passed all security checks.</p>
          </motion.div>
        )}

        {/* Export footer */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-12 rounded-lg border border-border bg-card p-6 flex flex-col sm:flex-row items-center justify-between gap-4"
        >
          <div>
            <p className="text-sm font-medium text-foreground">Want the full audit report?</p>
            <p className="text-xs text-muted-foreground mt-1">Export as PDF with all findings and fixes</p>
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-5 py-2.5 rounded-md bg-elevated border border-border text-sm text-foreground hover:bg-elevated hover:text-foreground transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </motion.div>

      </div>
    </div>
  );
}
