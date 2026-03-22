"use client";

import { useMemo, useCallback } from "react";
import { FileCode, RotateCcw, Download } from "lucide-react";
import { RiskScore } from "./RiskScore";
import { FindingCard } from "./FindingCard";
import { SeverityBadge, SEVERITY_CONFIG } from "./SeverityBadge";
import type { ScanResult, Severity } from "@/types";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "#2d0a0a", text: "#f87171", border: "#7f1d1d" },
  HIGH:     { bg: "#2d1500", text: "#fb923c", border: "#7c2d12" },
  MEDIUM:   { bg: "#2d2500", text: "#facc15", border: "#713f12" },
  LOW:      { bg: "#0a1a2d", text: "#60a5fa", border: "#1e3a5f" },
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
  const isSolana = (result as any).chain === "solana";
  const isAnchor = (result as any).is_anchor === true;

  const grouped = useMemo(() => {
    const groups: Record<Severity, typeof result.findings> = {
      CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
    };
    result.findings.forEach((f) => groups[f.severity].push(f));
    return groups;
  }, [result]);

  const counts = useMemo(() => ({
    CRITICAL: grouped.CRITICAL.length,
    HIGH: grouped.HIGH.length,
    MEDIUM: grouped.MEDIUM.length,
    LOW: grouped.LOW.length,
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
        const chainTag = (f as any).chain
          ? `<span style="font-size:9px;padding:2px 6px;border-radius:20px;background:#2d1f00;color:#f59e0b;border:1px solid #92400e;margin-left:8px;">${(f as any).chain.toUpperCase()}</span>`
          : "";
        return `
          <div style="margin-bottom:16px;border:1px solid ${c.border};border-radius:10px;overflow:hidden;">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid ${c.border}40;background:${c.bg}30;">
              <div style="display:flex;align-items:center;gap:12px;">
                <span style="font-size:11px;color:#555;font-family:monospace;">${String(i + 1).padStart(2, "0")}</span>
                <span style="font-size:14px;font-weight:600;color:#e5e5e5;">${f.title}${chainTag}</span>
              </div>
              <span style="font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:20px;background:${c.bg};color:${c.text};border:1px solid ${c.border};">${sev}</span>
            </div>
            <div style="padding:14px 18px;background:#0d0d0d;">
              <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#555;margin:0 0 6px 0;">Description</p>
              <p style="font-size:13px;color:#aaa;line-height:1.7;margin:0 0 14px 0;">${f.description}</p>
              <div style="background:#0a1f0f;border:1px solid #1a4d2a;border-radius:8px;padding:12px 16px;">
                <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#2d7a45;margin:0 0 6px 0;">Recommended Fix</p>
                <p style="font-size:13px;color:#aaa;line-height:1.7;margin:0;">${f.fix}</p>
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

    const chainInfo = isSolana
      ? `<div style="margin-bottom:24px;padding:12px 18px;background:#1a1000;border:1px solid #92400e;border-radius:10px;display:flex;align-items:center;gap:10px;">
          <span style="font-size:10px;font-weight:700;letter-spacing:1.5px;padding:3px 10px;border-radius:20px;background:#2d1f00;color:#f59e0b;border:1px solid #92400e;">SOLANA${isAnchor ? " · ANCHOR" : ""}</span>
          <span style="font-size:12px;color:#aaa;">Scanned via cargo-audit + pattern analysis</span>
        </div>`
      : "";

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
      <title>Audit Report — ${fileName}</title>
      <style>*{box-sizing:border-box;margin:0;padding:0;}body{background:#0a0a0a;color:#e5e5e5;font-family:'Courier New',monospace;padding:48px;}@media print{body{padding:32px;}}</style>
    </head><body>
      <div style="display:flex;align-items:flex-start;justify-content:space-between;padding-bottom:24px;border-bottom:1px solid #1a1a1a;margin-bottom:36px;">
        <div>
          <div style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#555;margin-bottom:6px;">Security Audit Report</div>
          <div style="font-size:22px;font-weight:700;color:#fff;">${fileName}</div>
          <div style="font-size:12px;color:#444;margin-top:4px;">${date} · ChainAudit</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:52px;font-weight:700;font-family:monospace;color:${riskColor};line-height:1;">${result.risk_score}</div>
          <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:${riskColor};margin-top:4px;">${riskLabel}</div>
        </div>
      </div>
      ${chainInfo}
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
    const url = URL.createObjectURL(blob);
    const win = window.open(url, "_blank");
    if (win) win.onafterprint = () => URL.revokeObjectURL(url);
  }, [result, fileName, date, grouped, counts]);

  return (
    <div className="min-h-screen pt-20 pb-20 px-6">
      <div className="max-w-3xl mx-auto">

        {/* Top meta bar */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-white/25">
            <FileCode className="w-3 h-3" />
            <span className="text-white/40 font-medium">{fileName}</span>
            {isSolana && (
              <span className="px-1.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                SOLANA
              </span>
            )}
            {isAnchor && (
              <span className="px-1.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                ANCHOR
              </span>
            )}
            <span>·</span>
            <span>{date}</span>
          </div>
          <button
            onClick={onRescan}
            className="flex items-center gap-1.5 text-[11px] uppercase tracking-widest text-white/30 hover:text-white/60 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            New Scan
          </button>
        </div>

        {/* Hero score section */}
        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-8 mb-6 flex flex-col md:flex-row items-center gap-8">
          <RiskScore score={result.risk_score} />
          <div className="hidden md:block w-px self-stretch bg-white/[0.06]" />
          <div className="flex-1 space-y-4 w-full">
            <div>
              <p className="text-[11px] uppercase tracking-widest text-white/25 mb-1.5">Scan Summary</p>
              <p className="text-white/60 text-sm leading-relaxed">
                Found <span className="text-white font-semibold">{result.findings.length} issue{result.findings.length !== 1 ? "s" : ""}</span> across{" "}
                <span className="text-white font-semibold">{Object.values(counts).filter(Boolean).length}</span> severity levels.{" "}
                {isSolana && (
                  <span className="text-amber-400/70">Solana program — scanned via cargo-audit + pattern analysis. </span>
                )}
                {counts.CRITICAL > 0
                  ? "Immediate remediation required before deployment."
                  : counts.HIGH > 0
                  ? "High severity issues should be resolved before mainnet."
                  : "No critical issues found. Review remaining findings."}
              </p>
            </div>

            {/* Solana scanner info */}
            {isSolana && (result as any).scanners_used && (
              <div className="flex items-center gap-2 flex-wrap">
                {(result as any).scanners_used.cargo_audit && (
                  <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400/70 border border-amber-500/15 uppercase tracking-wider">
                    cargo-audit
                  </span>
                )}
                {(result as any).scanners_used.pattern_scan && (
                  <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400/70 border border-amber-500/15 uppercase tracking-wider">
                    pattern scan
                  </span>
                )}
                {(result as any).scanners_used.cargo_geiger && (
                  <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400/70 border border-amber-500/15 uppercase tracking-wider">
                    cargo-geiger
                  </span>
                )}
              </div>
            )}

            <div className="grid grid-cols-4 gap-2">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev} className="flex flex-col items-center gap-1.5 p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                  <span className={`text-xl font-bold font-mono ${SEVERITY_CONFIG[sev].text} ${counts[sev] === 0 ? "opacity-20" : ""}`}>
                    {counts[sev]}
                  </span>
                  <SeverityBadge severity={sev} size="sm" />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Findings by severity */}
        <div className="space-y-8">
          {SEVERITY_ORDER.map((sev) => {
            const findings = grouped[sev];
            if (findings.length === 0) return null;
            return (
              <section key={sev}>
                <div className="flex items-center gap-3 mb-3">
                  <SeverityBadge severity={sev} />
                  <div className="flex-1 h-px bg-white/[0.06]" />
                  <span className="text-[11px] text-white/25 tabular-nums">
                    {findings.length} finding{findings.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="space-y-2">
                  {findings.map((finding, i) => (
                    <FindingCard key={`${sev}-${i}`} finding={finding} index={i} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>

        {/* Footer CTA */}
        <div className="mt-12 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-white/80">Want the full audit report?</p>
            <p className="text-xs text-white/30 mt-1">Export as PDF with remediation checklist</p>
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/[0.06] border border-white/[0.10] text-sm text-white/70 hover:bg-white/[0.09] hover:text-white/90 transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>
      </div>
    </div>
  );
}