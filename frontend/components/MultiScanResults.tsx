"use client";

import { useState, useCallback } from "react";
import { FileCode, RotateCcw, Download, ChevronDown } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import { escapeHtml } from "@/lib/escape-html";
import {
  riskColorClass,
  riskColorHex,
  riskLabelLong,
  riskLabelShort,
  severityExportPalette,
} from "@/lib/severity";
import { chainBadgeStyle, chainDisplay, chainExportTint } from "@/lib/chains";
import type { Severity } from "@/types";

interface Finding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  fix: string;
  check: string;
  impact: string;
  confidence: string;
  occurrences: number;
  chain?: string;
}

interface FileResult {
  file: string;
  status: "success" | "error" | "skipped" | "timeout";
  reason?: string;
  risk_score: number;
  total_findings: number;
  findings: Finding[];
  chain?: string;
  is_anchor?: boolean;
}

interface MultiScanResult {
  scan_id: string;
  type: "multi";
  total_files: number;
  scanned: number;
  overall_risk_score: number;
  total_findings: number;
  has_solana?: boolean;
  has_evm?: boolean;
  files: FileResult[];
}

interface MultiScanResultsProps {
  result: MultiScanResult;
  fileName: string;
  onRescan: () => void;
}



// ─── Chain display config ─────────────────────────────────────────────────────


// Inline badge for file rows
function ChainBadge({ chain, isAnchor }: { chain: string; isAnchor?: boolean }) {
  const { label } = chainDisplay(chain);
  return (
    <span
      className="shrink-0 rounded-full border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wider"
      style={chainBadgeStyle(chain)}
    >
      {label}{chain === "solana" && isAnchor ? " · ANCHOR" : ""}
    </span>
  );
}

// Inline badge for individual findings
function FindingChainBadge({ chain }: { chain: string }) {
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

// Export HTML chain tag (inline styles for PDF)
function exportChainTag(chain: string, isAnchor?: boolean): string {
  const s = chainExportTint(chain);
  // The label can fall back to a raw value off the API response, so it stays escaped.
  const label = escapeHtml(chainDisplay(chain).label.toUpperCase());
  const suffix = chain === "solana" && isAnchor ? " · ANCHOR" : "";
  return `<span style="font-size:9px;padding:2px 8px;border-radius:20px;background:${s.bg};color:${s.color};border:1px solid ${s.border};margin-left:8px;">${label}${suffix}</span>`;
}

function exportFindingChainTag(chain: string): string {
  const s = chainExportTint(chain);
  const label = escapeHtml(chainDisplay(chain).label.toUpperCase());
  return `<span style="font-size:8px;padding:1px 6px;border-radius:20px;background:${s.bg};color:${s.color};border:1px solid ${s.border};margin-left:6px;">${label}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────

function FileCard({ file, index }: { file: FileResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const risk = { text: riskColorClass(file.risk_score), label: riskLabelShort(file.risk_score) };
  const fileChain = file.chain ?? "ethereum";
  const isSolana = fileChain === "solana";
  const isAnchor = file.is_anchor === true;

  return (
    <div className={`rounded-lg border overflow-hidden transition-all duration-200
      ${isSolana
        ? "border-warning/25 bg-warning/[0.03] hover:border-warning/40"
        : "border-border bg-card hover:border-border-strong"
      }`}>
      <button
        onClick={() => file.status === "success" && setExpanded(!expanded)}
        aria-expanded={file.findings.length > 0 ? expanded : undefined}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-elevated border border-border flex items-center justify-center text-xs font-semibold text-muted-foreground font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex items-center gap-2 flex-1 min-w-0">
          <FileCode className={`w-3.5 h-3.5 flex-shrink-0 ${isSolana ? "text-warning" : "text-muted-foreground"}`} />
          <span className="text-sm text-foreground truncate">{file.file}</span>
          <ChainBadge chain={fileChain} isAnchor={isAnchor} />
        </div>

        {file.status === "success" ? (
          <div className="flex items-center gap-3 flex-shrink-0">
            <span className={`text-sm font-bold font-mono ${risk.text}`}>
              {file.risk_score}
            </span>
            <span className={`text-xs uppercase tracking-widest ${risk.text} opacity-70`}>
              {risk.label}
            </span>
            <span className="text-xs text-subtle">
              {file.total_findings} finding{file.total_findings !== 1 ? "s" : ""}
            </span>
            {file.findings.length > 0 && (
              <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-300 ${expanded ? "rotate-180" : ""}`} />
            )}
          </div>
        ) : (
          <span className="text-xs text-subtle uppercase tracking-widest">
            {file.status}
          </span>
        )}
      </button>

      {expanded && file.findings.length > 0 && (
        <div className="border-t border-border px-5 py-4 space-y-3">
          {file.findings.map((finding, i) => {
            const findingChain = finding.chain ?? fileChain;
            return (
              <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-card border border-border">
                <span className="text-xs font-mono text-subtle mt-0.5">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-sm text-foreground">{finding.title}</span>
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <FindingChainBadge chain={findingChain} />
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{finding.description}</p>
                  <div className="mt-2 rounded-lg bg-primary/[0.04] border border-primary/[0.10] p-2.5">
                    <p className="text-xs text-primary/60 uppercase tracking-widest mb-1">Fix</p>
                    <p className="text-xs text-muted-foreground">{finding.fix}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function MultiScanResults({ result, fileName, onRescan }: MultiScanResultsProps) {
  const overallRisk = { text: riskColorClass(result.overall_risk_score), label: riskLabelShort(result.overall_risk_score) };
  const hasSolana = result.has_solana === true;
  const hasEVM = result.has_evm === true;

  const date = new Date().toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });

  const handleExport = useCallback(() => {
    const fileSectionsHtml = result.files.map((file) => {
      const fileChain = file.chain ?? "ethereum";

      if (file.status !== "success" || file.findings.length === 0) {
        return `
          <div style="margin-bottom:24px;border:1px solid #1a1a1a;border-radius:10px;overflow:hidden;">
            <div style="padding:14px 18px;background:#111;display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:13px;font-weight:600;color:#e5e5e5;">${escapeHtml(file.file)}</span>
              <span style="font-size:11px;color:#444;text-transform:uppercase;letter-spacing:1px;">
                ${escapeHtml(file.status === "success" ? "0 findings" : (file.reason || file.status))}
              </span>
            </div>
          </div>`;
      }

      const riskColor = riskColorHex(file.risk_score);
      const chainTag = exportChainTag(fileChain, file.is_anchor);

      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const grouped: Record<string, Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
      file.findings.forEach(f => grouped[f.severity]?.push(f));

      const findingsHtml = order.flatMap(sev =>
        grouped[sev].map((f, i) => {
          const c = severityExportPalette((sev as Severity) ?? "LOW");
          const findingChain = f.chain ?? fileChain;
          const findingChainTag = exportFindingChainTag(findingChain);
          return `
            <div style="margin-bottom:12px;border:1px solid ${c.border};border-radius:8px;overflow:hidden;">
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:${c.bg}30;border-bottom:1px solid ${c.border}40;">
                <div style="display:flex;align-items:center;gap:10px;">
                  <span style="font-size:10px;color:#555;font-family:monospace;">${String(i + 1).padStart(2, "0")}</span>
                  <span style="font-size:13px;font-weight:600;color:#e5e5e5;">${escapeHtml(f.title)}${findingChainTag}</span>
                </div>
                <span style="font-size:9px;font-weight:700;letter-spacing:1px;padding:2px 8px;border-radius:20px;background:${c.bg};color:${c.text};border:1px solid ${c.border};">${sev}</span>
              </div>
              <div style="padding:12px 14px;background:#0d0d0d;">
                <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#555;margin:0 0 5px 0;">Description</p>
                <p style="font-size:12px;color:#aaa;line-height:1.6;margin:0 0 12px 0;">${escapeHtml(f.description)}</p>
                <div style="background:#0a1f0f;border:1px solid #1a4d2a;border-radius:6px;padding:10px 12px;">
                  <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#2d7a45;margin:0 0 5px 0;">Recommended Fix</p>
                  <p style="font-size:12px;color:#aaa;line-height:1.6;margin:0;">${escapeHtml(f.fix)}</p>
                </div>
              </div>
            </div>`;
        })
      ).join("");

      return `
        <div style="margin-bottom:28px;border:1px solid #222;border-radius:10px;overflow:hidden;">
          <div style="padding:14px 18px;background:#111;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1a1a1a;">
            <span style="font-size:14px;font-weight:600;color:#e5e5e5;">${escapeHtml(file.file)}${chainTag}</span>
            <div>
              <span style="font-size:22px;font-weight:700;font-family:monospace;color:${riskColor};">${file.risk_score}</span>
              <span style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:${riskColor};margin-left:8px;">${riskLabelLong(file.risk_score)}</span>
              <span style="font-size:11px;color:#444;margin-left:12px;">${file.total_findings} finding${file.total_findings !== 1 ? "s" : ""}</span>
            </div>
          </div>
          <div style="padding:14px 18px;background:#0a0a0a;">
            ${findingsHtml}
          </div>
        </div>`;
    }).join("");

    const fileRowsHtml = result.files.map(f => {
      const rc = riskColorHex(f.risk_score);
      const rowChain = f.chain ?? "ethereum";
      const chainBadge = exportChainTag(rowChain, f.is_anchor).replace('margin-left:8px', 'margin-left:6px');
      return `
        <tr>
          <td style="padding:8px 12px;font-size:12px;color:#ccc;border-bottom:1px solid #1a1a1a;">${escapeHtml(f.file)}${chainBadge}</td>
          <td style="padding:8px 12px;font-size:12px;font-family:monospace;color:${rc};border-bottom:1px solid #1a1a1a;text-align:center;">${f.risk_score}</td>
          <td style="padding:8px 12px;font-size:12px;color:#666;border-bottom:1px solid #1a1a1a;text-align:center;">${escapeHtml(f.status === "success" ? f.total_findings : f.status)}</td>
        </tr>`;
    }).join("");

    const overallColor = riskColorHex(result.overall_risk_score);

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
      <title>Multi-Contract Audit — ${escapeHtml(fileName)}</title>
      <style>*{box-sizing:border-box;margin:0;padding:0;}body{background:#0a0a0a;color:#e5e5e5;font-family:'Courier New',monospace;padding:48px;}@media print{body{padding:32px;}}</style>
    </head><body>
      <div style="display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:1px solid #1a1a1a;margin-bottom:32px;">
        <div>
          <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#555;margin-bottom:6px;">Multi-Contract Security Audit</div>
          <div style="font-size:22px;font-weight:700;color:#fff;">${escapeHtml(fileName)}</div>
          <div style="font-size:11px;color:#444;margin-top:4px;">${date} · ChainAudit · ${result.total_files} file${result.total_files !== 1 ? "s" : ""}</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:52px;font-weight:700;font-family:monospace;color:${overallColor};line-height:1;">${result.overall_risk_score}</div>
          <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:${overallColor};margin-top:4px;">Overall ${riskLabelLong(result.overall_risk_score)}</div>
        </div>
      </div>
      <div style="display:flex;gap:12px;margin-bottom:32px;">
        ${[["Files", result.total_files], ["Scanned", result.scanned], ["Total Issues", result.total_findings]]
        .map(([label, val]) => `
          <div style="flex:1;text-align:center;padding:14px 8px;background:#111;border:1px solid #1a1a1a;border-radius:8px;">
            <div style="font-size:28px;font-weight:700;font-family:monospace;color:#e5e5e5;">${val}</div>
            <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:#555;margin-top:4px;">${label}</div>
          </div>`).join("")}
      </div>
      <div style="margin-bottom:32px;">
        <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:10px;">File Summary</div>
        <table style="width:100%;border-collapse:collapse;background:#111;border:1px solid #1a1a1a;border-radius:8px;overflow:hidden;">
          <thead>
            <tr style="background:#161616;">
              <th style="padding:10px 12px;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#555;text-align:left;border-bottom:1px solid #1a1a1a;">File</th>
              <th style="padding:10px 12px;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#555;text-align:center;border-bottom:1px solid #1a1a1a;">Risk Score</th>
              <th style="padding:10px 12px;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#555;text-align:center;border-bottom:1px solid #1a1a1a;">Findings</th>
            </tr>
          </thead>
          <tbody>${fileRowsHtml}</tbody>
        </table>
      </div>
      <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:16px;">Detailed Findings by File</div>
      ${fileSectionsHtml}
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
  }, [result, fileName, date]);

  return (
    <div className="min-h-screen pt-20 pb-20 px-6">
      <div className="max-w-3xl mx-auto">

        {/* Top meta bar */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-subtle">
            <FileCode className="w-3 h-3" />
            <span className="text-muted-foreground font-medium">{fileName}</span>
            {hasSolana && (
              <span className="px-1.5 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/25 font-semibold">
                SOLANA
              </span>
            )}
            {hasEVM && (
              <span className="px-1.5 py-0.5 rounded-full bg-[#818CF8]/10 text-[#818CF8] border border-[#818CF8]/25 font-semibold">
                EVM
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
        </div>

        {/* Summary card */}
        <div className="rounded-lg border border-border bg-card p-8 mb-6">
          <div className="flex flex-col md:flex-row items-center gap-8">
            <div className="flex flex-col items-center flex-shrink-0">
              <span className={`text-6xl font-bold font-mono ${overallRisk.text}`}>
                {result.overall_risk_score}
              </span>
              <div className="mt-3 px-4 py-1.5 rounded-full border text-sm font-semibold tracking-wide border-border">
                <span className={overallRisk.text}>{overallRisk.label} Risk</span>
              </div>
            </div>

            <div className="hidden md:block w-px self-stretch bg-elevated" />

            <div className="flex-1 space-y-4 w-full">
              <div>
                <p className="text-xs uppercase tracking-widest text-subtle mb-1.5">Multi-Contract Scan</p>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Scanned <span className="text-foreground font-semibold">{result.scanned}</span> of{" "}
                  <span className="text-foreground font-semibold">{result.total_files}</span> files.{" "}
                  Found <span className="text-foreground font-semibold">{result.total_findings} total issue{result.total_findings !== 1 ? "s" : ""}</span> across all contracts.
                  {hasSolana && hasEVM && (
                    <span className="text-warning"> Mixed EVM + Solana scan.</span>
                  )}
                  {hasSolana && !hasEVM && (
                    <span className="text-warning"> Solana programs scanned via cargo-audit + pattern analysis.</span>
                  )}
                </p>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-md bg-card border border-border">
                  <span className="text-xl font-bold font-mono text-foreground">{result.total_files}</span>
                  <span className="text-xs text-muted-foreground uppercase tracking-widest">Files</span>
                </div>
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-md bg-card border border-border">
                  <span className="text-xl font-bold font-mono text-foreground">{result.scanned}</span>
                  <span className="text-xs text-muted-foreground uppercase tracking-widest">Scanned</span>
                </div>
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-md bg-card border border-border">
                  <span className="text-xl font-bold font-mono text-foreground">{result.total_findings}</span>
                  <span className="text-xs text-muted-foreground uppercase tracking-widest">Issues</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Per-file results */}
        <div className="space-y-3">
          <p className="text-xs uppercase tracking-widest text-subtle mb-4">Files</p>
          {result.files.map((file, i) => (
            <FileCard key={i} file={file} index={i} />
          ))}
        </div>

        {/* Footer export */}
        <div className="mt-12 rounded-lg border border-border bg-card p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-foreground">Want the full audit report?</p>
            <p className="text-xs text-muted-foreground mt-1">Export as PDF with all findings grouped by severity</p>
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-5 py-2.5 rounded-md bg-elevated border border-border text-sm text-foreground hover:bg-elevated hover:text-foreground transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>

      </div>
    </div>
  );
}