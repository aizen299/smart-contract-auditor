"use client";

import { useState, useCallback } from "react";
import { FileCode, RotateCcw, Download, ChevronDown } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";

interface Finding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  fix: string;
  check: string;
  impact: string;
  confidence: string;
  occurrences: number;
}

interface FileResult {
  file: string;
  status: "success" | "error" | "skipped" | "timeout";
  reason?: string;
  risk_score: number;
  total_findings: number;
  findings: Finding[];
}

interface MultiScanResult {
  scan_id: string;
  type: "multi";
  total_files: number;
  scanned: number;
  overall_risk_score: number;
  total_findings: number;
  files: FileResult[];
}

interface MultiScanResultsProps {
  result: MultiScanResult;
  fileName: string;
  onRescan: () => void;
}

function getRiskColor(score: number) {
  if (score >= 80) return { text: "text-red-400", label: "Critical" };
  if (score >= 60) return { text: "text-orange-400", label: "High" };
  if (score >= 40) return { text: "text-yellow-400", label: "Medium" };
  if (score >= 20) return { text: "text-sky-400", label: "Low" };
  return { text: "text-emerald-400", label: "Minimal" };
}

function getRiskColorHex(score: number): string {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#38bdf8";
  return "#00ff88";
}

function getRiskLabelText(score: number): string {
  if (score >= 80) return "Critical Risk";
  if (score >= 60) return "High Risk";
  if (score >= 40) return "Medium Risk";
  if (score >= 20) return "Low Risk";
  return "Minimal Risk";
}

function FileCard({ file, index }: { file: FileResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const risk = getRiskColor(file.risk_score);

  return (
    <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] overflow-hidden">
      <button
        onClick={() => file.status === "success" && setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-white/[0.05] border border-white/[0.07] flex items-center justify-center text-[10px] font-semibold text-white/30 font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex items-center gap-2 flex-1 min-w-0">
          <FileCode className="w-3.5 h-3.5 text-white/30 flex-shrink-0" />
          <span className="text-sm text-white/80 truncate">{file.file}</span>
        </div>

        {file.status === "success" ? (
          <div className="flex items-center gap-3 flex-shrink-0">
            <span className={`text-sm font-bold font-mono ${risk.text}`}>
              {file.risk_score}
            </span>
            <span className={`text-[10px] uppercase tracking-widest ${risk.text} opacity-70`}>
              {risk.label}
            </span>
            <span className="text-[11px] text-white/25">
              {file.total_findings} finding{file.total_findings !== 1 ? "s" : ""}
            </span>
            {file.findings.length > 0 && (
              <ChevronDown className={`w-4 h-4 text-white/30 transition-transform duration-300 ${expanded ? "rotate-180" : ""}`} />
            )}
          </div>
        ) : (
          <span className="text-[11px] text-white/25 uppercase tracking-widest">
            {file.status}
          </span>
        )}
      </button>

      {expanded && file.findings.length > 0 && (
        <div className="border-t border-white/[0.05] px-5 py-4 space-y-3">
          {file.findings.map((finding, i) => (
            <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/[0.05]">
              <span className="text-[10px] font-mono text-white/25 mt-0.5">
                {String(i + 1).padStart(2, "0")}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm text-white/80">{finding.title}</span>
                  <SeverityBadge severity={finding.severity} size="sm" />
                </div>
                <p className="text-xs text-white/40 leading-relaxed">{finding.description}</p>
                <div className="mt-2 rounded-lg bg-[#00ff88]/[0.04] border border-[#00ff88]/[0.10] p-2.5">
                  <p className="text-[10px] text-[#00ff88]/60 uppercase tracking-widest mb-1">Fix</p>
                  <p className="text-xs text-white/50">{finding.fix}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function MultiScanResults({ result, fileName, onRescan }: MultiScanResultsProps) {
  const overallRisk = getRiskColor(result.overall_risk_score);

  const date = new Date().toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });

  const handleExport = useCallback(() => {
    const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
      CRITICAL: { bg: "#2d0a0a", text: "#f87171", border: "#7f1d1d" },
      HIGH:     { bg: "#2d1500", text: "#fb923c", border: "#7c2d12" },
      MEDIUM:   { bg: "#2d2500", text: "#facc15", border: "#713f12" },
      LOW:      { bg: "#0a1a2d", text: "#60a5fa", border: "#1e3a5f" },
    };

    // Per-file detailed sections
    const fileSectionsHtml = result.files.map((file) => {
      if (file.status !== "success" || file.findings.length === 0) {
        return `
          <div style="margin-bottom:24px;border:1px solid #1a1a1a;border-radius:10px;overflow:hidden;">
            <div style="padding:14px 18px;background:#111;display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:13px;font-weight:600;color:#e5e5e5;">${file.file}</span>
              <span style="font-size:11px;color:#444;text-transform:uppercase;letter-spacing:1px;">
                ${file.status === "success" ? "0 findings" : (file.reason || file.status)}
              </span>
            </div>
          </div>`;
      }

      const riskColor = getRiskColorHex(file.risk_score);

      // Group findings by severity for this file
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const grouped: Record<string, Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
      file.findings.forEach(f => grouped[f.severity]?.push(f));

      const findingsHtml = order.flatMap(sev =>
        grouped[sev].map((f, i) => {
          const c = SEVERITY_COLORS[sev] || SEVERITY_COLORS.LOW;
          return `
            <div style="margin-bottom:12px;border:1px solid ${c.border};border-radius:8px;overflow:hidden;">
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:${c.bg}30;border-bottom:1px solid ${c.border}40;">
                <div style="display:flex;align-items:center;gap:10px;">
                  <span style="font-size:10px;color:#555;font-family:monospace;">${String(i + 1).padStart(2, "0")}</span>
                  <span style="font-size:13px;font-weight:600;color:#e5e5e5;">${f.title}</span>
                </div>
                <span style="font-size:9px;font-weight:700;letter-spacing:1px;padding:2px 8px;border-radius:20px;background:${c.bg};color:${c.text};border:1px solid ${c.border};">${sev}</span>
              </div>
              <div style="padding:12px 14px;background:#0d0d0d;">
                <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#555;margin:0 0 5px 0;">Description</p>
                <p style="font-size:12px;color:#aaa;line-height:1.6;margin:0 0 12px 0;">${f.description}</p>
                <div style="background:#0a1f0f;border:1px solid #1a4d2a;border-radius:6px;padding:10px 12px;">
                  <p style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#2d7a45;margin:0 0 5px 0;">Recommended Fix</p>
                  <p style="font-size:12px;color:#aaa;line-height:1.6;margin:0;">${f.fix}</p>
                </div>
              </div>
            </div>`;
        })
      ).join("");

      return `
        <div style="margin-bottom:28px;border:1px solid #222;border-radius:10px;overflow:hidden;">
          <div style="padding:14px 18px;background:#111;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1a1a1a;">
            <span style="font-size:14px;font-weight:600;color:#e5e5e5;">${file.file}</span>
            <div>
              <span style="font-size:22px;font-weight:700;font-family:monospace;color:${riskColor};">${file.risk_score}</span>
              <span style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:${riskColor};margin-left:8px;">${getRiskLabelText(file.risk_score)}</span>
              <span style="font-size:11px;color:#444;margin-left:12px;">${file.total_findings} finding${file.total_findings !== 1 ? "s" : ""}</span>
            </div>
          </div>
          <div style="padding:14px 18px;background:#0a0a0a;">
            ${findingsHtml}
          </div>
        </div>`;
    }).join("");

    // File summary table rows
    const fileRowsHtml = result.files.map(f => {
      const rc = getRiskColorHex(f.risk_score);
      return `
        <tr>
          <td style="padding:8px 12px;font-size:12px;color:#ccc;border-bottom:1px solid #1a1a1a;">${f.file}</td>
          <td style="padding:8px 12px;font-size:12px;font-family:monospace;color:${rc};border-bottom:1px solid #1a1a1a;text-align:center;">${f.risk_score}</td>
          <td style="padding:8px 12px;font-size:12px;color:#666;border-bottom:1px solid #1a1a1a;text-align:center;">${f.status === "success" ? f.total_findings : f.status}</td>
        </tr>`;
    }).join("");

    const overallColor = getRiskColorHex(result.overall_risk_score);

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
      <title>Multi-Contract Audit — ${fileName}</title>
      <style>*{box-sizing:border-box;margin:0;padding:0;}body{background:#0a0a0a;color:#e5e5e5;font-family:'Courier New',monospace;padding:48px;}@media print{body{padding:32px;}}</style>
    </head><body>

      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:1px solid #1a1a1a;margin-bottom:32px;">
        <div>
          <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#555;margin-bottom:6px;">Multi-Contract Security Audit</div>
          <div style="font-size:22px;font-weight:700;color:#fff;">${fileName}</div>
          <div style="font-size:11px;color:#444;margin-top:4px;">${date} · AuditScan · ${result.total_files} file${result.total_files !== 1 ? "s" : ""}</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:52px;font-weight:700;font-family:monospace;color:${overallColor};line-height:1;">${result.overall_risk_score}</div>
          <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:${overallColor};margin-top:4px;">Overall ${getRiskLabelText(result.overall_risk_score)}</div>
        </div>
      </div>

      <!-- Summary stats -->
      <div style="display:flex;gap:12px;margin-bottom:32px;">
        ${[
          ["Files", result.total_files],
          ["Scanned", result.scanned],
          ["Total Issues", result.total_findings],
        ].map(([label, val]) => `
          <div style="flex:1;text-align:center;padding:14px 8px;background:#111;border:1px solid #1a1a1a;border-radius:8px;">
            <div style="font-size:28px;font-weight:700;font-family:monospace;color:#e5e5e5;">${val}</div>
            <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:#555;margin-top:4px;">${label}</div>
          </div>`).join("")}
      </div>

      <!-- File summary table -->
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

      <!-- Per-file detailed findings -->
      <div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#444;margin-bottom:16px;">Detailed Findings by File</div>
      ${fileSectionsHtml}

      <!-- Footer -->
      <div style="margin-top:48px;padding-top:24px;border-top:1px solid #1a1a1a;display:flex;justify-content:space-between;">
        <span style="font-size:11px;color:#333;">Generated by AuditScan</span>
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
          <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-white/25">
            <FileCode className="w-3 h-3" />
            <span className="text-white/40 font-medium">{fileName}</span>
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

        {/* Summary card */}
        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-8 mb-6">
          <div className="flex flex-col md:flex-row items-center gap-8">

            {/* Overall score */}
            <div className="flex flex-col items-center flex-shrink-0">
              <span className={`text-6xl font-bold font-mono ${overallRisk.text}`}>
                {result.overall_risk_score}
              </span>
              <div className="mt-3 px-4 py-1.5 rounded-full border text-sm font-semibold tracking-wide border-white/10">
                <span className={overallRisk.text}>{overallRisk.label} Risk</span>
              </div>
            </div>

            <div className="hidden md:block w-px self-stretch bg-white/[0.06]" />

            {/* Stats */}
            <div className="flex-1 space-y-4 w-full">
              <div>
                <p className="text-[11px] uppercase tracking-widest text-white/25 mb-1.5">Multi-Contract Scan</p>
                <p className="text-white/60 text-sm leading-relaxed">
                  Scanned <span className="text-white font-semibold">{result.scanned}</span> of{" "}
                  <span className="text-white font-semibold">{result.total_files}</span> files.
                  Found <span className="text-white font-semibold">{result.total_findings} total issue{result.total_findings !== 1 ? "s" : ""}</span> across all contracts.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                  <span className="text-xl font-bold font-mono text-white/70">{result.total_files}</span>
                  <span className="text-[10px] text-white/30 uppercase tracking-widest">Files</span>
                </div>
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                  <span className="text-xl font-bold font-mono text-white/70">{result.scanned}</span>
                  <span className="text-[10px] text-white/30 uppercase tracking-widest">Scanned</span>
                </div>
                <div className="flex flex-col items-center gap-1 p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                  <span className="text-xl font-bold font-mono text-white/70">{result.total_findings}</span>
                  <span className="text-[10px] text-white/30 uppercase tracking-widest">Issues</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Per-file results */}
        <div className="space-y-3">
          <p className="text-[11px] uppercase tracking-widest text-white/25 mb-4">Files</p>
          {result.files.map((file, i) => (
            <FileCard key={i} file={file} index={i} />
          ))}
        </div>

        {/* Footer with working export */}
        <div className="mt-12 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-white/80">Want the full audit report?</p>
            <p className="text-xs text-white/30 mt-1">Export as PDF with all findings grouped by severity</p>
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