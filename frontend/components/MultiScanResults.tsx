"use client";

import { useState } from "react";
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

function FileCard({ file, index }: { file: FileResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const risk = getRiskColor(file.risk_score);

  return (
    <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] overflow-hidden">
      <button
        onClick={() => file.status === "success" && setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        {/* Index */}
        <span className="flex-shrink-0 w-6 h-6 rounded-lg bg-white/[0.05] border border-white/[0.07] flex items-center justify-center text-[10px] font-semibold text-white/30 font-mono">
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* File icon + name */}
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <FileCode className="w-3.5 h-3.5 text-white/30 flex-shrink-0" />
          <span className="text-sm text-white/80 truncate">{file.file}</span>
        </div>

        {/* Status / score */}
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

      {/* Expanded findings */}
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
              <div
                className="mt-3 px-4 py-1.5 rounded-full border text-sm font-semibold tracking-wide"
                style={{
                  borderColor: `${overallRisk.text.replace("text-", "")}30`,
                }}
              >
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

              {/* File stats */}
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

        {/* Footer */}
        <div className="mt-12 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-white/80">Want the full audit report?</p>
            <p className="text-xs text-white/30 mt-1">Export as PDF with all findings</p>
          </div>
          <button className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/[0.06] border border-white/[0.10] text-sm text-white/70 hover:bg-white/[0.09] hover:text-white/90 transition-all">
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>
      </div>
    </div>
  );
}