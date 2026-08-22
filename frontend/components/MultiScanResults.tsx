"use client";

import { useState, useCallback } from "react";
import { FileCode, RotateCcw, Download, ChevronDown } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import { escapeHtml } from "@/lib/escape-html";

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

function getRiskColor(score: number) {
  // `tone` is the flat on-screen colour; `text` is retained for any remaining
  // Tailwind-class consumers.
  if (score >= 80) return { text: "text-red-400", label: "Critical", tone: "var(--sev-critical)" };
  if (score >= 60) return { text: "text-orange-400", label: "High", tone: "var(--sev-high)" };
  if (score >= 40) return { text: "text-yellow-400", label: "Medium", tone: "var(--sev-medium)" };
  if (score >= 20) return { text: "text-sky-400", label: "Low", tone: "var(--sev-low)" };
  return { text: "text-emerald-400", label: "Minimal", tone: "var(--sev-safe)" };
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

// ─── Chain display config ─────────────────────────────────────────────────────

const CHAIN_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
  solana: { label: "SOLANA", color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20" },
  ethereum: { label: "ETHEREUM", color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/20" },
  arbitrum: { label: "ARBITRUM", color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
  optimism: { label: "OPTIMISM", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
  base: { label: "BASE", color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/20" },
  polygon: { label: "POLYGON", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  bnb: { label: "BNB", color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  avalanche: { label: "AVAX", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
  l2: { label: "L2", color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/20" },
};

function getChainConfig(chain: string) {
  return CHAIN_CONFIG[chain.toLowerCase()] ?? {
    label: chain.toUpperCase(),
    color: "text-violet-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/20"
  };
}

// Inline badge for file rows
function ChainBadge({ chain, isAnchor }: { chain: string; isAnchor?: boolean }) {
  const cfg = getChainConfig(chain);
  return (
    <span className={`text-[9px] px-1.5 py-0.5 rounded-full ${cfg.bg} ${cfg.color} border ${cfg.border} font-semibold tracking-wider uppercase flex-shrink-0`}>
      {cfg.label}{chain === "solana" && isAnchor ? " · ANCHOR" : ""}
    </span>
  );
}

// Inline badge for individual findings
function FindingChainBadge({ chain }: { chain: string }) {
  const cfg = getChainConfig(chain);
  return (
    <span className={`text-[9px] px-1.5 py-0.5 rounded-full ${cfg.bg} ${cfg.color} border ${cfg.border} font-semibold tracking-wider uppercase`}>
      {cfg.label}
    </span>
  );
}

// Export HTML chain tag (inline styles for PDF)
function exportChainTag(chain: string, isAnchor?: boolean): string {
  const EXPORT_CHAIN_STYLES: Record<string, { bg: string; color: string; border: string }> = {
    solana: { bg: "#2d1f00", color: "#f59e0b", border: "#92400e" },
    ethereum: { bg: "#1e1040", color: "#a78bfa", border: "#4c1d95" },
    arbitrum: { bg: "#0a1a3d", color: "#60a5fa", border: "#1e3a8a" },
    optimism: { bg: "#2d0a0a", color: "#f87171", border: "#7f1d1d" },
    base: { bg: "#0a1f2d", color: "#38bdf8", border: "#0c4a6e" },
    polygon: { bg: "#1a0a2d", color: "#c084fc", border: "#581c87" },
    bnb: { bg: "#2d2500", color: "#facc15", border: "#713f12" },
    avalanche: { bg: "#2d0a0a", color: "#f87171", border: "#7f1d1d" },
    l2: { bg: "#0a2d2d", color: "#22d3ee", border: "#164e63" },
  };
  const s = EXPORT_CHAIN_STYLES[chain.toLowerCase()] ?? EXPORT_CHAIN_STYLES.ethereum;
  const label = escapeHtml(CHAIN_CONFIG[chain.toLowerCase()]?.label ?? chain.toUpperCase());
  const suffix = chain === "solana" && isAnchor ? " · ANCHOR" : "";
  return `<span style="font-size:9px;padding:2px 8px;border-radius:20px;background:${s.bg};color:${s.color};border:1px solid ${s.border};margin-left:8px;">${label}${suffix}</span>`;
}

function exportFindingChainTag(chain: string): string {
  const EXPORT_CHAIN_STYLES: Record<string, { bg: string; color: string; border: string }> = {
    solana: { bg: "#2d1f00", color: "#f59e0b", border: "#92400e" },
    ethereum: { bg: "#1e1040", color: "#a78bfa", border: "#4c1d95" },
    arbitrum: { bg: "#0a1a3d", color: "#60a5fa", border: "#1e3a8a" },
    optimism: { bg: "#2d0a0a", color: "#f87171", border: "#7f1d1d" },
    base: { bg: "#0a1f2d", color: "#38bdf8", border: "#0c4a6e" },
    polygon: { bg: "#1a0a2d", color: "#c084fc", border: "#581c87" },
    bnb: { bg: "#2d2500", color: "#facc15", border: "#713f12" },
    avalanche: { bg: "#2d0a0a", color: "#f87171", border: "#7f1d1d" },
    l2: { bg: "#0a2d2d", color: "#22d3ee", border: "#164e63" },
  };
  const s = EXPORT_CHAIN_STYLES[chain.toLowerCase()] ?? EXPORT_CHAIN_STYLES.ethereum;
  const label = escapeHtml(CHAIN_CONFIG[chain.toLowerCase()]?.label ?? chain.toUpperCase());
  return `<span style="font-size:8px;padding:1px 6px;border-radius:20px;background:${s.bg};color:${s.color};border:1px solid ${s.border};margin-left:6px;">${label}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────

function FileCard({ file, index }: { file: FileResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const risk = getRiskColor(file.risk_score);
  const fileChain = file.chain ?? "ethereum";
  const isSolana = fileChain === "solana";
  const isAnchor = file.is_anchor === true;

  return (
    <div
      className="neu-panel risk-rail overflow-hidden"
      style={{ ["--rail" as string]: file.status === "success" ? risk.tone : "var(--text-faint)" }}
    >
      <button
        onClick={() => file.status === "success" && setExpanded(!expanded)}
        aria-expanded={expanded}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className="code-ref flex-shrink-0 w-7 h-7 flex items-center justify-center text-[11px] font-bold">
          {String(index + 1).padStart(2, "0")}
        </span>

        <div className="flex items-center gap-2 flex-1 min-w-0">
          <FileCode className="w-3.5 h-3.5 flex-shrink-0 text-ink-faint" />
          {/* File name is data — full contrast. */}
          <span className="data-strong text-sm font-semibold truncate">{file.file}</span>
          <ChainBadge chain={fileChain} isAnchor={isAnchor} />
        </div>

        {file.status === "success" ? (
          <div className="flex items-center gap-3 flex-shrink-0">
            <span className="data-strong text-base font-bold" style={{ color: risk.tone }}>
              {file.risk_score}
            </span>
            <span
              className="hidden sm:inline text-[9px] uppercase tracking-[0.14em] font-bold"
              style={{ color: risk.tone }}
            >
              {risk.label}
            </span>
            <span className="data-strong text-[11px] text-ink-muted">
              {file.total_findings} finding{file.total_findings !== 1 ? "s" : ""}
            </span>
            {file.findings.length > 0 && (
              <ChevronDown
                className={`w-4 h-4 text-ink-muted transition-transform duration-300 ${
                  expanded ? "rotate-180" : ""
                }`}
              />
            )}
          </div>
        ) : (
          <span
            className="sev-outline px-2 py-[3px] text-[9px] flex-shrink-0"
            style={{ borderColor: "var(--text-muted)", color: "var(--text-muted)" }}
          >
            {file.status}
          </span>
        )}
      </button>

      {expanded && file.findings.length > 0 && (
        <div className="px-5 pb-5 pt-1 space-y-3">
          {file.findings.map((finding, i) => {
            const findingChain = finding.chain ?? fileChain;
            return (
              <div key={i} className="neu-well flex items-start gap-3 p-3.5">
                <span className="code-ref flex-shrink-0 px-1.5 py-1 text-[10px] font-bold">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <span className="data-strong text-sm font-semibold">{finding.title}</span>
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <FindingChainBadge chain={findingChain} />
                  </div>
                  <p className="text-xs text-ink-secondary leading-relaxed">
                    {finding.description}
                  </p>
                  <div className="mt-2.5 rounded-lg px-3 py-2.5"
                    style={{
                      background: "var(--neu-surface)",
                      boxShadow: `var(--raise-sm), inset 0 0 0 1px var(--sev-safe)22`,
                    }}
                  >
                    <p
                      className="text-[9px] uppercase tracking-[0.16em] mb-1 font-bold"
                      style={{ color: "var(--sev-safe)" }}
                    >
                      Fix
                    </p>
                    <p className="text-xs text-ink-secondary leading-relaxed">{finding.fix}</p>
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
  const overallRisk = getRiskColor(result.overall_risk_score);
  const hasSolana = result.has_solana === true;
  const hasEVM = result.has_evm === true;

  const date = new Date().toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
  });

  const handleExport = useCallback(() => {
    const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
      CRITICAL: { bg: "#2d0a0a", text: "#f87171", border: "#7f1d1d" },
      HIGH: { bg: "#2d1500", text: "#fb923c", border: "#7c2d12" },
      MEDIUM: { bg: "#2d2500", text: "#facc15", border: "#713f12" },
      LOW: { bg: "#0a1a2d", text: "#60a5fa", border: "#1e3a5f" },
    };

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

      const riskColor = getRiskColorHex(file.risk_score);
      const chainTag = exportChainTag(fileChain, file.is_anchor);

      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const grouped: Record<string, Finding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
      file.findings.forEach(f => grouped[f.severity]?.push(f));

      const findingsHtml = order.flatMap(sev =>
        grouped[sev].map((f, i) => {
          const c = SEVERITY_COLORS[sev] || SEVERITY_COLORS.LOW;
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
              <span style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:${riskColor};margin-left:8px;">${getRiskLabelText(file.risk_score)}</span>
              <span style="font-size:11px;color:#444;margin-left:12px;">${file.total_findings} finding${file.total_findings !== 1 ? "s" : ""}</span>
            </div>
          </div>
          <div style="padding:14px 18px;background:#0a0a0a;">
            ${findingsHtml}
          </div>
        </div>`;
    }).join("");

    const fileRowsHtml = result.files.map(f => {
      const rc = getRiskColorHex(f.risk_score);
      const rowChain = f.chain ?? "ethereum";
      const chainBadge = exportChainTag(rowChain, f.is_anchor).replace('margin-left:8px', 'margin-left:6px');
      return `
        <tr>
          <td style="padding:8px 12px;font-size:12px;color:#ccc;border-bottom:1px solid #1a1a1a;">${escapeHtml(f.file)}${chainBadge}</td>
          <td style="padding:8px 12px;font-size:12px;font-family:monospace;color:${rc};border-bottom:1px solid #1a1a1a;text-align:center;">${f.risk_score}</td>
          <td style="padding:8px 12px;font-size:12px;color:#666;border-bottom:1px solid #1a1a1a;text-align:center;">${escapeHtml(f.status === "success" ? f.total_findings : f.status)}</td>
        </tr>`;
    }).join("");

    const overallColor = getRiskColorHex(result.overall_risk_score);

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
          <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:${overallColor};margin-top:4px;">Overall ${getRiskLabelText(result.overall_risk_score)}</div>
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
    <div className="relative z-10 min-h-screen pt-24 pb-24 px-6">
      <div className="max-w-3xl mx-auto">

        {/* Meta bar */}
        <div className="flex items-center justify-between gap-4 mb-7 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <FileCode className="w-3.5 h-3.5 text-ink-faint" />
            <span className="data-strong text-xs font-semibold truncate max-w-[220px]">
              {fileName}
            </span>
            {hasSolana && (
              <span
                className="sev-outline px-2 py-[3px] text-[9px]"
                style={{ borderColor: "var(--sev-high)", color: "var(--sev-high)" }}
              >
                Solana
              </span>
            )}
            {hasEVM && (
              <span
                className="sev-outline px-2 py-[3px] text-[9px]"
                style={{ borderColor: "#a78bfa", color: "#a78bfa" }}
              >
                EVM
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
        </div>

        {/* Summary */}
        <div className="neu-panel-lg p-8 mb-6">
          <div className="flex flex-col md:flex-row items-center gap-8">
            <div className="flex flex-col items-center flex-shrink-0">
              {/* Overall score sits in a sunken dial; the number itself is flat. */}
              <div
                className="neu-well w-32 h-32 rounded-full flex items-center justify-center"
              >
                <span
                  className="data-strong text-[2.75rem] font-bold leading-none"
                  style={{ color: overallRisk.tone }}
                >
                  {result.overall_risk_score}
                </span>
              </div>
              <div
                className="sev-outline mt-4 px-4 py-1.5 text-[11px]"
                style={{ borderColor: overallRisk.tone, color: overallRisk.tone }}
              >
                {overallRisk.label} Risk
              </div>
            </div>

            <div className="flex-1 space-y-5 w-full">
              <div>
                <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted mb-2 font-bold">
                  Multi-Contract Scan
                </p>
                <p className="text-ink-secondary text-[13px] leading-relaxed">
                  Scanned <span className="data-strong font-bold">{result.scanned}</span> of{" "}
                  <span className="data-strong font-bold">{result.total_files}</span> files.
                  Found{" "}
                  <span className="data-strong font-bold">
                    {result.total_findings} total issue{result.total_findings !== 1 ? "s" : ""}
                  </span>{" "}
                  across all contracts.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-2.5">
                {[
                  ["Files", result.total_files],
                  ["Scanned", result.scanned],
                  ["Issues", result.total_findings],
                ].map(([label, value]) => (
                  <div
                    key={String(label)}
                    className="neu-well flex flex-col items-center gap-2 px-2 py-3"
                  >
                    <span className="data-strong text-2xl font-bold leading-none">
                      {value as number}
                    </span>
                    <span className="text-[9px] text-ink-muted uppercase tracking-[0.14em] font-bold">
                      {label as string}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Per-file results */}
        <div className="space-y-3">
          <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted mb-4 font-bold">
            Files
          </p>
          {result.files.map((file, i) => (
            <FileCard key={i} file={file} index={i} />
          ))}
        </div>

        {/* Export */}
        <div className="mt-12 neu-panel p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <p className="data-strong text-sm font-semibold">Want the full audit report?</p>
            <p className="text-xs text-ink-muted mt-1">
              Export as PDF with all findings grouped by severity
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
        </div>

      </div>
    </div>
  );
}