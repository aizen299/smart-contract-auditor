import type { Severity } from "@/types";

/**
 * The single source of truth for severity and risk banding.
 *
 * This replaces five separate definitions that had drifted apart: four
 * copies of `getRiskLabel` (RiskScore, ScanResults, history/page,
 * MultiScanResults) plus SEVERITY_CONFIG in SeverityBadge. Two of those
 * copies used a four-band scale and two used five, so a contract scoring 15
 * was labelled "Low Risk" on the results screen and "Minimal" in history.
 *
 * Banding here matches `_risk_label` in backend/src/chainaudit/cli.py, which
 * is authoritative. Note the colour intent that follows from it: green means
 * MINIMAL, never LOW — low severity is blue. The CLI has always drawn LOW in
 * cyan and MINIMAL in green; only the web UI disagreed.
 */

export type RiskBand = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";

interface ScaleEntry {
  /** Badge text for a single finding. */
  label: string;
  /** Whole-contract score label, e.g. in the gauge. */
  riskLabel: string;
  /**
   * Mirrors the matching --severity-* token in app/globals.css. Both forms
   * exist because the exported audit report is a standalone HTML document
   * with no access to the app stylesheet, so it needs literal hex.
   */
  hex: string;
  /** Tailwind colour key, mapped in tailwind.config.ts. */
  key: string;
  /** Surface tints for the standalone export, which has no stylesheet. */
  exportBg: string;
  exportBorder: string;
}

const SCALE: Record<RiskBand, ScaleEntry> = {
  CRITICAL: { label: "Critical", riskLabel: "Critical Risk", hex: "#F87171", key: "critical", exportBg: "#2D0A0A", exportBorder: "#7F1D1D" },
  HIGH:     { label: "High",     riskLabel: "High Risk",     hex: "#FB923C", key: "high",     exportBg: "#2D1500", exportBorder: "#7C2D12" },
  MEDIUM:   { label: "Medium",   riskLabel: "Medium Risk",   hex: "#FBBF24", key: "medium",   exportBg: "#2D2500", exportBorder: "#713F12" },
  LOW:      { label: "Low",      riskLabel: "Low Risk",      hex: "#60A5FA", key: "low",      exportBg: "#0A1A2D", exportBorder: "#1E3A5F" },
  MINIMAL:  { label: "Minimal",  riskLabel: "Minimal Risk",  hex: "#4ADE80", key: "minimal",  exportBg: "#071A0F", exportBorder: "#14532D" },
};

/** Display order, most severe first. MINIMAL is a score band only — the
 *  backend never emits it as a finding severity. */
export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** Score → band. Thresholds match cli.py `_risk_label`. */
export function riskBand(score: number): RiskBand {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "MINIMAL";
}

export function severityMeta(severity: Severity): ScaleEntry {
  return SCALE[severity];
}

export function bandMeta(score: number): ScaleEntry {
  return SCALE[riskBand(score)];
}

/** Short label for compact surfaces such as the history table. */
export function riskLabelShort(score: number): string {
  return bandMeta(score).label;
}

/** Full label for the gauge and report headers. */
export function riskLabelLong(score: number): string {
  return bandMeta(score).riskLabel;
}

/** Literal hex, for the standalone HTML export only. In the app, use the
 *  Tailwind classes below so themes stay swappable. */
export function riskColorHex(score: number): string {
  return bandMeta(score).hex;
}

export function severityColorHex(severity: Severity): string {
  return SCALE[severity].hex;
}

/** Token-backed Tailwind classes for in-app severity chrome. */
export function severityClasses(severity: Severity) {
  const { key } = SCALE[severity];
  return {
    text: `text-severity-${key}`,
    bg: `bg-severity-${key}/10`,
    border: `border-severity-${key}/25`,
    dot: `bg-severity-${key}`,
    ring: `ring-severity-${key}/30`,
  };
}

/**
 * Tailwind's JIT scans source statically, so the interpolated class names
 * above are never seen as literals. This array is referenced by the
 * `safelist` in tailwind.config.ts to keep them in the build.
 */
export const SEVERITY_CLASS_KEYS = Object.values(SCALE).map((s) => s.key);

/** Text colour class for a whole-contract score. */
export function riskColorClass(score: number): string {
  return `text-severity-${bandMeta(score).key}`;
}

/** Literal tints for one severity in the standalone export. */
export function severityExportPalette(severity: Severity) {
  const e = SCALE[severity];
  return { bg: e.exportBg, text: e.hex, border: e.exportBorder };
}
