export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  title: string;
  severity: Severity;
  description: string;
  fix: string;
}

export interface ScanResult {
  risk_score: number;
  findings: Finding[];
}