export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  title: string;
  severity: Severity;
  description: string;
  fix: string;
  chain?: string;
  category?: string;
  occurrences?: number;
  l2_detected?: boolean;
  ml_exploitability?: string;
  ml_confidence?: number;
  files_affected?: string[];
}

export interface ScanResult {
  scan_id?: string;
  risk_score: number;
  total_findings?: number; 
  findings: Finding[];
  exploit_simulation?: {
    success: boolean;
    stdout: string;
    stderr: string;
  };

  chain?: string;
  is_anchor?: boolean;
  scanners_used?: {
    cargo_audit: boolean;
    pattern_scan: boolean;
    cargo_geiger: boolean;
  };
  errors?: string[];
}