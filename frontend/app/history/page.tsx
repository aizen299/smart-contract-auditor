"use client";
export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase";
import { NavBar } from "@/components/NavBar";
import { ScanResults } from "@/components/ScanResults";
import { useRouter } from "next/navigation";
import { FileCode, Trash2, ArrowLeft } from "lucide-react";
import type { ScanResult } from "@/types";

interface ScanRecord {
  id: string;
  file_name: string;
  risk_score: number;
  total_findings: number;
  findings: any[];
  created_at: string;
}

function getRiskColor(score: number) {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  if (score >= 20) return "text-sky-400";
  return "text-emerald-400";
}

// Flat on-screen tone for the score, matching the design tokens.
function getRiskTone(score: number) {
  if (score >= 80) return "var(--sev-critical)";
  if (score >= 60) return "var(--sev-high)";
  if (score >= 40) return "var(--sev-medium)";
  if (score >= 20) return "var(--sev-low)";
  return "var(--sev-safe)";
}

function getRiskLabel(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Minimal";
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ScanRecord | null>(null);
  const router = useRouter();

  useEffect(() => {
    const fetchScans = async () => {
      const supabase = createClient();
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) { router.push("/login"); return; }

      const { data } = await supabase
        .from("scans")
        .select("*")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

      setScans(data || []);
      setLoading(false);
    };
    fetchScans();
  }, []);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation(); // prevent opening the scan
    const supabase = createClient();
    await supabase.from("scans").delete().eq("id", id);
    setScans(scans.filter((s) => s.id !== id));
    if (selected?.id === id) setSelected(null);
  };

  // Show full results for a selected scan
  if (selected) {
    const scanResult: ScanResult = {
      risk_score: selected.risk_score,
      findings: selected.findings,
    };
    return (
      <div className="min-h-screen bg-[#080b10] text-white font-mono">
        <NavBar />
        {/* Back button */}
        <div className="fixed top-14 left-0 right-0 z-40 border-b border-white/[0.04] bg-[#080b10]/80 backdrop-blur-xl">
          <div className="max-w-6xl mx-auto px-6 h-10 flex items-center">
            <button
              onClick={() => setSelected(null)}
              className="flex items-center gap-1.5 text-[11px] uppercase tracking-widest text-white/30 hover:text-white/60 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" />
              Back to History
            </button>
          </div>
        </div>
        {/* Offset for the extra bar */}
        <div className="pt-10">
          <ScanResults
            result={scanResult}
            fileName={selected.file_name}
            onRescan={() => setSelected(null)}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen text-ink-secondary">
      <div className="neu-ambient" aria-hidden="true" />
      <div className="neu-grid" aria-hidden="true" />
      <NavBar />

      <main className="relative z-10 max-w-3xl mx-auto px-6 pt-28 pb-24">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="data-strong text-lg font-bold">Scan History</h1>
            <p className="text-xs text-ink-muted mt-1">Your past contract audits</p>
          </div>
          <span className="data-strong text-[11px] text-ink-muted uppercase tracking-[0.16em]">
            {scans.length} scan{scans.length !== 1 ? "s" : ""}
          </span>
        </div>

        {loading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="neu-well h-20 animate-pulse" />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="neu-panel-lg p-12 text-center">
            <div className="neu-well w-14 h-14 rounded-full flex items-center justify-center mx-auto mb-5">
              <FileCode className="w-6 h-6 text-ink-muted" />
            </div>
            <p className="data-strong text-sm font-semibold">No scans yet</p>
            <p className="text-xs text-ink-muted mt-1.5">Upload a contract to get started</p>
            <button
              onClick={() => router.push("/")}
              className="neu-btn mt-7 px-6 py-3 text-[11px] font-bold tracking-[0.16em] uppercase"
              style={{ color: "var(--accent)" }}
            >
              Scan a Contract
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <div
                key={scan.id}
                onClick={() => setSelected(scan)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelected(scan);
                  }
                }}
                className="neu-panel risk-rail group flex items-center gap-4 px-5 py-4 cursor-pointer"
                style={{ ["--rail" as string]: getRiskTone(scan.risk_score) }}
              >
                <div className="flex-shrink-0 text-center w-14">
                  <span
                    className="data-strong text-xl font-bold leading-none"
                    style={{ color: getRiskTone(scan.risk_score) }}
                  >
                    {scan.risk_score}
                  </span>
                  <p
                    className="text-[9px] uppercase tracking-[0.12em] mt-1 font-bold"
                    style={{ color: getRiskTone(scan.risk_score) }}
                  >
                    {getRiskLabel(scan.risk_score)}
                  </p>
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-3 h-3 text-ink-faint flex-shrink-0" />
                    <span className="data-strong text-sm font-semibold truncate">
                      {scan.file_name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="data-strong text-[11px] text-ink-muted">
                      {scan.total_findings} finding{scan.total_findings !== 1 ? "s" : ""}
                    </span>
                    <span className="text-[11px] text-ink-faint">·</span>
                    <span className="text-[11px] text-ink-muted">
                      {formatDate(scan.created_at)}
                    </span>
                  </div>
                </div>

                <button
                  onClick={(e) => handleDelete(e, scan.id)}
                  aria-label={`Delete scan of ${scan.file_name}`}
                  className="neu-btn flex-shrink-0 p-2 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 transition-opacity"
                  style={{ color: "var(--sev-critical)" }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}