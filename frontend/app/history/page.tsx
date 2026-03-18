"use client";
export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase";
import { NavBar } from "@/components/NavBar";
import { useRouter } from "next/navigation";
import { FileCode, Trash2, ChevronRight } from "lucide-react";

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

function getRiskLabel(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Minimal";
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const supabase = createClient();

  useEffect(() => {
    const fetchScans = async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        router.push("/login");
        return;
      }

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

  const handleDelete = async (id: string) => {
    await supabase.from("scans").delete().eq("id", id);
    setScans(scans.filter((s) => s.id !== id));
  };

  return (
    <div className="min-h-screen bg-[#080b10] text-white font-mono">
      <NavBar />

      <main className="max-w-3xl mx-auto px-6 pt-24 pb-20">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-lg font-semibold text-white/90">Scan History</h1>
            <p className="text-xs text-white/30 mt-1">Your past contract audits</p>
          </div>
          <span className="text-[11px] text-white/25 uppercase tracking-widest">
            {scans.length} scan{scans.length !== 1 ? "s" : ""}
          </span>
        </div>

        {loading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 rounded-2xl bg-white/[0.02] border border-white/[0.05] animate-pulse" />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-12 text-center">
            <FileCode className="w-8 h-8 text-white/20 mx-auto mb-3" />
            <p className="text-sm text-white/40">No scans yet</p>
            <p className="text-xs text-white/20 mt-1">Upload a contract to get started</p>
            <button
              onClick={() => router.push("/")}
              className="mt-6 px-5 py-2 rounded-xl bg-white/[0.06] border border-white/10 text-sm text-white/60 hover:text-white/80 transition-all"
            >
              Scan a Contract
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="group flex items-center gap-4 px-5 py-4 rounded-2xl border border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.035] hover:border-white/[0.12] transition-all"
              >
                {/* Risk score */}
                <div className="flex-shrink-0 text-center w-12">
                  <span className={`text-xl font-bold font-mono ${getRiskColor(scan.risk_score)}`}>
                    {scan.risk_score}
                  </span>
                  <p className={`text-[9px] uppercase tracking-widest ${getRiskColor(scan.risk_score)} opacity-70`}>
                    {getRiskLabel(scan.risk_score)}
                  </p>
                </div>

                {/* Divider */}
                <div className="w-px self-stretch bg-white/[0.06]" />

                {/* File info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-3 h-3 text-white/30 flex-shrink-0" />
                    <span className="text-sm text-white/80 truncate">{scan.file_name}</span>
                  </div>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-[11px] text-white/25">
                      {scan.total_findings} finding{scan.total_findings !== 1 ? "s" : ""}
                    </span>
                    <span className="text-[11px] text-white/20">·</span>
                    <span className="text-[11px] text-white/25">{formatDate(scan.created_at)}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => handleDelete(scan.id)}
                    className="p-1.5 rounded-lg hover:bg-red-500/10 text-white/20 hover:text-red-400 transition-all"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}