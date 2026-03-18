"use client";
export const dynamic = "force-dynamic";

import { useState } from "react";
import { UploadZone } from "@/components/UploadZone";
import { ScanResults } from "@/components/ScanResults";
import { ScanLoader } from "@/components/ScanLoader";
import { NavBar } from "@/components/NavBar";
import { createClient } from "@/lib/supabase";
import type { ScanResult } from "@/types";

type Stage = "idle" | "scanning" | "results" | "error";

export default function Home() {
  const [stage, setStage] = useState<Stage>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string>("");

  const handleScan = async (file: File) => {
    setFileName(file.name);
    setStage("scanning");
    setErrorMessage("");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setErrorMessage(data.detail || "An unexpected error occurred. Please try again.");
        setStage("error");
        return;
      }

      const scanResult = data as ScanResult;
      setResult(scanResult);
      setStage("results");

      // Save to Supabase if user is logged in
      try {
        const supabase = createClient();
        const { data: { user } } = await supabase.auth.getUser();
        if (user) {
          await supabase.from("scans").insert({
            user_id: user.id,
            file_name: file.name,
            risk_score: scanResult.risk_score,
            total_findings: scanResult.findings.length,
            findings: scanResult.findings,
          });
        }
      } catch {
        // Silently fail — scan still works without saving
        console.error("Failed to save scan to history");
      }

    } catch {
      setErrorMessage("Could not connect to the scan server. Make sure the backend is running.");
      setStage("error");
    }
  };

  const handleReset = () => {
    setStage("idle");
    setResult(null);
    setFileName("");
    setErrorMessage("");
  };

  return (
    <div className="min-h-screen bg-[#080b10] text-white font-mono">
      <NavBar onReset={stage !== "idle" ? handleReset : undefined} />

      <main className="relative">
        {stage === "idle" && <UploadZone onScan={handleScan} />}
        {stage === "scanning" && <ScanLoader fileName={fileName} />}
        {stage === "results" && result && (
          <ScanResults result={result} fileName={fileName} onRescan={handleReset} />
        )}
        {stage === "error" && (
          <div className="min-h-screen flex flex-col items-center justify-center px-6 pt-14">
            <div className="w-full max-w-md">
              <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-8 text-center">
                <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-4">
                  <svg className="w-5 h-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <p className="text-sm font-semibold text-white/80 mb-2">Scan Failed</p>
                <p className="text-xs text-white/40 leading-relaxed mb-6">{errorMessage}</p>
                <button
                  onClick={handleReset}
                  className="px-6 py-2.5 rounded-xl bg-white/[0.06] border border-white/10 text-sm text-white/70 hover:bg-white/[0.09] hover:text-white/90 transition-all"
                >
                  Try Again
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}