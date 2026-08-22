"use client";
export const dynamic = "force-dynamic";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { UploadZone } from "@/components/UploadZone";
import { ScanResults } from "@/components/ScanResults";
import { MultiScanResults } from "@/components/MultiScanResults";
import { ScanLoader } from "@/components/ScanLoader";
import { NavBar } from "@/components/NavBar";
import { createClient } from "@/lib/supabase";
import type { ScanResult } from "@/types";

type Stage = "idle" | "scanning" | "results" | "multi-results" | "error";

export default function Home() {
  const [stage, setStage] = useState<Stage>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [multiResult, setMultiResult] = useState<any | null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const router = useRouter();

  useEffect(() => {
    router.refresh();
  }, []);

  const handleScan = async (file: File) => {
    setFileName(file.name);
    setStage("scanning");
    setErrorMessage("");

    const formData = new FormData();
    formData.append("file", file);

    const isZip = file.name.endsWith(".zip");
    const isRust = file.name.endsWith(".rs");

    const endpoint = isZip
      ? "/api/scan/zip"
      : isRust
      ? "/api/scan/rust"
      : "/api/scan";

    try {
      // The scan API verifies a Supabase JWT, so the session token travels with
      // the request. Next's rewrite forwards headers to the backend unchanged.
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        // Scanning requires a verified Supabase token, so send them somewhere
        // they can act rather than showing a dead-end error.
        router.push("/login?next=/");
        return;
      }

      const res = await fetch(endpoint, {
        method: "POST",
        body: formData,
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      const data = await res.json().catch(() => ({}));

      if (res.status === 401) {
        router.push("/login?next=/");
        return;
      }

      if (res.status === 429) {
        setErrorMessage(
          data.detail || "Too many scans in a short period. Try again shortly."
        );
        setStage("error");
        return;
      }

      if (!res.ok) {
        setErrorMessage(data.detail || "An unexpected error occurred.");
        setStage("error");
        return;
      }

      if (isZip) {
        setMultiResult(data);
        setStage("multi-results");
      } else {
        // Both .sol and .rs return single scan results
        const scanResult = data as ScanResult;
        setResult(scanResult);
        setStage("results");

        // Save to history — the scan already proved the session is valid.
        try {
          await supabase.from("scans").insert({
              user_id: session.user.id,
              file_name: file.name,
              risk_score: scanResult.risk_score,
              total_findings: scanResult.total_findings ?? scanResult.findings?.length ?? 0,
              findings: scanResult.findings,
          });
        } catch {
          console.error("Failed to save scan to history");
        }
      }

    } catch {
      setErrorMessage("Could not connect to the scan server. Make sure the backend is running.");
      setStage("error");
    }
  };

  const handleReset = () => {
    setStage("idle");
    setResult(null);
    setMultiResult(null);
    setFileName("");
    setErrorMessage("");
  };

  return (
    <div className="relative min-h-screen text-ink-secondary">
      {/* Ambient motion sits behind everything; panels float above it. */}
      <div className="neu-ambient" aria-hidden="true" />
      <div className="neu-grid" aria-hidden="true" />

      <NavBar onReset={stage !== "idle" ? handleReset : undefined} />

      <main className="relative z-10">
        {stage === "idle" && <UploadZone onScan={handleScan} />}
        {stage === "scanning" && <ScanLoader fileName={fileName} />}
        {stage === "results" && result && (
          <ScanResults result={result} fileName={fileName} onRescan={handleReset} />
        )}
        {stage === "multi-results" && multiResult && (
          <MultiScanResults result={multiResult} fileName={fileName} onRescan={handleReset} />
        )}
        {stage === "error" && (
          <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-6">
            <div className="w-full max-w-md neu-panel-lg p-9 text-center">
              <div
                className="neu-well w-14 h-14 rounded-full flex items-center justify-center mx-auto mb-5"
                style={{ color: "var(--sev-critical)" }}
              >
                <svg className="w-6 h-6" viewBox="0 0 20 20" fill="currentColor">
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                    clipRule="evenodd"
                  />
                </svg>
              </div>
              <p className="data-strong text-sm font-bold mb-2">Scan Failed</p>
              <p role="alert" className="text-xs text-ink-secondary leading-relaxed mb-7">
                {errorMessage}
              </p>
              <button
                onClick={handleReset}
                className="neu-btn w-full py-3 text-[11px] font-bold tracking-[0.16em] uppercase"
              >
                Try Again
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}