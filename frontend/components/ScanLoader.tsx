"use client";

import { useEffect, useState } from "react";
import { FileCode } from "lucide-react";

const STEPS = [
  { label: "Parsing AST", detail: "Building abstract syntax tree..." },
  { label: "Resolving symbols", detail: "Mapping function calls & state vars..." },
  { label: "Running detectors", detail: "Checking 15 vulnerability classes..." },
  { label: "Scoring risk", detail: "Calculating CVSS-style severity weights..." },
  { label: "Generating report", detail: "Assembling findings..." },
];

interface ScanLoaderProps {
  fileName: string;
}

export function ScanLoader({ fileName }: ScanLoaderProps) {
  const [step, setStep] = useState(0);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const totalDuration = 3000;
    const stepDuration = totalDuration / STEPS.length;

    const stepTimer = setInterval(() => {
      setStep((s) => Math.min(s + 1, STEPS.length - 1));
    }, stepDuration);

    const progTimer = setInterval(() => {
      setProgress((p) => Math.min(p + 1, 98));
    }, totalDuration / 100);

    return () => {
      clearInterval(stepTimer);
      clearInterval(progTimer);
    };
  }, []);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-6 pt-14">
      {/* Background pulse */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-[500px] h-[500px] rounded-full border border-[#00ff88]/[0.04] animate-ping" style={{ animationDuration: "3s" }} />
        <div className="absolute w-[350px] h-[350px] rounded-full border border-[#00ff88]/[0.06] animate-ping" style={{ animationDuration: "2.2s", animationDelay: "0.4s" }} />
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* File info */}
        <div className="flex items-center gap-3 mb-8 px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.07]">
          <div className="w-8 h-8 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/20 flex items-center justify-center flex-shrink-0">
            <FileCode className="w-4 h-4 text-[#00ff88]" />
          </div>
          <div className="min-w-0">
            <p className="text-white/80 text-sm font-medium truncate">{fileName}</p>
            <p className="text-white/30 text-xs">Scanning now...</p>
          </div>
          <div className="ml-auto text-[#00ff88] text-sm font-semibold font-mono tabular-nums">
            {progress}%
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-px bg-white/[0.06] rounded-full mb-8 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-[#00ff88] to-[#00d4ff] rounded-full transition-all duration-300 ease-out relative"
            style={{ width: `${progress}%` }}
          >
            <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-white shadow-[0_0_8px_rgba(0,255,136,0.8)]" />
          </div>
        </div>

        {/* Steps */}
        <div className="space-y-3">
          {STEPS.map((s, i) => {
            const isDone = i < step;
            const isActive = i === step;
            return (
              <div
                key={s.label}
                className={`flex items-center gap-3 p-3 rounded-xl transition-all duration-500 ${
                  isActive
                    ? "bg-white/[0.04] border border-white/[0.08]"
                    : "opacity-40"
                }`}
              >
                {/* Status icon */}
                <div className={`flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center border transition-all duration-500 ${
                  isDone
                    ? "bg-[#00ff88]/20 border-[#00ff88]/40"
                    : isActive
                    ? "border-[#00ff88]/40"
                    : "border-white/10"
                }`}>
                  {isDone ? (
                    <svg className="w-2.5 h-2.5 text-[#00ff88]" viewBox="0 0 10 10" fill="none">
                      <path d="M2 5l2.5 2.5L8 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : isActive ? (
                    <div className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
                  ) : (
                    <div className="w-1.5 h-1.5 rounded-full bg-white/20" />
                  )}
                </div>

                <div className="min-w-0">
                  <p className={`text-xs font-medium tracking-wide transition-colors ${isActive || isDone ? "text-white/80" : "text-white/30"}`}>
                    {s.label}
                  </p>
                  {isActive && (
                    <p className="text-[11px] text-white/30 mt-0.5 animate-pulse">{s.detail}</p>
                  )}
                </div>

                {isDone && (
                  <div className="ml-auto text-[10px] text-[#00ff88]/60 tracking-widest uppercase">done</div>
                )}
              </div>
            );
          })}
        </div>

        {/* Scanning animation */}
        <div className="mt-8 flex items-center justify-center gap-1.5">
          {[0, 1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="w-1 rounded-full bg-[#00ff88]/50 animate-bounce"
              style={{
                height: `${8 + (i % 3) * 4}px`,
                animationDelay: `${i * 0.1}s`,
                animationDuration: "0.8s",
              }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}