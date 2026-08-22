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
        <div className="w-[500px] h-[500px] rounded-full border border-primary/[0.04] animate-ping" style={{ animationDuration: "3s" }} />
        <div className="absolute w-[350px] h-[350px] rounded-full border border-primary/[0.06] animate-ping" style={{ animationDuration: "2.2s", animationDelay: "0.4s" }} />
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* File info */}
        <div className="flex items-center gap-3 mb-8 px-4 py-3 rounded-md bg-card border border-border">
          <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
            <FileCode className="w-4 h-4 text-primary" />
          </div>
          <div className="min-w-0">
            <p className="text-foreground text-sm font-medium truncate">{fileName}</p>
            <p className="text-muted-foreground text-xs">Scanning now...</p>
          </div>
          <div className="ml-auto text-primary text-sm font-semibold font-mono tabular-nums">
            {progress}%
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-px bg-elevated rounded-full mb-8 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-primary to-info rounded-full transition-all duration-300 ease-out relative"
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
                className={`flex items-center gap-3 p-3 rounded-md transition-all duration-500 ${
                  isActive
                    ? "bg-elevated border border-border"
                    : "opacity-40"
                }`}
              >
                {/* Status icon */}
                <div className={`flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center border transition-all duration-500 ${
                  isDone
                    ? "bg-primary/20 border-primary/40"
                    : isActive
                    ? "border-primary/40"
                    : "border-border"
                }`}>
                  {isDone ? (
                    <svg className="w-2.5 h-2.5 text-primary" viewBox="0 0 10 10" fill="none">
                      <path d="M2 5l2.5 2.5L8 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : isActive ? (
                    <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  ) : (
                    <div className="w-1.5 h-1.5 rounded-full bg-white/20" />
                  )}
                </div>

                <div className="min-w-0">
                  <p className={`text-xs font-medium tracking-wide transition-colors ${isActive || isDone ? "text-foreground" : "text-muted-foreground"}`}>
                    {s.label}
                  </p>
                  {isActive && (
                    <p className="text-xs text-muted-foreground mt-0.5 animate-pulse">{s.detail}</p>
                  )}
                </div>

                {isDone && (
                  <div className="ml-auto text-xs text-primary/60 tracking-widest uppercase">done</div>
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
              className="w-1 rounded-full bg-primary/50 animate-bounce"
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