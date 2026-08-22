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
    <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-6">
      <div className="w-full max-w-md">
        {/* File under scan — raised header. Filename and % are data. */}
        <div className="neu-panel flex items-center gap-3 px-4 py-3.5 mb-7">
          <div
            className="neu-chip w-9 h-9 flex items-center justify-center flex-shrink-0"
            style={{ color: "var(--accent)" }}
          >
            <FileCode className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <p className="data-strong text-sm font-semibold truncate">{fileName}</p>
            <p className="text-ink-muted text-[11px] mt-0.5">Scanning now…</p>
          </div>
          <div
            className="data-strong ml-auto text-lg font-bold"
            style={{ color: "var(--accent)" }}
            aria-live="polite"
          >
            {progress}%
          </div>
        </div>

        {/* Progress runs in a sunken channel; the fill itself is flat. */}
        <div className="neu-well h-3 rounded-full mb-8 overflow-hidden p-[3px]">
          <div
            className="h-full rounded-full transition-all duration-300 ease-out"
            style={{
              width: `${progress}%`,
              background: "linear-gradient(90deg, var(--accent), var(--accent-cool))",
              boxShadow: "0 0 10px var(--accent)",
            }}
          />
        </div>

        {/* Steps */}
        <div className="space-y-2.5">
          {STEPS.map((s, i) => {
            const isDone = i < step;
            const isActive = i === step;
            return (
              <div
                key={s.label}
                className={
                  isActive
                    ? "neu-well flex items-center gap-3 p-3 transition-all duration-500"
                    : "flex items-center gap-3 p-3 transition-all duration-500"
                }
                style={!isActive && !isDone ? { opacity: 0.4 } : undefined}
              >
                <div
                  className="flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center"
                  style={{
                    border: `1.5px solid ${
                      isDone || isActive ? "var(--accent)" : "var(--text-faint)"
                    }`,
                  }}
                >
                  {isDone ? (
                    <svg
                      className="w-2.5 h-2.5"
                      style={{ color: "var(--accent)" }}
                      viewBox="0 0 10 10"
                      fill="none"
                    >
                      <path
                        d="M2 5l2.5 2.5L8 3"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  ) : isActive ? (
                    <div
                      className="w-1.5 h-1.5 rounded-full animate-pulse"
                      style={{ background: "var(--accent)" }}
                    />
                  ) : (
                    <div
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: "var(--text-faint)" }}
                    />
                  )}
                </div>

                <div className="min-w-0">
                  <p
                    className={`text-xs font-semibold tracking-wide ${
                      isActive || isDone ? "data-strong" : "text-ink-muted"
                    }`}
                  >
                    {s.label}
                  </p>
                  {isActive && (
                    <p className="text-[11px] text-ink-muted mt-0.5">{s.detail}</p>
                  )}
                </div>

                {isDone && (
                  <span
                    className="ml-auto text-[9px] tracking-[0.18em] uppercase font-bold"
                    style={{ color: "var(--accent)" }}
                  >
                    done
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
