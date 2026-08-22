"use client";

import { useEffect, useState } from "react";
import { bandMeta } from "@/lib/severity";

interface RiskScoreProps {
  score: number;
}

export function RiskScore({ score }: RiskScoreProps) {
  const [displayScore, setDisplayScore] = useState(0);
  const { riskLabel, hex } = bandMeta(score);

  const RADIUS = 72;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const strokeDashoffset = CIRCUMFERENCE - (displayScore / 100) * CIRCUMFERENCE;

  useEffect(() => {
    // Respect the OS setting rather than counting up regardless — the
    // animation is decorative and the number is the point.
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      setDisplayScore(score);
      return;
    }
    let current = 0;
    const timer = setInterval(() => {
      current += 2;
      if (current >= score) {
        setDisplayScore(score);
        clearInterval(timer);
      } else {
        setDisplayScore(current);
      }
    }, 20);
    return () => clearInterval(timer);
  }, [score]);

  return (
    <div className="flex flex-col items-center">
      <div
        className="relative h-44 w-44"
        role="img"
        aria-label={`Risk score ${score} out of 100 — ${riskLabel}`}
      >
        <div
          className="absolute inset-4 rounded-full opacity-20 blur-xl transition-all duration-slow"
          style={{ backgroundColor: hex }}
          aria-hidden="true"
        />

        <svg className="h-full w-full -rotate-90" viewBox="0 0 180 180" aria-hidden="true">
          <circle
            cx="90" cy="90" r={RADIUS}
            fill="none"
            stroke="hsl(var(--gauge-track))"
            strokeWidth="var(--gauge-stroke)"
            strokeLinecap="round"
          />
          <circle
            cx="90" cy="90" r={RADIUS}
            fill="none"
            stroke={hex}
            strokeWidth="var(--gauge-stroke)"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={strokeDashoffset}
            style={{
              transition: "stroke-dashoffset 0.05s linear",
              filter: `drop-shadow(0 0 8px ${hex}4D)`,
            }}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-mono text-5xl font-bold leading-none tabular-nums"
            style={{ color: hex }}
          >
            {displayScore}
          </span>
          <span className="mt-1 text-xs uppercase tracking-widest text-subtle">/ 100</span>
        </div>
      </div>

      <div
        className="mt-4 rounded-full border px-4 py-1.5 text-sm font-semibold tracking-wide"
        style={{ borderColor: `${hex}40`, backgroundColor: `${hex}1A`, color: hex }}
      >
        {riskLabel}
      </div>
    </div>
  );
}
