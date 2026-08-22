"use client";

import { useEffect, useState } from "react";

interface RiskScoreProps {
  score: number;
}

function getRisk(score: number) {
  if (score >= 80) return { label: "Critical Risk", color: "var(--sev-critical)" };
  if (score >= 60) return { label: "High Risk", color: "var(--sev-high)" };
  if (score >= 40) return { label: "Medium Risk", color: "var(--sev-medium)" };
  if (score >= 20) return { label: "Low Risk", color: "var(--sev-low)" };
  return { label: "Minimal Risk", color: "var(--sev-safe)" };
}

/**
 * The dial housing is neumorphic — a sunken well the track sits in.
 * The arc and the number are not: they are the datum, so they render as a
 * flat saturated stroke and stark white digits.
 */
export function RiskScore({ score }: RiskScoreProps) {
  const [display, setDisplay] = useState(0);
  const { label, color } = getRisk(score);

  const RADIUS = 70;
  const CIRC = 2 * Math.PI * RADIUS;
  const offset = CIRC - (display / 100) * CIRC;

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setDisplay(score);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const DURATION = 900;
    const tick = (now: number) => {
      const t = Math.min((now - start) / DURATION, 1);
      // easeOutCubic — fast settle, no bounce past the true value
      setDisplay(Math.round(score * (1 - Math.pow(1 - t, 3))));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score]);

  return (
    <div className="flex flex-col items-center">
      <div
        className="relative w-44 h-44 rounded-full flex items-center justify-center"
        style={{ background: "var(--neu-sunken)", boxShadow: "var(--press)" }}
      >
        <svg className="w-[164px] h-[164px] -rotate-90" viewBox="0 0 180 180">
          <circle
            cx="90"
            cy="90"
            r={RADIUS}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="9"
            strokeLinecap="round"
          />
          <circle
            cx="90"
            cy="90"
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={CIRC}
            strokeDashoffset={offset}
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="data-strong text-[3.25rem] font-bold leading-none"
            style={{ color }}
          >
            {display}
          </span>
          <span className="text-[10px] text-ink-muted mt-1 tracking-[0.2em] uppercase">
            / 100
          </span>
        </div>
      </div>

      {/* Flat outlined verdict — not a soft chip. */}
      <div
        className="sev-outline mt-5 px-4 py-1.5 text-[11px]"
        style={{ borderColor: color, color }}
      >
        {label}
      </div>
    </div>
  );
}
