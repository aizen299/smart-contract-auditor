"use client";

import { useEffect, useState } from "react";

interface RiskScoreProps {
  score: number;
}

function getRiskLabel(score: number) {
  if (score >= 80) return { label: "Critical Risk", color: "#ef4444", glow: "rgba(239,68,68,0.3)" };
  if (score >= 60) return { label: "High Risk", color: "#f97316", glow: "rgba(249,115,22,0.3)" };
  if (score >= 40) return { label: "Medium Risk", color: "#eab308", glow: "rgba(234,179,8,0.3)" };
  return { label: "Low Risk", color: "#00ff88", glow: "rgba(0,255,136,0.3)" };
}

export function RiskScore({ score }: RiskScoreProps) {
  const [displayScore, setDisplayScore] = useState(0);
  const { label, color, glow } = getRiskLabel(score);

  const RADIUS = 72;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const strokeDashoffset = CIRCUMFERENCE - (displayScore / 100) * CIRCUMFERENCE;

  useEffect(() => {
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
      {/* Circular gauge */}
      <div className="relative w-44 h-44">
        {/* Glow background */}
        <div
          className="absolute inset-4 rounded-full blur-xl opacity-20 transition-all duration-1000"
          style={{ backgroundColor: color }}
        />

        <svg className="w-full h-full -rotate-90" viewBox="0 0 180 180">
          {/* Track */}
          <circle
            cx="90" cy="90" r={RADIUS}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="10"
            strokeLinecap="round"
          />
          {/* Progress */}
          <circle
            cx="90" cy="90" r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={strokeDashoffset}
            style={{
              transition: "stroke-dashoffset 0.05s linear",
              filter: `drop-shadow(0 0 8px ${glow})`,
            }}
          />
        </svg>

        {/* Score text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-5xl font-bold font-mono tabular-nums leading-none"
            style={{ color }}
          >
            {displayScore}
          </span>
          <span className="text-xs text-white/30 mt-1 tracking-widest uppercase">/ 100</span>
        </div>
      </div>

      {/* Label */}
      <div
        className="mt-4 px-4 py-1.5 rounded-full border text-sm font-semibold tracking-wide"
        style={{
          borderColor: `${color}30`,
          backgroundColor: `${color}10`,
          color,
        }}
      >
        {label}
      </div>
    </div>
  );
}