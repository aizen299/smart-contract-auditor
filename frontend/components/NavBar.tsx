"use client";

import { ShieldCheck, RotateCcw } from "lucide-react";

interface NavBarProps {
  onReset?: () => void;
}

export function NavBar({ onReset }: NavBarProps) {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-[#080b10]/80 backdrop-blur-xl">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <div className="absolute inset-0 rounded-lg bg-[#00ff88]/20 blur-sm" />
            <div className="relative w-7 h-7 rounded-lg bg-gradient-to-br from-[#00ff88]/30 to-[#00d4ff]/20 border border-[#00ff88]/30 flex items-center justify-center">
              <ShieldCheck className="w-3.5 h-3.5 text-[#00ff88]" />
            </div>
          </div>
          <span className="text-sm font-semibold tracking-widest text-white/90 uppercase">
            AuditScan
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20 font-semibold tracking-wider">
            BETA
          </span>
        </div>

        <div className="flex items-center gap-4">
          <nav className="hidden md:flex items-center gap-6 text-[11px] tracking-widest text-white/40 uppercase">
            <a href="#" className="hover:text-white/70 transition-colors">Docs</a>
            <a href="#" className="hover:text-white/70 transition-colors">Pricing</a>
            <a href="#" className="hover:text-white/70 transition-colors">API</a>
          </nav>
          {onReset ? (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 text-[11px] tracking-widest uppercase text-white/40 hover:text-white/70 transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              New Scan
            </button>
          ) : (
            <button className="text-[11px] tracking-widest uppercase px-3 py-1.5 rounded-lg border border-white/10 text-white/50 hover:border-white/20 hover:text-white/70 transition-all">
              Sign In
            </button>
          )}
        </div>
      </div>
    </header>
  );
}