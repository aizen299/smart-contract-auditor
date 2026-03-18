"use client";

import { ShieldCheck, RotateCcw, LogOut, User } from "lucide-react";
import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase";
import type { User as SupabaseUser } from "@supabase/supabase-js";
import Link from "next/link";

interface NavBarProps {
  onReset?: () => void;
}

export function NavBar({ onReset }: NavBarProps) {
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const supabase = createClient();

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => setUser(data.user));
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });
    return () => subscription.unsubscribe();
  }, []);

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    setUser(null);
  };

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
          {onReset && (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 text-[11px] tracking-widest uppercase text-white/40 hover:text-white/70 transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              New Scan
            </button>
          )}

          {user ? (
            <div className="flex items-center gap-3">
              <Link
                href="/history"
                className="text-[11px] tracking-widest uppercase text-white/40 hover:text-white/70 transition-colors"
              >
                History
              </Link>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03]">
                <User className="w-3 h-3 text-white/40" />
                <span className="text-[11px] text-white/50 max-w-[120px] truncate">
                  {user.email || user.user_metadata?.user_name || "User"}
                </span>
              </div>
              <button
                onClick={handleSignOut}
                className="flex items-center gap-1.5 text-[11px] tracking-widest uppercase text-white/30 hover:text-red-400 transition-colors"
              >
                <LogOut className="w-3 h-3" />
                Sign Out
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="text-[11px] tracking-widest uppercase px-3 py-1.5 rounded-lg border border-white/10 text-white/50 hover:border-white/20 hover:text-white/70 transition-all"
            >
              Sign In
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}