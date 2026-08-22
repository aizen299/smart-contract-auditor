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

  useEffect(() => {
    const supabase = createClient();

    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        if (event === "SIGNED_IN" || event === "SIGNED_OUT" || event === "TOKEN_REFRESHED") {
          setUser(session?.user ?? null);
        }
      }
    );

    return () => subscription.unsubscribe();
  }, []);

  const handleSignOut = async () => {
    const supabase = createClient();
    await supabase.auth.signOut();
    setUser(null);
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 px-4 pt-4">
      <div
        className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between rounded-2xl"
        style={{
          background: "var(--neu-surface)",
          boxShadow: "var(--raise)",
        }}
      >
        <Link
          href="/"
          onClick={(e) => {
            if (onReset) {
              e.preventDefault();
              onReset();
            }
          }}
          className="flex items-center gap-2.5"
        >
          <div
            className="neu-chip w-8 h-8 flex items-center justify-center"
            style={{ color: "var(--accent)" }}
          >
            <ShieldCheck className="w-4 h-4" />
          </div>
          <span className="data-strong text-sm font-bold tracking-[0.16em] uppercase">
            ChainAudit
          </span>
          <span
            className="sev-outline px-1.5 py-[2px] text-[9px]"
            style={{ borderColor: "var(--accent)", color: "var(--accent)" }}
          >
            Beta
          </span>
        </Link>

        <div className="flex items-center gap-2.5">
          {onReset && (
            <button
              onClick={onReset}
              className="neu-btn flex items-center gap-1.5 px-3 py-2 text-[10px] tracking-[0.16em] uppercase text-ink-muted"
            >
              <RotateCcw className="w-3 h-3" />
              <span className="hidden sm:inline">New Scan</span>
            </button>
          )}

          {user ? (
            <>
              <Link
                href="/history"
                className="neu-btn px-3 py-2 text-[10px] tracking-[0.16em] uppercase text-ink-muted"
              >
                History
              </Link>
              <div className="neu-well hidden md:flex items-center gap-2 px-3 py-2">
                <User className="w-3 h-3 text-ink-faint" />
                <span className="text-[10px] text-ink-muted max-w-[130px] truncate">
                  {user.email || user.user_metadata?.user_name || "User"}
                </span>
              </div>
              <button
                onClick={handleSignOut}
                aria-label="Sign out"
                className="neu-btn flex items-center gap-1.5 px-3 py-2 text-[10px] tracking-[0.16em] uppercase text-ink-muted"
              >
                <LogOut className="w-3 h-3" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </>
          ) : (
            <Link
              href="/login"
              className="neu-btn px-4 py-2 text-[10px] tracking-[0.16em] uppercase"
              style={{ color: "var(--accent)" }}
            >
              Sign In
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}
