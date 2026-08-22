"use client";

import { RotateCcw, LogOut, User } from "lucide-react";
import { Logo } from "@/components/brand/Logo";
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
    <header className="fixed inset-x-0 top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-xl">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">

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
          <Logo />
          <span className="rounded-full border border-primary/25 bg-primary/10 px-1.5 py-0.5 text-xs font-semibold tracking-wider text-primary">
            BETA
          </span>
        </Link>

        <div className="flex items-center gap-4">
          {onReset && (
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground"
            >
              <RotateCcw className="h-3 w-3" aria-hidden="true" />
              New Scan
            </button>
          )}

          {user ? (
            <div className="flex items-center gap-3">
              <Link
                href="/history"
                className="text-xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground"
              >
                History
              </Link>
              <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5">
                <User className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                <span className="max-w-[140px] truncate text-xs text-muted-foreground">
                  {user.email || user.user_metadata?.user_name || "User"}
                </span>
              </div>
              <button
                onClick={handleSignOut}
                className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-destructive"
              >
                <LogOut className="h-3 w-3" aria-hidden="true" />
                Sign Out
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="rounded-md border border-border px-3 py-1.5 text-xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
            >
              Sign In
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}