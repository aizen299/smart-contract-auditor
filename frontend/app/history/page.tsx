"use client";
export const dynamic = "force-dynamic";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, FileCode, Trash2 } from "lucide-react";
import { createClient } from "@/lib/supabase";
import { NavBar } from "@/components/NavBar";
import { ScanResults } from "@/components/ScanResults";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import type { ScanResult } from "@/types";
import { bandMeta, riskLabelShort } from "@/lib/severity";

interface ScanRecord {
  id: string;
  file_name: string;
  risk_score: number;
  total_findings: number;
  findings: any[];
  created_at: string;
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<ScanRecord | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ScanRecord | null>(null);
  const router = useRouter();

  useEffect(() => {
    const fetchScans = async () => {
      const supabase = createClient();
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) { router.push("/login"); return; }

      const { data, error: fetchError } = await supabase
        .from("scans")
        .select("*")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

      // A failed fetch previously rendered as an empty history, which reads as
      // "you have no scans" — the opposite of what happened.
      if (fetchError) setError("Could not load your scan history.");
      setScans(data || []);
      setLoading(false);
    };
    fetchScans();
  }, [router]);

  const confirmDelete = useCallback(async () => {
    if (!pendingDelete) return;
    const target = pendingDelete;
    setPendingDelete(null);

    const supabase = createClient();
    const { error: deleteError } = await supabase.from("scans").delete().eq("id", target.id);
    if (deleteError) {
      setError("Could not delete that scan.");
      return;
    }
    setScans((prev) => prev.filter((s) => s.id !== target.id));
    if (selected?.id === target.id) setSelected(null);
  }, [pendingDelete, selected]);

  if (selected) {
    const scanResult: ScanResult = {
      risk_score: selected.risk_score,
      findings: selected.findings,
    };
    return (
      <div className="min-h-screen">
        <NavBar />
        <div className="fixed inset-x-0 top-14 z-40 border-b border-border/60 bg-background/80 backdrop-blur-xl">
          <div className="mx-auto flex h-10 max-w-6xl items-center px-6">
            <button
              onClick={() => setSelected(null)}
              className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground"
            >
              <ArrowLeft className="h-3 w-3" aria-hidden="true" />
              Back to history
            </button>
          </div>
        </div>
        <div className="pt-10">
          <ScanResults
            result={scanResult}
            fileName={selected.file_name}
            onRescan={() => setSelected(null)}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <NavBar />

      <main className="mx-auto max-w-3xl px-6 pb-20 pt-24">
        <div className="mb-8 flex items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">Scan history</h1>
            <p className="mt-1 text-sm text-muted-foreground">Your past contract audits</p>
          </div>
          {!loading && scans.length > 0 && (
            <span className="shrink-0 text-xs uppercase tracking-widest text-subtle">
              {scans.length} scan{scans.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>

        {error && (
          <p role="alert" className="mb-4 rounded-md border border-destructive/25 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            {error}
          </p>
        )}

        {loading ? (
          <div className="space-y-2" aria-busy="true" aria-label="Loading scan history">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-[72px] w-full rounded-lg" />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="rounded-lg border border-border bg-card p-12 text-center">
            <FileCode className="mx-auto mb-3 h-8 w-8 text-subtle" aria-hidden="true" />
            <p className="text-base font-medium text-foreground">No scans yet</p>
            <p className="mt-1 text-sm text-muted-foreground">Upload a contract to get started</p>
            <Button className="mt-6" onClick={() => router.push("/")}>
              Scan a contract
            </Button>
          </div>
        ) : (
          <ul className="space-y-2">
            {scans.map((scan) => {
              const { hex } = bandMeta(scan.risk_score);
              return (
                <li
                  key={scan.id}
                  className="flex items-stretch gap-1 rounded-lg border border-border bg-card transition-colors hover:border-border-strong hover:bg-elevated"
                >
                  {/* A real button, so the row is reachable by keyboard. It was
                      previously a div with onClick, which nothing but a mouse
                      could operate. */}
                  <button
                    type="button"
                    onClick={() => setSelected(scan)}
                    className="flex min-w-0 flex-1 items-center gap-4 rounded-l-lg px-5 py-4 text-left"
                  >
                    <span className="w-12 shrink-0 text-center">
                      <span
                        className="block font-mono text-xl font-bold tabular-nums"
                        style={{ color: hex }}
                      >
                        {scan.risk_score}
                      </span>
                      <span
                        className="block text-xs uppercase tracking-widest"
                        style={{ color: hex }}
                      >
                        {riskLabelShort(scan.risk_score)}
                      </span>
                    </span>

                    <span className="w-px self-stretch bg-border" aria-hidden="true" />

                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <FileCode className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                        <span className="truncate font-mono text-sm text-foreground">{scan.file_name}</span>
                      </span>
                      <span className="mt-1 block text-sm text-muted-foreground">
                        {scan.total_findings} finding{scan.total_findings !== 1 ? "s" : ""}
                        {" · "}
                        {formatDate(scan.created_at)}
                      </span>
                    </span>
                  </button>

                  {/* Always in the layout and always focusable. Hiding it behind
                      opacity-0 until hover made it unreachable by keyboard. */}
                  <button
                    type="button"
                    onClick={() => setPendingDelete(scan)}
                    aria-label={`Delete scan of ${scan.file_name}`}
                    className="shrink-0 self-center rounded-md p-2 text-subtle transition-colors hover:bg-destructive/10 hover:text-destructive focus-visible:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </main>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(o) => !o && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this scan?</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete
                ? `The saved report for ${pendingDelete.file_name} will be removed from your history. This cannot be undone.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
