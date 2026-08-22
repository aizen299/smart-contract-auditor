import { cn } from "@/lib/utils";

/**
 * ChainAudit mark — a block held in brackets.
 *
 * Brackets read as code, the hexagon reads as a block: together, "auditing
 * code on chain". Monoline so it holds at 24px, currentColor so it inherits
 * whatever it sits in.
 *
 * Chosen over three alternatives that were rendered and compared side by
 * side. A hexagon-plus-check was the obvious first move and the reason it
 * lost: it is the standard "verified" badge, which is what the stock lucide
 * ShieldCheck already said. A scanline variant read as a hamburger menu, and
 * a waveform variant read as a heart-rate monitor. This one is the only
 * option that is specific to what the product does.
 */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn("h-6 w-6", className)}
      aria-hidden="true"
      focusable="false"
    >
      {/* Brackets — code */}
      <path d="M8.5 3.2H4.6v17.6h3.9M15.5 3.2h3.9v17.6h-3.9" />
      {/* Block — chain */}
      <path d="M12 7l3.9 2.25v4.5L12 16l-3.9-2.25V9.25Z" opacity={0.85} />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "font-mono text-sm font-semibold uppercase tracking-widest text-foreground",
        className,
      )}
    >
      ChainAudit
    </span>
  );
}

/** Icon + wordmark. The default lockup for headers. */
export function Logo({
  className,
  markClassName,
}: {
  className?: string;
  markClassName?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <span className="relative inline-flex">
        <span className="absolute inset-0 rounded-md bg-primary/20 blur-sm" aria-hidden="true" />
        <span className="relative inline-flex items-center justify-center rounded-md border border-primary/30 bg-primary/10 p-1 text-primary">
          <LogoMark className={cn("h-4 w-4", markClassName)} />
        </span>
      </span>
      <Wordmark />
    </span>
  );
}
