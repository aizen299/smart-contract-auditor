import type { Severity } from "@/types";
import { severityClasses, severityMeta } from "@/lib/severity";

interface BadgeProps {
  severity: Severity;
  size?: "sm" | "md";
}

export function SeverityBadge({ severity, size = "md" }: BadgeProps) {
  const c = severityClasses(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border font-semibold uppercase tracking-wider
        ${c.bg} ${c.text} ${c.border}
        ${size === "sm" ? "text-xs px-2 py-0.5" : "text-xs px-2.5 py-1"}
      `}
    >
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${c.dot}`} aria-hidden="true" />
      {severityMeta(severity).label}
    </span>
  );
}
