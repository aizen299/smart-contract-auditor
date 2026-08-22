import type { Severity } from "@/types";

/**
 * Severity tags are deliberately flat.
 *
 * A neumorphic tag would encode risk as a shadow direction, which is both
 * slow to read and invisible to anyone who cannot resolve the soft edges.
 * These sit on top of the soft surfaces as solid, saturated marks: dark ink
 * on a bright fill for the two levels that demand attention, and a crisp
 * outline for the two that do not.
 */
const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; color: string; solid: boolean }
> = {
  CRITICAL: { label: "Critical", color: "var(--sev-critical)", solid: true },
  HIGH:     { label: "High",     color: "var(--sev-high)",     solid: true },
  MEDIUM:   { label: "Medium",   color: "var(--sev-medium)",   solid: false },
  LOW:      { label: "Low",      color: "var(--sev-low)",      solid: false },
};

interface BadgeProps {
  severity: Severity;
  size?: "sm" | "md";
}

export function SeverityBadge({ severity, size = "md" }: BadgeProps) {
  const { label, color, solid } = SEVERITY_CONFIG[severity];
  const dims = size === "sm" ? "text-[9px] px-2 py-[3px]" : "text-[10px] px-2.5 py-1";

  if (solid) {
    return (
      <span
        className={`sev-tag ${dims}`}
        style={{ backgroundColor: color, boxShadow: `0 0 12px ${color}55` }}
      >
        {label}
      </span>
    );
  }

  return (
    <span
      className={`sev-outline inline-flex items-center gap-1.5 ${dims}`}
      style={{ borderColor: color, color }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
        style={{ backgroundColor: color }}
      />
      {label}
    </span>
  );
}

export { SEVERITY_CONFIG };
