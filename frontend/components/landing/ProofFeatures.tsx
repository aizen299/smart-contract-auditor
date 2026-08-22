"use client";

import { Binary, GitBranch, Layers } from "lucide-react";

/**
 * Claim-and-proof cards. Every number here is read off the backend rather
 * than chosen for effect:
 *   30 EVM rules            RULES in evm_rules.py
 *   51 Slither mappings     SLITHER_TO_RULE in evm_rules.py
 *   23 Solana rules         SOLANA_RULES in solana_rules.py
 *   8  chains               SUPPORTED_CHAINS in chain_registry.py
 * If those change, change these.
 */

const FEATURES = [
  {
    id: "detection",
    icon: Binary,
    title: "Slither-backed, not regex-guessed",
    body:
      "EVM scans run Slither and map its detectors onto 30 curated rules. Checks that do not map to a rule are dropped rather than surfaced as noise, and duplicates collapse to one finding with an occurrence count.",
    proofLabel: "Rule mapping",
    proof: [
      { text: "51 Slither detectors mapped", dim: false },
      { text: "→ 30 rules, each with CVSS factors", dim: true },
      { text: "unmapped checks discarded", dim: true },
    ],
  },
  {
    id: "scoring",
    icon: GitBranch,
    title: "A risk score you can recompute",
    body:
      "Each finding scores as CVSS base × confidence weight × severity multiplier. The sum is normalised across a curve, so twenty low findings never outrank one critical.",
    proofLabel: "Score function",
    proof: [
      { text: "Σ (cvss × conf × sev)", dim: true },
      { text: "100 × (1 − e^(−total/80))", dim: false },
      { text: "non-empty findings floor at 5", dim: true },
    ],
  },
  {
    id: "chains",
    icon: Layers,
    title: "Solidity and Solana, one upload",
    body:
      "Drop a zip of mixed contracts. Each file is routed by content, not extension — Solidity through Slither, Rust through cargo-audit, a pattern pass and cargo-geiger.",
    proofLabel: "Router",
    proof: [
      { text: ".sol → slither → 30 rules", dim: true },
      { text: ".rs  → cargo-audit + 23 rules", dim: false },
      { text: "8 chains detected from source", dim: true },
    ],
  },
];

export function ProofFeatures() {
  return (
    <section className="border-t border-border/60 px-6 py-24" aria-labelledby="proof-heading">
      <div className="mx-auto w-full max-w-5xl space-y-12">
        <div className="max-w-2xl space-y-4">
          <h2 id="proof-heading" className="text-3xl font-semibold tracking-tight text-foreground">
            Every finding traces back to a rule.
          </h2>
          <p className="leading-relaxed text-muted-foreground">
            A scanner that cannot explain itself is a scanner you cannot act on.
            Each report names the rule that fired, why it scored what it did,
            and the fix.
          </p>
        </div>

        <ul className="space-y-4">
          {FEATURES.map((f) => (
            <li
              key={f.id}
              className="group flex flex-col items-stretch overflow-hidden rounded-lg border border-border bg-card transition-colors duration-fast hover:border-border-strong md:flex-row"
            >
              <div className="flex flex-1 flex-col justify-center p-6 md:p-8">
                <div className="mb-4 flex items-center gap-4">
                  <span className="rounded-md border border-border bg-elevated p-2 text-primary">
                    <f.icon className="h-5 w-5" aria-hidden="true" />
                  </span>
                  <h3 className="text-lg font-medium text-foreground">{f.title}</h3>
                </div>
                <p className="max-w-md leading-relaxed text-muted-foreground">{f.body}</p>
              </div>

              <div className="flex flex-col border-t border-border bg-background md:w-80 md:border-l md:border-t-0">
                <div className="border-b border-border px-4 py-2">
                  <span className="text-xs font-semibold uppercase tracking-widest text-subtle">
                    {f.proofLabel}
                  </span>
                </div>
                <div className="flex flex-1 flex-col justify-center gap-1 p-4 font-mono text-xs leading-relaxed">
                  {f.proof.map((line, i) => (
                    <span
                      key={i}
                      className={line.dim ? "text-subtle" : "text-primary"}
                    >
                      {line.text}
                    </span>
                  ))}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
