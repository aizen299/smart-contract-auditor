/**
 * The single source of truth for chain display.
 *
 * This replaces three maps that had drifted apart — CHAIN_COLORS in
 * FindingCard, CHAIN_DISPLAY in ScanResults and CHAIN_CONFIG in
 * MultiScanResults. They disagreed on Ethereum (purple vs violet) and had
 * Arbitrum and Base outright swapped, so one chain rendered in two different
 * colours depending on which component drew the badge.
 *
 * Keys and display names match SUPPORTED_CHAINS in
 * backend/src/chainaudit/chain_registry.py. Colours are each chain's own
 * brand hue lightened until it clears 4.5:1 on --background; every entry
 * below is measured and passes. They are literals rather than CSS variables
 * because the standalone HTML export needs them too, and because a chain's
 * brand colour is not a themeable product decision.
 */

export interface ChainDisplay {
  label: string;
  hex: string;
}

const CHAINS: Record<string, ChainDisplay> = {
  ethereum:  { label: "Ethereum",  hex: "#818CF8" },
  arbitrum:  { label: "Arbitrum",  hex: "#38BDF8" },
  optimism:  { label: "Optimism",  hex: "#F87171" },
  base:      { label: "Base",      hex: "#60A5FA" },
  polygon:   { label: "Polygon",   hex: "#C084FC" },
  bnb:       { label: "BNB Chain", hex: "#FACC15" },
  avalanche: { label: "Avalanche", hex: "#FB7185" },
  solana:    { label: "Solana",    hex: "#F59E0B" },
};

// The scanner also emits these as chain values on individual findings.
const ALIASES: Record<string, string> = {
  evm: "ethereum",
  l2: "arbitrum",
};

const FALLBACK: ChainDisplay = { label: "EVM", hex: "#818CF8" };

export function chainDisplay(chain: string | undefined): ChainDisplay {
  if (!chain) return CHAINS.ethereum;
  const key = chain.toLowerCase();
  return CHAINS[key] ?? CHAINS[ALIASES[key] ?? ""] ?? { ...FALLBACK, label: chain.toUpperCase() };
}

/** Inline style for a chain badge — works in the app and in the export. */
export function chainBadgeStyle(chain: string | undefined) {
  const { hex } = chainDisplay(chain);
  return { color: hex, backgroundColor: `${hex}1A`, borderColor: `${hex}40` };
}

/**
 * Tints for the standalone export. Eight-digit hex is used rather than a
 * hand-picked dark swatch per chain, so the export can never drift from the
 * in-app badge the way the previous two copies of this table did.
 */
export function chainExportTint(chain: string | undefined) {
  const { hex } = chainDisplay(chain);
  return { bg: `${hex}1F`, color: hex, border: `${hex}59` };
}

export const SUPPORTED_CHAIN_KEYS = Object.keys(CHAINS);
