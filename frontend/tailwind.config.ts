import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./types/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Structural surfaces. Consumed by neumorphic containers.
        neu: {
          bg: "var(--neu-bg)",
          surface: "var(--neu-surface)",
          alt: "var(--neu-surface-alt)",
          sunken: "var(--neu-sunken)",
          dark: "var(--neu-dark)",
          light: "var(--neu-light)",
        },
        // Data colours. Flat and saturated — these never carry a shadow.
        sev: {
          critical: "var(--sev-critical)",
          high: "var(--sev-high)",
          medium: "var(--sev-medium)",
          low: "var(--sev-low)",
          safe: "var(--sev-safe)",
        },
        ink: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
          faint: "var(--text-faint)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          cool: "var(--accent-cool)",
        },
      },
      boxShadow: {
        raise: "var(--raise)",
        "raise-sm": "var(--raise-sm)",
        "raise-lg": "var(--raise-lg)",
        press: "var(--press)",
        "press-sm": "var(--press-sm)",
      },
      borderRadius: {
        neu: "1.5rem",
      },
    },
  },
  plugins: [],
};

export default config;
