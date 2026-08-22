import type { Config } from "tailwindcss";

/**
 * Colours resolve through the CSS variables in app/globals.css rather than
 * being defined here, so a single token edit re-themes the whole app and the
 * `<alpha-value>` placeholder keeps opacity modifiers (`bg-card/60`) working.
 */
const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts}",
    "./types/**/*.{js,ts,jsx,tsx}",
  ],
  // severityClasses() in lib/severity.ts builds these names by interpolation,
  // so the JIT scanner cannot see them as literals.
  safelist: [
    {
      pattern: /(bg|text|border|ring)-severity-(critical|high|medium|low|minimal)/,
      variants: ["hover", "focus"],
    },
  ],
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: "hsl(var(--foreground) / <alpha-value>)",
        card: {
          DEFAULT: "hsl(var(--card) / <alpha-value>)",
          foreground: "hsl(var(--card-foreground) / <alpha-value>)",
        },
        elevated: "hsl(var(--elevated) / <alpha-value>)",
        muted: {
          DEFAULT: "hsl(var(--muted) / <alpha-value>)",
          foreground: "hsl(var(--muted-foreground) / <alpha-value>)",
        },
        subtle: "hsl(var(--subtle-foreground) / <alpha-value>)",
        border: {
          DEFAULT: "hsl(var(--border) / <alpha-value>)",
          strong: "hsl(var(--border-strong) / <alpha-value>)",
        },
        input: "hsl(var(--input) / <alpha-value>)",
        ring: "hsl(var(--ring) / <alpha-value>)",
        primary: {
          DEFAULT: "hsl(var(--primary) / <alpha-value>)",
          foreground: "hsl(var(--primary-foreground) / <alpha-value>)",
          hover: "hsl(var(--primary-hover) / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive) / <alpha-value>)",
          foreground: "hsl(var(--destructive-foreground) / <alpha-value>)",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary) / <alpha-value>)",
          foreground: "hsl(var(--secondary-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(var(--accent) / <alpha-value>)",
          foreground: "hsl(var(--accent-foreground) / <alpha-value>)",
        },
        popover: {
          DEFAULT: "hsl(var(--popover) / <alpha-value>)",
          foreground: "hsl(var(--popover-foreground) / <alpha-value>)",
        },
        info: "hsl(var(--info) / <alpha-value>)",
        warning: "hsl(var(--warning) / <alpha-value>)",
        syntax: {
          keyword: "hsl(var(--syntax-keyword) / <alpha-value>)",
          type: "hsl(var(--syntax-type) / <alpha-value>)",
          string: "hsl(var(--syntax-string) / <alpha-value>)",
          comment: "hsl(var(--syntax-comment) / <alpha-value>)",
          punct: "hsl(var(--syntax-punct) / <alpha-value>)",
        },
        severity: {
          critical: "hsl(var(--severity-critical) / <alpha-value>)",
          high: "hsl(var(--severity-high) / <alpha-value>)",
          medium: "hsl(var(--severity-medium) / <alpha-value>)",
          low: "hsl(var(--severity-low) / <alpha-value>)",
          minimal: "hsl(var(--severity-minimal) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        DEFAULT: "var(--radius)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
      },
      transitionTimingFunction: {
        out: "var(--ease-out)",
      },
      transitionDuration: {
        DEFAULT: "var(--duration)",
        fast: "var(--duration-fast)",
        slow: "var(--duration-slow)",
      },
      keyframes: {
        "fade-up": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "none" },
        },
      },
      animation: {
        "fade-up": "fade-up var(--duration-slow) var(--ease-out) both",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
