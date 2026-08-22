import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Source-level guard for the report exports.
 *
 * Both export functions build an HTML document by string concatenation and open
 * it as a `blob:` URL, which inherits this app's origin. Values that originate
 * outside our own code — contract filenames above all, since zip entry names are
 * chosen by whoever authored the archive being audited — must pass through
 * escapeHtml() on the way in.
 *
 * This asserts against the source text rather than rendered output because the
 * builders are closures inside `useCallback` and are not independently
 * importable. It is a regression tripwire, not a substitute for escapeHtml's own
 * unit tests: it catches a future edit that interpolates an untrusted value raw.
 */

const COMPONENTS = ["ScanResults.tsx", "MultiScanResults.tsx"] as const;

// Expressions that carry data from outside our own code.
const UNTRUSTED = [
  "fileName",
  "file.file",
  "f.file",
  "f.title",
  "f.description",
  "f.fix",
  "file.reason",
  "file.status",
  "f.status",
];

function sourceOf(component: string): string {
  return readFileSync(join(__dirname, component), "utf8");
}

describe("report export escaping", () => {
  it.each(COMPONENTS)("%s imports escapeHtml", (component) => {
    expect(sourceOf(component)).toContain("@/lib/escape-html");
  });

  describe.each(COMPONENTS)("%s", (component) => {
    it.each(UNTRUSTED)(
      "never interpolates %s into HTML unescaped",
      (expression) => {
        const src = sourceOf(component);
        // Matches `${expression}` and `${expression.something()}` but not
        // `${escapeHtml(expression)}`.
        const raw = new RegExp(
          "\\$\\{\\s*" + expression.replace(/\./g, "\\.") + "[^}]*\\}",
          "g",
        );
        const offenders = (src.match(raw) ?? []).filter(
          (m) => !m.includes("escapeHtml"),
        );
        expect(offenders).toEqual([]);
      },
    );
  });

  it("escapeHtml is not accidentally applied twice to the same value", () => {
    for (const component of COMPONENTS) {
      expect(sourceOf(component)).not.toMatch(/escapeHtml\(\s*escapeHtml\(/);
    }
  });
});
