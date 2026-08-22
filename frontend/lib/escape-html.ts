const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape a value for interpolation into an HTML string.
 *
 * The report exports build an HTML document by string concatenation and open it
 * as a `blob:` URL. A blob URL inherits the origin of the document that created
 * it, and the page CSP permits `'unsafe-inline'`, so any unescaped value lands
 * in a script-capable, same-origin document.
 *
 * The values that matter most are contract filenames: the top-level name comes
 * from the user's own upload, but for zip scans every per-file name is a zip
 * entry basename chosen by whoever authored the archive. Auditing third-party
 * contracts is the product's core use case, so those names are untrusted input.
 *
 * Escapes the five characters that are significant in both element text and
 * quoted attribute values, so a single helper is safe in either position.
 */
export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}
