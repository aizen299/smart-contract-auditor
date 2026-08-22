"use client";

import { useState, useCallback, useRef } from "react";
import { Upload, FileCode, FileArchive, Zap, Lock, Eye, X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface UploadZoneProps {
  onScan: (file: File) => void;
}

// Mirrors the backend ceiling (5MB zip) so an oversized file is reported
// immediately instead of after uploading and waiting for a 400.
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

function getFileType(file: File): "sol" | "zip" | "rust" | null {
  if (file.name.endsWith(".sol")) return "sol";
  if (file.name.endsWith(".zip")) return "zip";
  if (file.name.endsWith(".rs")) return "rust";
  return null;
}

const CHAINS = [
  { label: "Ethereum", color: "#a78bfa" },
  { label: "Arbitrum", color: "#5ac8fa" },
  { label: "Optimism", color: "#ff6961" },
  { label: "Base", color: "#64a9ff" },
  { label: "Polygon", color: "#c084fc" },
  { label: "Solana", color: "#ffb340" },
];

const ACCENT: Record<string, string> = {
  sol: "var(--accent)",
  zip: "var(--accent-cool)",
  rust: "var(--sev-high)",
};

export function UploadZone({ onScan }: UploadZoneProps) {
  const [dragging, setDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [rejection, setRejection] = useState<string>("");
  const inputRef = useRef<HTMLInputElement>(null);

  const fileType = selectedFile ? getFileType(selectedFile) : null;
  const accent = fileType ? ACCENT[fileType] : "var(--accent)";

  const accept = useCallback((file: File | undefined) => {
    if (!file) return;
    if (!getFileType(file)) {
      setRejection(
        `${file.name} is not a supported file. Upload a .sol, .rs, or .zip file.`
      );
      setSelectedFile(null);
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setRejection(
        `${file.name} is ${(file.size / 1024 / 1024).toFixed(1)}MB. The limit is ` +
          `${MAX_UPLOAD_BYTES / 1024 / 1024}MB.`
      );
      setSelectedFile(null);
      return;
    }
    setRejection("");
    setSelectedFile(file);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      accept(e.dataTransfer.files[0]);
    },
    [accept]
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  };
  const handleDragLeave = () => setDragging(false);
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    accept(e.target.files?.[0]);

  const fileLabel =
    fileType === "zip"
      ? "Multi-contract archive"
      : fileType === "rust"
      ? "Solana / Rust program"
      : "Solidity contract";

  const scanLabel = selectedFile
    ? fileType === "zip"
      ? "Scan Archive"
      : fileType === "rust"
      ? "Scan Solana Program"
      : "Scan Contract"
    : "Select a file to continue";

  return (
    <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-6 py-24">
      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        className="text-center max-w-2xl mb-10"
      >
        <div className="neu-chip inline-flex items-center gap-2 px-3 py-1.5 mb-7">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }}
          />
          <span className="text-[10px] tracking-[0.22em] uppercase text-ink-muted">
            Static Analysis · ML Exploitability
          </span>
        </div>

        <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-5 leading-[1.05] data-strong">
          Audit Smart
          <br />
          <span style={{ color: "var(--accent)" }}>Contracts</span>
        </h1>

        <p className="text-ink-secondary text-sm leading-relaxed max-w-md mx-auto mb-7">
          Upload a Solidity file, a Solana program, or an archive of contracts.
          Get risk scores, ML exploitability predictions, and actionable fixes.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-2">
          {CHAINS.map(({ label, color }) => (
            <span
              key={label}
              className="sev-outline px-2.5 py-1 text-[9px]"
              style={{ borderColor: `${color}66`, color }}
            >
              {label}
            </span>
          ))}
        </div>
      </motion.div>

      {/* Drop well — sunken, because it receives something. */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, duration: 0.4 }}
        className="w-full max-w-lg"
      >
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => !selectedFile && inputRef.current?.click()}
          role="button"
          tabIndex={selectedFile ? -1 : 0}
          aria-label="Drop a contract file here, or press Enter to browse"
          onKeyDown={(e) => {
            if (!selectedFile && (e.key === "Enter" || e.key === " ")) {
              e.preventDefault();
              inputRef.current?.click();
            }
          }}
          className="neu-well-deep relative px-8 py-12 cursor-pointer transition-shadow duration-200"
          style={
            dragging
              ? { boxShadow: `var(--press-lg), inset 0 0 0 2px var(--accent)` }
              : undefined
          }
        >
          <input
            ref={inputRef}
            type="file"
            accept=".sol,.zip,.rs"
            onChange={handleFileChange}
            className="sr-only"
          />

          <AnimatePresence mode="wait">
            {selectedFile ? (
              <motion.div
                key="selected"
                initial={{ opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.97 }}
                transition={{ duration: 0.18 }}
                className="flex flex-col items-center gap-3"
              >
                <div
                  className="neu-chip w-12 h-12 flex items-center justify-center"
                  style={{ color: accent }}
                >
                  {fileType === "zip" ? (
                    <FileArchive className="w-5 h-5" />
                  ) : (
                    <FileCode className="w-5 h-5" />
                  )}
                </div>
                <div className="text-center">
                  {/* Filename is data — full contrast, no soft treatment. */}
                  <p className="data-strong text-sm font-semibold break-all px-4">
                    {selectedFile.name}
                  </p>
                  <p className="text-[11px] text-ink-muted mt-1.5 tracking-wide">
                    {(selectedFile.size / 1024).toFixed(1)} KB · {fileLabel}
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedFile(null);
                    setRejection("");
                  }}
                  className="neu-btn inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] tracking-widest uppercase text-ink-muted"
                >
                  <X className="w-3 h-3" />
                  Remove
                </button>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="flex flex-col items-center gap-4"
              >
                <motion.div
                  animate={dragging ? { y: -4 } : { y: 0 }}
                  transition={{ type: "spring", stiffness: 320, damping: 20 }}
                  className="neu-chip w-12 h-12 flex items-center justify-center"
                  style={{ color: dragging ? "var(--accent)" : "var(--text-muted)" }}
                >
                  <Upload className="w-5 h-5" />
                </motion.div>
                <div className="text-center">
                  <p className="text-sm text-ink-secondary">
                    Drop your{" "}
                    <span className="data-strong font-semibold">.sol</span>,{" "}
                    <span className="data-strong font-semibold">.rs</span> or{" "}
                    <span className="data-strong font-semibold">.zip</span> here
                  </p>
                  <p className="text-[11px] text-ink-faint mt-1.5">or click to browse</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Rejection — flat critical colour, announced to assistive tech. */}
        <AnimatePresence>
          {rejection && (
            <motion.p
              role="alert"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-4 text-center text-xs font-medium"
              style={{ color: "var(--sev-critical)" }}
            >
              {rejection}
            </motion.p>
          )}
        </AnimatePresence>

        {/* Primary action — extruded, depresses on press. */}
        <button
          onClick={() => selectedFile && onScan(selectedFile)}
          disabled={!selectedFile}
          className="neu-btn w-full mt-5 py-4 text-xs font-bold tracking-[0.18em] uppercase"
          style={selectedFile ? { color: accent } : undefined}
        >
          {selectedFile ? `→ ${scanLabel}` : scanLabel}
        </button>
      </motion.div>

      {/* Capability strip */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.25 }}
        className="mt-12 flex flex-wrap items-center justify-center gap-3"
      >
        {[
          { icon: Zap, label: "Results in Under 2 Min" },
          { icon: Lock, label: "Uploads Deleted After Scan" },
          { icon: Eye, label: "50+ Vulnerability Rules" },
        ].map(({ icon: Icon, label }) => (
          <div
            key={label}
            className="neu-chip flex items-center gap-2 px-3 py-2 text-[10px] tracking-[0.14em] uppercase text-ink-muted"
          >
            <Icon className="w-3 h-3" />
            {label}
          </div>
        ))}
      </motion.div>
    </div>
  );
}
