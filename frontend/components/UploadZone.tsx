"use client";

import { useState, useCallback, useRef } from "react";
import { Upload, FileCode, FileArchive, Zap, Lock, Eye } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { chainBadgeStyle, chainDisplay } from "@/lib/chains";

interface UploadZoneProps {
  onScan: (file: File) => void;
}

// Mirrors the backend ceiling (5MB zip) so an oversized file is reported
// immediately instead of after uploading and waiting for a 400.
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

function getFileType(file: File): "sol" | "zip" | "rust" | null {
  if (file.name.endsWith(".sol")) return "sol";
  if (file.name.endsWith(".zip")) return "zip";
  if (file.name.endsWith(".rs"))  return "rust";
  return null;
}

// Which chains to advertise on the hero. Colours and labels come from
// lib/chains.ts so this list can never disagree with the badges elsewhere.
const CHAIN_PILLS = ["ethereum", "arbitrum", "optimism", "base", "polygon", "solana"];

export function UploadZone({ onScan }: UploadZoneProps) {
  const [dragging, setDragging]       = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [rejection, setRejection] = useState<string>("");
  const inputRef = useRef<HTMLInputElement>(null);

  const fileType    = selectedFile ? getFileType(selectedFile) : null;
  // Mirrors --warning / --info / --primary in app/globals.css.
  const accentColor = fileType === "rust" ? "#F59E0B" : fileType === "zip" ? "#38BDF8" : "#22C55E";

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

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    accept(e.dataTransfer.files[0]);
  }, [accept]);

  const handleDragOver  = (e: React.DragEvent) => { e.preventDefault(); setDragging(true); };
  const handleDragLeave = () => setDragging(false);
  const openPicker = useCallback(() => {
    if (!selectedFile) inputRef.current?.click();
  }, [selectedFile]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    accept(e.target.files?.[0]);
  };

  const fileLabel = fileType === "zip"  ? "Multi-contract zip"
                  : fileType === "rust" ? "Solana / Rust program"
                  : "Solidity";

  const scanLabel = fileType === "zip"  ? `→ Scan ${selectedFile?.name}`
                  : fileType === "rust" ? "→ Scan Solana Program"
                  : "→ Scan Contract";

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 pb-16 pt-24">

      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(0,255,136,1) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0,255,136,1) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      />

      {/* Glow orbs */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] rounded-full bg-primary/[0.03] blur-3xl pointer-events-none" />
      <div className="absolute top-1/2 left-1/4 w-[300px] h-[300px] rounded-full bg-info/[0.04] blur-3xl pointer-events-none" />

      {/* Hero text */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="relative z-10 text-center max-w-2xl mb-12"
      >
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/20 bg-primary/5 text-primary text-xs tracking-widest uppercase mb-6">
          <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
          AI-Powered Static Analysis
        </div>

        <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-4 leading-[1.05]">
          <span className="text-foreground">Audit Smart</span>
          <br />
          <span className="bg-gradient-to-r from-primary via-primary to-info bg-clip-text text-transparent">
            Contracts
          </span>
        </h1>

        <p className="text-muted-foreground text-base leading-relaxed max-w-lg mx-auto mb-6">
          Upload a Solidity file, Solana Rust program, or a zip of multiple contracts.
          Get a comprehensive security report with risk scores and actionable fixes.
        </p>

        {/* Supported chain pills */}
        <div className="flex flex-wrap items-center justify-center gap-1.5">
          {CHAIN_PILLS.map((key) => (
            <span
              key={key}
              className="rounded-full border px-2.5 py-0.5 text-xs uppercase tracking-widest"
              style={chainBadgeStyle(key)}
            >
              {chainDisplay(key).label}
            </span>
          ))}
        </div>
      </motion.div>

      {/* Drop zone */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, duration: 0.35 }}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={openPicker}
        onKeyDown={(e) => {
          // A div with onClick is invisible to the keyboard, and this is the
          // only route into the file picker — without this a keyboard-only
          // user cannot upload at all.
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            openPicker();
          }
        }}
        role={selectedFile ? undefined : "button"}
        tabIndex={selectedFile ? undefined : 0}
        aria-label={selectedFile ? undefined : "Choose a .sol, .rs or .zip file to scan"}
        className={`relative z-10 w-full max-w-lg rounded-lg transition-all duration-300 cursor-pointer border-2 border-dashed
          ${dragging
            ? "border-primary/60 bg-primary/5 scale-[1.01]"
            : selectedFile
            ? "border-border-strong bg-card"
            : "border-border bg-card hover:border-border-strong hover:bg-card"
          }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".sol,.zip,.rs"
          onChange={handleFileChange}
          className="hidden"
          tabIndex={-1}
          aria-hidden="true"
        />

        <div className="p-10 text-center">
          <AnimatePresence mode="wait">
            {selectedFile ? (
              <motion.div
                key="selected"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.18 }}
                className="flex flex-col items-center gap-3"
              >
                <div
                  className="w-12 h-12 rounded-md flex items-center justify-center"
                  style={{ backgroundColor: `${accentColor}18`, border: `1px solid ${accentColor}30` }}
                >
                  {fileType === "zip"
                    ? <FileArchive className="w-5 h-5" style={{ color: accentColor }} />
                    : <FileCode    className="w-5 h-5" style={{ color: accentColor }} />
                  }
                </div>
                <div>
                  <p className="text-foreground font-medium text-sm">{selectedFile.name}</p>
                  <p className="text-muted-foreground text-xs mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB · {fileLabel}
                  </p>
                </div>

                {fileType === "zip" && (
                  <div className="px-3 py-1 rounded-full bg-info/10 border border-info/20 text-xs text-info tracking-widest uppercase">
                    Multi-contract scan
                  </div>
                )}
                {fileType === "rust" && (
                  <div className="px-3 py-1 rounded-full bg-warning/10 border border-warning/25 text-xs text-warning tracking-widest uppercase">
                    Solana / Rust scan
                  </div>
                )}

                <button
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                  className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2 transition-colors"
                >
                  Remove file
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
                <div className={`w-12 h-12 rounded-md border flex items-center justify-center transition-colors
                  ${dragging ? "bg-primary/15 border-primary/40" : "bg-elevated border-border"}`}>
                  <Upload className={`w-5 h-5 transition-colors ${dragging ? "text-primary" : "text-muted-foreground"}`} />
                </div>
                <div>
                  <p className="text-foreground text-sm font-medium">
                    Drop your{" "}
                    <span className="text-primary">.sol</span>
                    {", "}
                    <span className="text-warning">.rs</span>
                    {" or "}
                    <span className="text-info">.zip</span> file here
                  </p>
                  <p className="text-muted-foreground text-xs mt-1">or click to browse</p>
                </div>
                <div className="flex items-center gap-2 flex-wrap justify-center">
                  <span className="text-xs tracking-widest uppercase text-subtle border border-border rounded-full px-3 py-1">
                    Solidity .sol
                  </span>
                  <span className="text-subtle text-xs">·</span>
                  <span className="text-xs tracking-widest uppercase text-warning/70 border border-warning/25 rounded-full px-3 py-1">
                    Solana .rs
                  </span>
                  <span className="text-subtle text-xs">·</span>
                  <span className="text-xs tracking-widest uppercase text-subtle border border-border rounded-full px-3 py-1">
                    Multi .zip
                  </span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {dragging && (
          <div className="absolute inset-0 rounded-lg bg-primary/5 pointer-events-none" />
        )}

        {rejection && (
          <p
            role="alert"
            className="px-10 pb-6 -mt-4 text-sm text-destructive text-center"
          >
            {rejection}
          </p>
        )}
      </motion.div>

      {/* Scan button */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="relative z-10 mt-4 w-full max-w-lg"
      >
        <button
          onClick={() => selectedFile && onScan(selectedFile)}
          disabled={!selectedFile}
          className={`w-full py-3.5 rounded-md text-sm font-semibold tracking-widest uppercase transition-all duration-300
            ${selectedFile
              ? fileType === "rust"
                ? "bg-warning text-background hover:bg-warning/90 active:scale-[0.99]"
                : "bg-primary text-background hover:bg-primary-hover shadow-[0_0_40px_rgba(0,255,136,0.2)] hover:shadow-[0_0_60px_rgba(0,255,136,0.3)] active:scale-[0.99]"
              : "bg-elevated text-muted-foreground cursor-not-allowed border border-border"
            }`}
        >
          {selectedFile ? scanLabel : "Select a File to Continue"}
        </button>
      </motion.div>

      {/* Feature pills */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="relative z-10 mt-10 flex flex-wrap items-center justify-center gap-4"
      >
        {[
          // Timings and retention describe what the scanner actually does:
          // Slither is capped at 90s and the cargo tools at 120s each, and
          // uploads are deleted after the scan while findings are saved to
          // history only when signed in.
          { icon: Zap,  label: "Results in Under 2 Min"     },
          { icon: Lock, label: "Uploads Deleted After Scan" },
          { icon: Eye,  label: "50+ Vulnerability Rules"    },
        ].map(({ icon: Icon, label }) => (
          <div key={label} className="flex items-center gap-2 text-xs tracking-widest uppercase text-subtle">
            <Icon className="w-3 h-3 text-subtle" />
            {label}
          </div>
        ))}
      </motion.div>
    </div>
  );
}
