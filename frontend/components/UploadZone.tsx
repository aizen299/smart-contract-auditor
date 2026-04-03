"use client";

import { useState, useCallback, useRef } from "react";
import { Upload, FileCode, FileArchive, Zap, Lock, Eye } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface UploadZoneProps {
  onScan: (file: File) => void;
}

function getFileType(file: File): "sol" | "zip" | "rust" | null {
  if (file.name.endsWith(".sol")) return "sol";
  if (file.name.endsWith(".zip")) return "zip";
  if (file.name.endsWith(".rs"))  return "rust";
  return null;
}

const CHAIN_PILLS = [
  { label: "Ethereum",  color: "text-purple-400/60", border: "border-purple-500/20" },
  { label: "Arbitrum",  color: "text-sky-400/60",    border: "border-sky-500/20"    },
  { label: "Optimism",  color: "text-red-400/60",    border: "border-red-500/20"    },
  { label: "Base",      color: "text-blue-400/60",   border: "border-blue-500/20"   },
  { label: "Polygon",   color: "text-purple-400/60", border: "border-purple-500/20" },
  { label: "Solana",    color: "text-amber-400/60",  border: "border-amber-500/20"  },
];

export function UploadZone({ onScan }: UploadZoneProps) {
  const [dragging, setDragging]       = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const fileType    = selectedFile ? getFileType(selectedFile) : null;
  const accentColor = fileType === "rust" ? "#f59e0b" : fileType === "zip" ? "#00d4ff" : "#00ff88";

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && getFileType(file)) setSelectedFile(file);
  }, []);

  const handleDragOver  = (e: React.DragEvent) => { e.preventDefault(); setDragging(true); };
  const handleDragLeave = () => setDragging(false);
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && getFileType(file)) setSelectedFile(file);
  };

  const fileLabel = fileType === "zip"  ? "Multi-contract zip"
                  : fileType === "rust" ? "Solana / Rust program"
                  : "Solidity";

  const scanLabel = fileType === "zip"  ? `→ Scan ${selectedFile?.name}`
                  : fileType === "rust" ? "→ Scan Solana Program"
                  : "→ Scan Contract";

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center px-6 pt-14 overflow-hidden">

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
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] rounded-full bg-[#00ff88]/[0.03] blur-3xl pointer-events-none" />
      <div className="absolute top-1/2 left-1/4 w-[300px] h-[300px] rounded-full bg-[#00d4ff]/[0.04] blur-3xl pointer-events-none" />

      {/* Hero text */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="relative z-10 text-center max-w-2xl mb-12"
      >
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#00ff88]/20 bg-[#00ff88]/5 text-[#00ff88] text-[11px] tracking-widest uppercase mb-6">
          <div className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
          AI-Powered Static Analysis
        </div>

        <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-4 leading-[1.05]">
          <span className="text-white">Audit Smart</span>
          <br />
          <span className="bg-gradient-to-r from-[#00ff88] via-[#00e5a0] to-[#00d4ff] bg-clip-text text-transparent">
            Contracts
          </span>
        </h1>

        <p className="text-white/40 text-base leading-relaxed max-w-lg mx-auto mb-6">
          Upload a Solidity file, Solana Rust program, or a zip of multiple contracts.
          Get a comprehensive security report with risk scores and actionable fixes.
        </p>

        {/* Supported chain pills */}
        <div className="flex flex-wrap items-center justify-center gap-1.5">
          {CHAIN_PILLS.map(({ label, color, border }) => (
            <span
              key={label}
              className={`text-[10px] tracking-widest uppercase border rounded-full px-2.5 py-0.5 ${color} ${border} bg-white/[0.02]`}
            >
              {label}
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
        onClick={() => !selectedFile && inputRef.current?.click()}
        className={`relative z-10 w-full max-w-lg rounded-2xl transition-all duration-300 cursor-pointer border-2 border-dashed
          ${dragging
            ? "border-[#00ff88]/60 bg-[#00ff88]/5 scale-[1.01]"
            : selectedFile
            ? "border-white/20 bg-white/[0.03]"
            : "border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.03]"
          }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".sol,.zip,.rs"
          onChange={handleFileChange}
          className="hidden"
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
                  className="w-12 h-12 rounded-xl flex items-center justify-center"
                  style={{ backgroundColor: `${accentColor}18`, border: `1px solid ${accentColor}30` }}
                >
                  {fileType === "zip"
                    ? <FileArchive className="w-5 h-5" style={{ color: accentColor }} />
                    : <FileCode    className="w-5 h-5" style={{ color: accentColor }} />
                  }
                </div>
                <div>
                  <p className="text-white font-medium text-sm">{selectedFile.name}</p>
                  <p className="text-white/30 text-xs mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB · {fileLabel}
                  </p>
                </div>

                {fileType === "zip" && (
                  <div className="px-3 py-1 rounded-full bg-[#00d4ff]/10 border border-[#00d4ff]/20 text-[10px] text-[#00d4ff] tracking-widest uppercase">
                    Multi-contract scan
                  </div>
                )}
                {fileType === "rust" && (
                  <div className="px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-[10px] text-amber-400 tracking-widest uppercase">
                    Solana / Rust scan
                  </div>
                )}

                <button
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                  className="text-[11px] text-white/30 hover:text-white/60 underline underline-offset-2 transition-colors"
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
                <div className={`w-12 h-12 rounded-xl border flex items-center justify-center transition-colors
                  ${dragging ? "bg-[#00ff88]/15 border-[#00ff88]/40" : "bg-white/[0.04] border-white/10"}`}>
                  <Upload className={`w-5 h-5 transition-colors ${dragging ? "text-[#00ff88]" : "text-white/40"}`} />
                </div>
                <div>
                  <p className="text-white/70 text-sm font-medium">
                    Drop your{" "}
                    <span className="text-[#00ff88]">.sol</span>
                    {", "}
                    <span className="text-amber-400">.rs</span>
                    {" or "}
                    <span className="text-[#00d4ff]">.zip</span> file here
                  </p>
                  <p className="text-white/30 text-xs mt-1">or click to browse</p>
                </div>
                <div className="flex items-center gap-2 flex-wrap justify-center">
                  <span className="text-[10px] tracking-widest uppercase text-white/20 border border-white/10 rounded-full px-3 py-1">
                    Solidity .sol
                  </span>
                  <span className="text-white/20 text-xs">·</span>
                  <span className="text-[10px] tracking-widest uppercase text-amber-500/40 border border-amber-500/20 rounded-full px-3 py-1">
                    Solana .rs
                  </span>
                  <span className="text-white/20 text-xs">·</span>
                  <span className="text-[10px] tracking-widest uppercase text-white/20 border border-white/10 rounded-full px-3 py-1">
                    Multi .zip
                  </span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {dragging && (
          <div className="absolute inset-0 rounded-2xl bg-[#00ff88]/5 pointer-events-none" />
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
          className={`w-full py-3.5 rounded-xl text-sm font-semibold tracking-widest uppercase transition-all duration-300
            ${selectedFile
              ? fileType === "rust"
                ? "bg-amber-400 text-[#080b10] hover:bg-amber-300 shadow-[0_0_40px_rgba(245,158,11,0.2)] hover:shadow-[0_0_60px_rgba(245,158,11,0.3)] active:scale-[0.99]"
                : "bg-[#00ff88] text-[#080b10] hover:bg-[#00e57a] shadow-[0_0_40px_rgba(0,255,136,0.2)] hover:shadow-[0_0_60px_rgba(0,255,136,0.3)] active:scale-[0.99]"
              : "bg-white/[0.04] text-white/20 cursor-not-allowed border border-white/10"
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
          { icon: Zap,  label: "< 30s Analysis"          },
          { icon: Lock, label: "Never Stored"             },
          { icon: Eye,  label: "22+ Vulnerability Classes" },
        ].map(({ icon: Icon, label }) => (
          <div key={label} className="flex items-center gap-2 text-[11px] tracking-widest uppercase text-white/25">
            <Icon className="w-3 h-3 text-white/20" />
            {label}
          </div>
        ))}
      </motion.div>
    </div>
  );
}
