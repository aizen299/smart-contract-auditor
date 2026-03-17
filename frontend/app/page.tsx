"use client";

import { useState } from "react";
import { UploadZone } from "@/components/UploadZone";
import { ScanResults } from "@/components/ScanResults";
import { ScanLoader } from "@/components/ScanLoader";
import { NavBar } from "@/components/NavBar";
import type { ScanResult } from "@/types";

type Stage = "idle" | "scanning" | "results";

export default function Home() {
  const [stage, setStage] = useState<Stage>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [fileName, setFileName] = useState<string>("");

  const handleScan = async (file: File) => {
    setFileName(file.name);
    setStage("scanning");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });
      const data: ScanResult = await res.json();
      setResult(data);
      setStage("results");
    } catch {
      // Demo fallback — remove in production
      await new Promise((r) => setTimeout(r, 3200));
      setResult(DEMO_RESULT);
      setStage("results");
    }
  };

  const handleReset = () => {
    setStage("idle");
    setResult(null);
    setFileName("");
  };

  return (
    <div className="min-h-screen bg-[#080b10] text-white font-mono">
      <NavBar onReset={stage !== "idle" ? handleReset : undefined} />

      <main className="relative">
        {stage === "idle" && <UploadZone onScan={handleScan} />}
        {stage === "scanning" && <ScanLoader fileName={fileName} />}
        {stage === "results" && result && (
          <ScanResults result={result} fileName={fileName} onRescan={handleReset} />
        )}
      </main>
    </div>
  );
}

const DEMO_RESULT: ScanResult = {
  risk_score: 78,
  findings: [
    {
      title: "Reentrancy Vulnerability",
      severity: "CRITICAL",
      description:
        "The withdraw() function updates the balance after transferring ETH, allowing a malicious contract to re-enter before state is updated. This can drain all contract funds.",
      fix: "Apply the Checks-Effects-Interactions pattern. Update internal state (balances[msg.sender] = 0) before making any external call.",
    },
    {
      title: "Integer Overflow in Token Minting",
      severity: "HIGH",
      description:
        "totalSupply += amount on line 84 is unchecked. If amount is crafted to overflow, totalSupply wraps to a small value, breaking accounting invariants.",
      fix: "Use Solidity 0.8.x built-in overflow checks, or wrap arithmetic in OpenZeppelin's SafeMath library.",
    },
    {
      title: "Unprotected Self-Destruct",
      severity: "HIGH",
      description:
        "selfdestruct(owner) can be called by anyone due to missing access control on the destroy() function. Attacker can permanently disable the contract.",
      fix: "Add onlyOwner modifier to the destroy() function. Consider removing selfdestruct entirely per EIP-6049 deprecation.",
    },
    {
      title: "Centralized Oracle Dependency",
      severity: "MEDIUM",
      description:
        "Price data relies on a single EOA-controlled oracle. This creates a single point of failure and manipulation risk.",
      fix: "Integrate a decentralized oracle like Chainlink with multiple data sources and heartbeat validation.",
    },
    {
      title: "Missing Event Emissions",
      severity: "LOW",
      description:
        "State-changing functions setOwner() and updateFee() do not emit events, making off-chain monitoring and audit trails impossible.",
      fix: "Define and emit appropriate events for all critical state changes.",
    },
  ],
};