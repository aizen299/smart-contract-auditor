import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuditScan — Smart Contract Security Analysis",
  description:
    "AI-powered Solidity auditing. Upload your contract and get a comprehensive security report in seconds.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#080b10]">{children}</body>
    </html>
  );
}