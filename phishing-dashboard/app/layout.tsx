import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishNet SOC — Phishing Detection & Mitigation Platform",
  description: "Enterprise-grade phishing detection, investigation, and takedown coordination system.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="font-sans bg-slate-950 antialiased">
        {children}
      </body>
    </html>
  );
}
