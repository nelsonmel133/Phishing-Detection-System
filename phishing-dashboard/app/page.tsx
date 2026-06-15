"use client";

import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import {
  Shield, AlertTriangle, Eye, Activity, Search, Copy, CheckCheck,
  Globe, MessageSquare, Link2, Mail, Clock, TrendingUp, TrendingDown,
  Zap, Lock, Unlock, Terminal, Send, ChevronRight, AlertCircle,
  XCircle, CheckCircle, Minus, ExternalLink, Cpu, Network, Filter,
  RefreshCw, Info, BarChart2,
} from "lucide-react";

type RiskLevel = "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "CRITICAL";
type ChannelType = "URL" | "SMS" | "EMAIL" | "DOMAIN";

interface ScanPayload {
  id: string;
  trackingCode: string;
  timestamp: string;
  channel: ChannelType;
  rawInput: string;
  displayInput: string;
  riskScore: number;
  riskLevel: RiskLevel;
  targetBrand: string;
  registrar: string;
  registrarAbuse: string;
  ipAddress: string;
  country: string;
  createdAt: string;
  expiresAt: string;
  tlsValid: boolean;
  redirectChain: string[];
  indicators: string[];
  keyloggerDetected: boolean;
  formHarvestDetected: boolean;
  fakeBrand: string;
  fakeBrandColor: string;
  fakeBrandBg: string;
  takedownPriority: "URGENT" | "HIGH" | "MEDIUM" | "LOW";
}

interface LogEntry {
  id: string;
  timestamp: string;
  type: "INJECT" | "BLOCK" | "SCAN" | "ALERT" | "SYNC";
  message: string;
}

const SEED_PAYLOADS: ScanPayload[] = [
  {
    id: "1", trackingCode: "scn_9901", timestamp: "2025-06-15T08:42:11Z",
    channel: "URL", rawInput: "http://paypa1-secure-login.xyz/account/verify?token=8a3f91c",
    displayInput: "paypa1-secure-login.xyz", riskScore: 97, riskLevel: "CRITICAL",
    targetBrand: "PayPal", registrar: "NameCheap, Inc.", registrarAbuse: "abuse@namecheap.com",
    ipAddress: "185.220.101.47", country: "RU", createdAt: "2025-06-14T02:11:00Z",
    expiresAt: "2025-07-14T02:11:00Z", tlsValid: false,
    redirectChain: ["paypa1-secure-login.xyz", "185.220.101.47/redirect", "paypa1-secure-login.xyz/collect"],
    indicators: ["Homoglyph substitution (1→l)", "No TLS certificate", "Registered <48hrs ago", "IP flagged in AbuseIPDB", "Form harvesting script detected", "Keylogger payload in <head>"],
    keyloggerDetected: true, formHarvestDetected: true, fakeBrand: "PayPal",
    fakeBrandColor: "#003087", fakeBrandBg: "#009cde", takedownPriority: "URGENT",
  },
  {
    id: "2", trackingCode: "scn_9902", timestamp: "2025-06-15T08:39:05Z",
    channel: "SMS", rawInput: "Your HSBC account has been suspended. Verify now: https://bit.ly/3xHSBC-auth",
    displayInput: "bit.ly/3xHSBC-auth → hsbc-auth-verify.net", riskScore: 89, riskLevel: "MALICIOUS",
    targetBrand: "HSBC Bank", registrar: "GoDaddy LLC", registrarAbuse: "abuse@godaddy.com",
    ipAddress: "91.108.4.200", country: "NL", createdAt: "2025-06-13T17:44:00Z",
    expiresAt: "2025-07-13T17:44:00Z", tlsValid: true,
    redirectChain: ["bit.ly/3xHSBC-auth", "hsbc-auth-verify.net/login"],
    indicators: ["SMS smishing pattern", "URL shortener obfuscation", "Brand impersonation (HSBC)", "Urgency language trigger", "Credential harvesting form", "Geolocation-based redirect"],
    keyloggerDetected: false, formHarvestDetected: true, fakeBrand: "HSBC",
    fakeBrandColor: "#db0011", fakeBrandBg: "#ffffff", takedownPriority: "HIGH",
  },
  {
    id: "3", trackingCode: "scn_9903", timestamp: "2025-06-15T08:31:22Z",
    channel: "EMAIL", rawInput: "Your Microsoft 365 subscription expires today. Renew: http://m1crosoft-renew.com/365/renew",
    displayInput: "m1crosoft-renew.com", riskScore: 91, riskLevel: "CRITICAL",
    targetBrand: "Microsoft", registrar: "Tucows Domains Inc.", registrarAbuse: "domainabuse@tucows.com",
    ipAddress: "192.42.116.16", country: "DE", createdAt: "2025-06-15T01:03:00Z",
    expiresAt: "2025-07-15T01:03:00Z", tlsValid: false,
    redirectChain: ["m1crosoft-renew.com", "192.42.116.16/gate", "m1crosoft-renew.com/cc-capture"],
    indicators: ["Homoglyph attack (i→1)", "No TLS certificate", "Credit card capture endpoint", "Registered <12hrs ago", "MX record spoofing Microsoft domain"],
    keyloggerDetected: true, formHarvestDetected: true, fakeBrand: "Microsoft",
    fakeBrandColor: "#737373", fakeBrandBg: "#ffffff", takedownPriority: "URGENT",
  },
  {
    id: "4", trackingCode: "scn_9904", timestamp: "2025-06-15T08:24:47Z",
    channel: "URL", rawInput: "https://suspicious-download.io/chrome-update-v119.exe",
    displayInput: "suspicious-download.io", riskScore: 74, riskLevel: "SUSPICIOUS",
    targetBrand: "Google Chrome", registrar: "Porkbun LLC", registrarAbuse: "abuse@porkbun.com",
    ipAddress: "103.28.54.222", country: "SG", createdAt: "2025-06-11T09:15:00Z",
    expiresAt: "2026-06-11T09:15:00Z", tlsValid: true,
    redirectChain: ["suspicious-download.io/chrome-update-v119.exe"],
    indicators: ["Executable payload delivery", "Browser impersonation", "No code-signing certificate on binary", "Domain reputation score: 12/100"],
    keyloggerDetected: false, formHarvestDetected: false, fakeBrand: "Google",
    fakeBrandColor: "#4285F4", fakeBrandBg: "#f8f9fa", takedownPriority: "HIGH",
  },
  {
    id: "5", trackingCode: "scn_9905", timestamp: "2025-06-15T08:18:03Z",
    channel: "URL", rawInput: "https://github.com/anthropics/anthropic-sdk-python",
    displayInput: "github.com/anthropics/anthropic-sdk-python", riskScore: 2, riskLevel: "SAFE",
    targetBrand: "GitHub", registrar: "MarkMonitor Inc.", registrarAbuse: "abusecomplaints@markmonitor.com",
    ipAddress: "140.82.112.4", country: "US", createdAt: "2007-10-09T18:20:00Z",
    expiresAt: "2026-10-09T18:20:00Z", tlsValid: true,
    redirectChain: ["github.com/anthropics/anthropic-sdk-python"],
    indicators: ["Verified domain age: 17 years", "TLS valid", "Clean WHOIS"],
    keyloggerDetected: false, formHarvestDetected: false, fakeBrand: "GitHub",
    fakeBrandColor: "#24292e", fakeBrandBg: "#f6f8fa", takedownPriority: "LOW",
  },
  {
    id: "6", trackingCode: "scn_9906", timestamp: "2025-06-15T08:11:58Z",
    channel: "DOMAIN", rawInput: "amaz0n-prime-offers.club", displayInput: "amaz0n-prime-offers.club",
    riskScore: 83, riskLevel: "MALICIOUS", targetBrand: "Amazon", registrar: "NameSilo LLC",
    registrarAbuse: "abuse@namesilo.com", ipAddress: "45.33.32.156", country: "CN",
    createdAt: "2025-06-10T14:22:00Z", expiresAt: "2026-06-10T14:22:00Z", tlsValid: true,
    redirectChain: ["amaz0n-prime-offers.club", "amaz0n-prime-offers.club/deals/capture"],
    indicators: ["Homoglyph substitution (o→0)", "Suspicious TLD (.club)", "Amazon brand impersonation", "Credential harvesting", "Parked on malicious subnet"],
    keyloggerDetected: false, formHarvestDetected: true, fakeBrand: "Amazon",
    fakeBrandColor: "#ff9900", fakeBrandBg: "#131921", takedownPriority: "HIGH",
  },
];

const INITIAL_LOGS: LogEntry[] = [
  { id: "log_001", timestamp: "08:42:11", type: "ALERT", message: "CRITICAL threat detected — scn_9901 flagged for immediate review" },
  { id: "log_002", timestamp: "08:39:05", type: "SCAN",  message: "SMS smishing payload ingested — scn_9902 queued for analysis" },
  { id: "log_003", timestamp: "08:31:22", type: "ALERT", message: "CRITICAL threat detected — scn_9903 Microsoft impersonation active" },
  { id: "log_004", timestamp: "08:24:47", type: "SCAN",  message: "Suspicious download URL scanned — scn_9904 under review" },
  { id: "log_005", timestamp: "08:18:03", type: "SCAN",  message: "Clean URL confirmed safe — scn_9905 cleared" },
  { id: "log_006", timestamp: "08:11:58", type: "BLOCK", message: "Domain blocked at perimeter — amaz0n-prime-offers.club → NULL_ROUTE" },
  { id: "log_007", timestamp: "08:05:00", type: "SYNC",  message: "Threat intelligence feed synchronized — 4,812 new IOC entries" },
];

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}
function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}
function uid(): string { return Math.random().toString(36).slice(2, 10); }

function RiskBadge({ level, score }: { level: RiskLevel; score: number }) {
  const cfg = {
    CRITICAL:   "bg-red-500/20 text-red-400 border border-red-500/40 ring-1 ring-red-500/30",
    MALICIOUS:  "bg-orange-500/20 text-orange-400 border border-orange-500/40",
    SUSPICIOUS: "bg-amber-500/20 text-amber-400 border border-amber-500/40",
    SAFE:       "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40",
  }[level];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold tracking-widest uppercase ${cfg}`}>
      {level === "CRITICAL" && <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />}
      {score}% · {level}
    </span>
  );
}

function ChannelBadge({ type }: { type: ChannelType }) {
  const cfg = {
    URL:    { cls: "text-sky-400 bg-sky-400/10 border-sky-400/30",     Icon: Link2 },
    SMS:    { cls: "text-violet-400 bg-violet-400/10 border-violet-400/30", Icon: MessageSquare },
    EMAIL:  { cls: "text-pink-400 bg-pink-400/10 border-pink-400/30",  Icon: Mail },
    DOMAIN: { cls: "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",  Icon: Globe },
  }[type];
  const { Icon } = cfg;
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9px] font-mono font-bold uppercase tracking-widest ${cfg.cls}`}>
      <Icon size={9} />{type}
    </span>
  );
}

function StatusIcon({ level }: { level: RiskLevel }) {
  if (level === "SAFE")       return <CheckCircle  size={16} className="text-emerald-400 flex-shrink-0" />;
  if (level === "SUSPICIOUS") return <AlertTriangle size={16} className="text-amber-400 flex-shrink-0" />;
  if (level === "MALICIOUS")  return <AlertCircle  size={16} className="text-orange-400 flex-shrink-0" />;
  return <XCircle size={16} className="text-red-400 flex-shrink-0 animate-pulse" />;
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 90 ? "bg-red-500" : score >= 70 ? "bg-orange-500" : score >= 40 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="h-1 w-full bg-slate-700/60 rounded-full overflow-hidden">
      <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${score}%` }} />
    </div>
  );
}

function generateTakedownEmail(payload: ScanPayload): string {
  const date = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  return `To: ${payload.registrarAbuse}
Subject: URGENT — Phishing/Abuse Takedown Request for ${payload.displayInput}
Date: ${date}
Priority: ${payload.takedownPriority}

Dear ${payload.registrar} Abuse Team,

I am writing on behalf of our Security Operations Center (SOC) to formally 
request the immediate suspension and takedown of the following malicious domain 
actively engaged in phishing operations targeting ${payload.targetBrand} customers.

━━ ABUSE DETAILS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Domain / URL:    ${payload.rawInput}
Hosting IP:      ${payload.ipAddress}
Country:         ${payload.country}
Registrar:       ${payload.registrar}
TLS Certificate: ${payload.tlsValid ? "Valid (Misused)" : "ABSENT"}
Detection Date:  ${new Date(payload.timestamp).toUTCString()}
Risk Score:      ${payload.riskScore}/100 (${payload.riskLevel})
Scan ID:         ${payload.trackingCode}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

THREAT DESCRIPTION:
This domain is actively impersonating ${payload.targetBrand} to harvest user 
credentials and financial data. Our automated detection pipeline has confirmed 
the following malicious indicators:

${payload.indicators.map((i, idx) => `  ${idx + 1}. ${i}`).join("\n")}

${payload.keyloggerDetected ? "⚠ CRITICAL: Active keylogging script detected on this domain.\n" : ""}${payload.formHarvestDetected ? "⚠ CRITICAL: Form data harvesting endpoint actively exfiltrating credentials.\n" : ""}
REDIRECT CHAIN (Observed):
${payload.redirectChain.map((r, i) => `  [${i + 1}] ${r}`).join("\n → ")}

REQUESTED ACTIONS:
  1. Immediate suspension of domain registration: ${payload.displayInput}
  2. Null-routing of IP address ${payload.ipAddress}
  3. Preservation of WHOIS and server logs for law enforcement
  4. Confirmation of takedown action within 4 hours of receipt

This phishing campaign is causing active harm to consumers. We request your 
fastest possible action under your Acceptable Use Policy (AUP) and applicable 
provisions of the ICANN Registrar Accreditation Agreement (RAA §3.18).

Relevant reporting references:
  • Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/
  • PhishTank Report: https://www.phishtank.com/
  • APWG eCrime Report: https://apwg.org/

We are prepared to provide additional forensic evidence upon request.

Regards,

Security Operations Center
Phishing Detection & Mitigation Platform
Incident Reference: ${payload.trackingCode.toUpperCase()}-TKD-${Date.now().toString(36).toUpperCase()}`;
}

function SandboxPreview({ payload }: { payload: ScanPayload }) {
  if (payload.riskLevel === "SAFE") {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-3 text-emerald-400/60">
        <CheckCircle size={40} />
        <p className="font-mono text-sm">No threat signature — safe target</p>
        <p className="text-xs text-slate-500 font-mono">{payload.rawInput}</p>
      </div>
    );
  }
  return (
    <div className="flex flex-col h-full">
      <div className="bg-slate-700/80 px-3 py-2 flex items-center gap-2 rounded-t border border-slate-600/50 border-b-0">
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500/70" />
          <span className="w-3 h-3 rounded-full bg-amber-500/70" />
          <span className="w-3 h-3 rounded-full bg-emerald-500/40" />
        </div>
        <div className="flex-1 flex items-center gap-2 bg-slate-800/80 rounded px-2 py-1">
          <Lock size={10} className="text-amber-400" />
          <span className="font-mono text-[10px] text-slate-400 truncate">{payload.rawInput}</span>
        </div>
        <ExternalLink size={11} className="text-slate-500" />
      </div>
      <div className="bg-red-900/60 border border-red-500/50 border-b-0 px-3 py-2 flex items-start gap-2">
        <AlertTriangle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-red-300 text-[10px] font-bold font-mono uppercase tracking-wider">
            ⚠ Sandboxed Threat Render — Analyst View Only
          </p>
          <p className="text-red-400/80 text-[9px] font-mono mt-0.5">
            This is a structural mockup reconstruction. No live resources have been loaded.
            {payload.keyloggerDetected && " Keylogger script payload isolated."}
            {payload.formHarvestDetected && " Form harvesting intercepted."}
          </p>
        </div>
      </div>
      <div className="flex-1 border border-slate-600/50 rounded-b bg-white overflow-hidden relative min-h-0">
        <div className="px-4 py-2.5 flex items-center justify-between"
          style={{ backgroundColor: payload.fakeBrandBg, borderBottom: `2px solid ${payload.fakeBrandColor}` }}>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-sm flex items-center justify-center font-bold text-white text-xs"
              style={{ backgroundColor: payload.fakeBrandColor }}>
              {payload.fakeBrand[0]}
            </div>
            <span className="font-bold text-xs" style={{ color: payload.fakeBrandColor }}>{payload.fakeBrand}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-12 h-2 rounded-full bg-gray-200" />
            <div className="w-10 h-2 rounded-full bg-gray-200" />
          </div>
        </div>
        <div className="p-4 flex flex-col gap-3"
          style={{ backgroundColor: payload.fakeBrandBg === "#ffffff" ? "#f5f5f5" : "#1a1a2e" }}>
          <div className="bg-white rounded shadow-sm p-4 mx-auto w-full max-w-xs">
            <div className="text-center mb-3">
              <div className="w-8 h-8 rounded mx-auto mb-2 flex items-center justify-center font-bold text-white text-sm"
                style={{ backgroundColor: payload.fakeBrandColor }}>
                {payload.fakeBrand[0]}
              </div>
              <div className="h-2.5 rounded w-32 mx-auto mb-1" style={{ backgroundColor: "#1a1a1a" }} />
              <div className="h-1.5 bg-gray-400 rounded w-24 mx-auto" />
            </div>
            <div className="space-y-2">
              <div className="h-7 bg-gray-100 border border-gray-300 rounded px-2 flex items-center">
                <div className="h-1.5 bg-gray-300 rounded w-20" />
              </div>
              <div className="h-7 bg-gray-100 border border-gray-300 rounded px-2 flex items-center">
                <div className="h-1.5 bg-gray-300 rounded w-16" />
              </div>
              <div className="h-7 rounded flex items-center justify-center" style={{ backgroundColor: payload.fakeBrandColor }}>
                <div className="h-1.5 bg-white/60 rounded w-12" />
              </div>
            </div>
          </div>
          {payload.keyloggerDetected && (
            <div className="bg-red-900/90 border border-red-500 rounded px-2 py-1.5 flex items-center gap-2">
              <Cpu size={10} className="text-red-400 flex-shrink-0" />
              <span className="text-red-300 text-[9px] font-mono">KEYLOGGER ACTIVE — document.addEventListener('keydown') intercepted</span>
            </div>
          )}
          {payload.formHarvestDetected && (
            <div className="bg-orange-900/90 border border-orange-500 rounded px-2 py-1.5 flex items-center gap-2">
              <Network size={10} className="text-orange-400 flex-shrink-0" />
              <span className="text-orange-300 text-[9px] font-mono">DATA EXFIL — POST /collect → {payload.ipAddress} detected</span>
            </div>
          )}
          {!payload.tlsValid && (
            <div className="bg-amber-900/90 border border-amber-500 rounded px-2 py-1.5 flex items-center gap-2">
              <Unlock size={10} className="text-amber-400 flex-shrink-0" />
              <span className="text-amber-300 text-[9px] font-mono">NO TLS — Plaintext credential transmission in progress</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function PhishingDashboard() {
  const [payloads] = useState<ScanPayload[]>(SEED_PAYLOADS);
  const [selectedId, setSelectedId] = useState<string>("1");
  const [searchQuery, setSearchQuery] = useState("");
  const [copyState, setCopyState] = useState<"idle" | "copied">("idle");
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_LOGS);
  const [injectValue, setInjectValue] = useState("");
  const [injectLoading, setInjectLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"diagnostics" | "sandbox">("diagnostics");
  const [pulseKey, setPulseKey] = useState(0);
  const logEndRef = useRef<HTMLDivElement>(null);

  const selected = useMemo(() => payloads.find((p) => p.id === selectedId) ?? payloads[0], [payloads, selectedId]);

  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase();
    if (!q) return payloads;
    return payloads.filter((p) =>
      p.trackingCode.toLowerCase().includes(q) ||
      p.rawInput.toLowerCase().includes(q) ||
      p.displayInput.toLowerCase().includes(q) ||
      p.targetBrand.toLowerCase().includes(q) ||
      p.riskLevel.toLowerCase().includes(q)
    );
  }, [payloads, searchQuery]);

  const metrics = useMemo(() => {
    const total = payloads.length;
    const malicious = payloads.filter((p) => p.riskLevel === "MALICIOUS" || p.riskLevel === "CRITICAL").length;
    const suspicious = payloads.filter((p) => p.riskLevel === "SUSPICIOUS").length;
    const meanRisk = Math.round(payloads.reduce((sum, p) => sum + p.riskScore, 0) / total);
    return { total, malicious, suspicious, meanRisk };
  }, [payloads]);

  const takedownEmail = useMemo(() => generateTakedownEmail(selected), [selected]);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(takedownEmail);
    setCopyState("copied");
    setTimeout(() => setCopyState("idle"), 2000);
  }, [takedownEmail]);

  const handleInject = useCallback(() => {
    if (!injectValue.trim()) return;
    setInjectLoading(true);
    setTimeout(() => {
      const entry: LogEntry = {
        id: `log_${uid()}`, timestamp: now(), type: "INJECT",
        message: `Rule injected — domain "${injectValue.trim()}" → NULL_ROUTE applied across all 6 edge nodes`,
      };
      setLogs((prev) => [entry, ...prev]);
      setInjectValue("");
      setInjectLoading(false);
      setPulseKey((k) => k + 1);
      if (typeof window !== "undefined") {
        window.alert(`✅ Injection Successful\n\nDomain: ${injectValue.trim()}\nStatus: NULL_ROUTE applied\nNodes synced: 6/6\nTimestamp: ${now()}`);
      }
    }, 800);
  }, [injectValue]);

  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  const logTypeStyle: Record<LogEntry["type"], string> = {
    INJECT: "text-cyan-400", BLOCK: "text-red-400", SCAN: "text-sky-400",
    ALERT: "text-amber-400", SYNC: "text-emerald-400",
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* ── Header ── */}
      <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur border-b border-slate-800/60">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-shrink-0">
              <div className="w-9 h-9 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <Shield size={18} className="text-red-400" />
              </div>
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full animate-pulse border-2 border-slate-950" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-slate-100 leading-none">
                PhishNet <span className="text-red-400">SOC</span>
              </h1>
              <p className="text-[10px] text-slate-500 font-mono tracking-wider mt-0.5">
                PHISHING DETECTION & MITIGATION PLATFORM v4.2.1
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-4 text-[10px] font-mono text-slate-500">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>LIVE FEED ACTIVE</span>
            </div>
            <div className="h-3 w-px bg-slate-700" />
            <div className="flex items-center gap-1.5">
              <Activity size={11} className="text-sky-400" />
              <span className="text-slate-400">6 EDGE NODES SYNC</span>
            </div>
            <div className="h-3 w-px bg-slate-700" />
            <div className="flex items-center gap-1.5 text-slate-400">
              <Clock size={11} />
              <span suppressHydrationWarning>{new Date().toUTCString().slice(0, 25)} UTC</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono font-semibold bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 rounded transition-colors">
              <RefreshCw size={11} />REFRESH
            </button>
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono font-semibold bg-red-500/10 hover:bg-red-500/20 border border-red-500/40 text-red-400 rounded transition-colors">
              <Zap size={11} />ESCALATE
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-[1920px] mx-auto px-4 sm:px-6 py-5 space-y-5">

        {/* ── Metrics Ticker ── */}
        <section className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          <div className="bg-slate-900 border border-slate-800/60 rounded-xl p-4 flex flex-col gap-2 hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Total Scans Parsed</span>
              <TrendingUp size={13} className="text-sky-400" />
            </div>
            <div className="text-3xl font-bold font-mono text-slate-100 tracking-tight">
              {metrics.total.toLocaleString()}<span className="text-sm text-slate-500 font-normal ml-1">scans</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-emerald-400 font-mono">↑ +12.4%</span>
              <span className="text-[10px] text-slate-600 font-mono">vs. 24h prior</span>
            </div>
            <RiskBar score={42} />
          </div>
          <div className="bg-slate-900 border border-red-500/30 rounded-xl p-4 flex flex-col gap-2 shadow-[0_0_16px_rgba(239,68,68,0.06)]">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-red-400/70 uppercase tracking-widest">Malicious Flagged</span>
              <XCircle size={13} className="text-red-400" />
            </div>
            <div className="text-3xl font-bold font-mono text-red-400 tracking-tight">
              {metrics.malicious.toLocaleString()}<span className="text-sm text-red-600 font-normal ml-1">targets</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-red-400 font-mono">↑ +3 CRITICAL</span>
              <span className="text-[10px] text-slate-600 font-mono">last 1h</span>
            </div>
            <div className="h-1 w-full bg-slate-700/60 rounded-full overflow-hidden">
              <div className="h-full bg-red-500 rounded-full animate-pulse" style={{ width: `${(metrics.malicious / metrics.total) * 100}%` }} />
            </div>
          </div>
          <div className="bg-slate-900 border border-amber-500/25 rounded-xl p-4 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-amber-400/70 uppercase tracking-widest">Under Review</span>
              <Eye size={13} className="text-amber-400" />
            </div>
            <div className="text-3xl font-bold font-mono text-amber-400 tracking-tight">
              {metrics.suspicious.toLocaleString()}<span className="text-sm text-amber-600 font-normal ml-1">pending</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-amber-400 font-mono">→ QUEUED</span>
              <span className="text-[10px] text-slate-600 font-mono">analyst review</span>
            </div>
            <div className="h-1 w-full bg-slate-700/60 rounded-full overflow-hidden">
              <div className="h-full bg-amber-500 rounded-full" style={{ width: `${(metrics.suspicious / metrics.total) * 100}%` }} />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800/60 rounded-xl p-4 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Mean Risk Index</span>
              <BarChart2 size={13} className="text-slate-400" />
            </div>
            <div className="text-3xl font-bold font-mono tracking-tight" style={{
              color: metrics.meanRisk >= 70 ? "#f87171" : metrics.meanRisk >= 40 ? "#fbbf24" : "#34d399"
            }}>
              {metrics.meanRisk}%<span className="text-sm font-normal ml-1 text-slate-500">RSI</span>
            </div>
            <div className="flex items-center gap-1.5">
              <TrendingDown size={11} className="text-emerald-400" />
              <span className="text-[10px] text-slate-600 font-mono">PORTFOLIO RISK SCORE</span>
            </div>
            <RiskBar score={metrics.meanRisk} />
          </div>
        </section>

        {/* ── Main Grid ── */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">

          {/* ── Left: Threat Stream ── */}
          <aside className="xl:col-span-4 flex flex-col gap-3">
            <div className="bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800/60 bg-slate-900/80">
                <div className="flex items-center gap-2">
                  <Activity size={13} className="text-red-400" />
                  <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-widest">Live Threat Stream</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] font-mono text-slate-600">{filtered.length}/{payloads.length} NODES</span>
                  <Filter size={11} className="text-slate-600" />
                </div>
              </div>
              <div className="px-3 py-2.5 border-b border-slate-800/40 bg-slate-950/40">
                <div className="relative">
                  <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter by ID, domain, brand, risk level..."
                    className="w-full bg-slate-800/60 border border-slate-700/50 rounded-lg pl-8 pr-3 py-2 text-[11px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/20 transition-all"
                  />
                </div>
              </div>
              <div className="divide-y divide-slate-800/40 max-h-[calc(100vh-360px)] overflow-y-auto">
                {filtered.length === 0 && (
                  <div className="px-4 py-8 text-center text-slate-600 text-xs font-mono">No payloads match filter</div>
                )}
                {filtered.map((payload) => (
                  <button key={payload.id} onClick={() => setSelectedId(payload.id)}
                    className={`w-full text-left px-4 py-3 transition-all group hover:bg-slate-800/40 ${
                      selectedId === payload.id ? "bg-slate-800/60 border-l-2 border-sky-500" : "border-l-2 border-transparent"
                    }`}>
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2 min-w-0">
                        <StatusIcon level={payload.riskLevel} />
                        <span className="text-[10px] font-mono font-bold text-slate-400 tracking-wider flex-shrink-0">{payload.trackingCode}</span>
                        <ChannelBadge type={payload.channel} />
                      </div>
                      <span className="text-[9px] font-mono text-slate-600 flex-shrink-0">{formatTimestamp(payload.timestamp)}</span>
                    </div>
                    <p className="text-[11px] text-slate-300 font-mono truncate mb-1.5 leading-relaxed">{payload.displayInput}</p>
                    <div className="flex items-center justify-between gap-2">
                      <RiskBadge level={payload.riskLevel} score={payload.riskScore} />
                      <div className="flex items-center gap-1 text-[9px] font-mono text-slate-600">
                        <Globe size={9} />{payload.targetBrand}
                      </div>
                    </div>
                    {selectedId === payload.id && (
                      <div className="mt-1.5 flex items-center gap-1 text-[9px] text-sky-400 font-mono">
                        <ChevronRight size={9} />ACTIVE INVESTIGATION
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </aside>

          {/* ── Right: Workspace ── */}
          <section className="xl:col-span-8 flex flex-col gap-4">
            <div className="bg-slate-900 border border-slate-800/60 rounded-xl px-5 py-4">
              <div className="flex flex-wrap items-start gap-3 justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Active Investigation</span>
                    <span className="text-[10px] font-mono text-slate-600">›</span>
                    <span className="text-[10px] font-mono text-sky-400 font-bold">{selected.trackingCode}</span>
                    <ChannelBadge type={selected.channel} />
                    <RiskBadge level={selected.riskLevel} score={selected.riskScore} />
                  </div>
                  <p className="text-sm font-mono text-slate-200 mt-1 truncate max-w-lg">{selected.rawInput}</p>
                </div>
                <span className={`text-[10px] font-mono px-2 py-1 rounded border flex-shrink-0 ${
                  selected.takedownPriority === "URGENT" ? "text-red-400 border-red-500/40 bg-red-500/10"
                  : selected.takedownPriority === "HIGH" ? "text-orange-400 border-orange-500/40 bg-orange-500/10"
                  : "text-amber-400 border-amber-500/40 bg-amber-500/10"
                }`}>
                  ↑ {selected.takedownPriority} PRIORITY
                </span>
              </div>
            </div>

            {/* Tab switcher */}
            <div className="flex bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden">
              <button onClick={() => setActiveTab("diagnostics")}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-xs font-mono font-semibold uppercase tracking-widest transition-all ${
                  activeTab === "diagnostics" ? "bg-slate-800 text-sky-400 border-b-2 border-sky-500" : "text-slate-500 hover:text-slate-400 hover:bg-slate-800/30"
                }`}>
                <Info size={12} />Diagnostics & Mitigation
              </button>
              <button onClick={() => setActiveTab("sandbox")}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-xs font-mono font-semibold uppercase tracking-widest transition-all ${
                  activeTab === "sandbox" ? "bg-slate-800 text-amber-400 border-b-2 border-amber-500" : "text-slate-500 hover:text-slate-400 hover:bg-slate-800/30"
                }`}>
                <Eye size={12} />Sandbox Preview
              </button>
            </div>

            {activeTab === "diagnostics" ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Metadata */}
                <div className="bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800/60 flex items-center gap-2">
                    <Cpu size={12} className="text-sky-400" />
                    <span className="text-[10px] font-mono font-semibold text-slate-300 uppercase tracking-widest">Metadata & Risk Factors</span>
                  </div>
                  <div className="p-4 space-y-4">
                    <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                      {[
                        { label: "Scan ID",       value: selected.trackingCode },
                        { label: "Target Brand",  value: selected.targetBrand },
                        { label: "Hosting IP",    value: selected.ipAddress },
                        { label: "Origin Country",value: selected.country },
                        { label: "Registrar",     value: selected.registrar },
                        { label: "Abuse Email",   value: selected.registrarAbuse },
                        { label: "Reg. Date",     value: new Date(selected.createdAt).toLocaleDateString() },
                        { label: "Expires",       value: new Date(selected.expiresAt).toLocaleDateString() },
                      ].map(({ label, value }) => (
                        <div key={label}>
                          <dt className="text-[9px] font-mono text-slate-600 uppercase tracking-widest mb-0.5">{label}</dt>
                          <dd className="text-[11px] font-mono text-slate-300 truncate">{value}</dd>
                        </div>
                      ))}
                    </div>
                    <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/40">
                      <span className={`flex items-center gap-1 text-[9px] font-mono px-2 py-1 rounded border ${
                        selected.tlsValid ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" : "text-red-400 border-red-500/30 bg-red-500/10"
                      }`}>
                        {selected.tlsValid ? <Lock size={9} /> : <Unlock size={9} />}
                        TLS: {selected.tlsValid ? "VALID" : "ABSENT"}
                      </span>
                      <span className={`flex items-center gap-1 text-[9px] font-mono px-2 py-1 rounded border ${
                        selected.keyloggerDetected ? "text-red-400 border-red-500/30 bg-red-500/10" : "text-slate-500 border-slate-700 bg-slate-800"
                      }`}>
                        <Cpu size={9} />KEYLOGGER: {selected.keyloggerDetected ? "DETECTED" : "NONE"}
                      </span>
                      <span className={`flex items-center gap-1 text-[9px] font-mono px-2 py-1 rounded border ${
                        selected.formHarvestDetected ? "text-orange-400 border-orange-500/30 bg-orange-500/10" : "text-slate-500 border-slate-700 bg-slate-800"
                      }`}>
                        <Network size={9} />FORM HARVEST: {selected.formHarvestDetected ? "ACTIVE" : "NONE"}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-slate-800/40">
                      <p className="text-[9px] font-mono text-slate-600 uppercase tracking-widest mb-1.5">Redirect Chain</p>
                      <div className="space-y-1">
                        {selected.redirectChain.map((hop, i) => (
                          <div key={i} className="flex items-center gap-2">
                            {i > 0 && <div className="w-px h-3 bg-slate-700 ml-1.5 -mt-1" />}
                            <div className={`flex items-center gap-1.5 text-[10px] font-mono rounded px-2 py-1 ${
                              i === 0 ? "bg-slate-800 text-sky-400"
                              : i === selected.redirectChain.length - 1 ? "bg-red-900/30 text-red-400 border border-red-500/20"
                              : "bg-slate-800/60 text-slate-400"
                            }`}>
                              <span className="text-[8px] text-slate-600">[{i + 1}]</span>{hop}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="pt-2 border-t border-slate-800/40">
                      <p className="text-[9px] font-mono text-slate-600 uppercase tracking-widest mb-1.5">Threat Indicators</p>
                      <ul className="space-y-1">
                        {selected.indicators.map((ind, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-[10px] font-mono text-slate-400">
                            <Minus size={9} className="text-red-500/70 mt-0.5 flex-shrink-0" />{ind}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Takedown email */}
                <div className="bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden flex flex-col">
                  <div className="px-4 py-3 border-b border-slate-800/60 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Mail size={12} className="text-emerald-400" />
                      <span className="text-[10px] font-mono font-semibold text-slate-300 uppercase tracking-widest">Registrar Abuse Takedown Email</span>
                    </div>
                    <button onClick={handleCopy}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono font-semibold transition-all ${
                        copyState === "copied"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : "bg-slate-800 text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-slate-100"
                      }`}>
                      {copyState === "copied" ? <><CheckCheck size={10} /> COPIED!</> : <><Copy size={10} /> COPY TEMPLATE</>}
                    </button>
                  </div>
                  <div className="flex-1 overflow-auto">
                    <pre className="p-4 text-[9.5px] font-mono text-slate-400 leading-relaxed whitespace-pre-wrap break-words">
                      {takedownEmail}
                    </pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden" style={{ minHeight: "500px" }}>
                <div className="px-4 py-3 border-b border-slate-800/60 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Eye size={12} className="text-amber-400" />
                    <span className="text-[10px] font-mono font-semibold text-slate-300 uppercase tracking-widest">Secure Sandbox Container Preview</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[9px] font-mono text-amber-400/70">
                    <AlertTriangle size={10} />ISOLATED · NO LIVE RESOURCES
                  </div>
                </div>
                <div className="p-4" style={{ height: "480px" }}>
                  <SandboxPreview payload={selected} />
                </div>
              </div>
            )}
          </section>
        </div>

        {/* ── Bottom Control Block ── */}
        <section className="bg-slate-900 border border-slate-800/60 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800/60 flex items-center gap-2 bg-slate-950/40">
            <Terminal size={13} className="text-cyan-400" />
            <span className="text-[10px] font-mono font-semibold text-slate-300 uppercase tracking-widest">
              Global Infrastructure Direct Injection
            </span>
            <div className="ml-auto flex items-center gap-1.5 text-[9px] font-mono text-emerald-400/70">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              FIREWALL ACTIVE — 6/6 NODES SYNCED
            </div>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-0 divide-y xl:divide-y-0 xl:divide-x divide-slate-800/40">
            <div className="p-5 flex flex-col gap-4">
              <div>
                <label className="block text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-2">
                  Malicious Domain / URL String
                </label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Globe size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                    <input type="text" value={injectValue} onChange={(e) => setInjectValue(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleInject()}
                      placeholder="e.g. malicious-domain-example.xyz"
                      className="w-full bg-slate-800/60 border border-slate-700/60 rounded-lg pl-8 pr-4 py-2.5 text-[11px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    />
                  </div>
                  <button onClick={handleInject} disabled={!injectValue.trim() || injectLoading}
                    className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed border border-cyan-500/40 hover:border-cyan-400/60 text-cyan-400 rounded-lg text-[10px] font-mono font-bold uppercase tracking-widest transition-all flex-shrink-0">
                    {injectLoading ? <><RefreshCw size={11} className="animate-spin" /> SYNCING</> : <><Send size={11} /> INJECT RULE</>}
                  </button>
                </div>
                <p className="text-[9px] font-mono text-slate-600 mt-2">
                  Rule will be null-routed across all 6 edge nodes. Press Enter or click Inject Rule. A browser confirmation will appear on sync.
                </p>
              </div>
              <div>
                <p className="text-[9px] font-mono text-slate-600 uppercase tracking-widest mb-2">Quick Inject From Queue</p>
                <div className="flex flex-wrap gap-2">
                  {payloads.filter((p) => p.riskLevel !== "SAFE").map((p) => (
                    <button key={p.id} onClick={() => setInjectValue(p.displayInput)}
                      className="text-[9px] font-mono px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-400 hover:text-slate-300 transition-all">
                      {p.trackingCode}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="p-5 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest">System Firewall Activity Log</p>
                <span className="text-[9px] font-mono text-slate-600">{logs.length} ENTRIES</span>
              </div>
              <div key={pulseKey}
                className="bg-slate-950 border border-slate-800/60 rounded-lg p-3 h-40 overflow-y-auto font-mono text-[10px] space-y-1.5 scroll-smooth">
                {logs.map((log) => (
                  <div key={log.id} className="flex items-start gap-2 leading-relaxed">
                    <span className="text-slate-700 flex-shrink-0">{log.timestamp}</span>
                    <span className={`flex-shrink-0 font-bold ${logTypeStyle[log.type]}`}>[{log.type}]</span>
                    <span className="text-slate-400">{log.message}</span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
              <p className="text-[9px] font-mono text-slate-700">
                ▸ All activity logged to immutable audit trail · Encrypted at rest (AES-256)
              </p>
            </div>
          </div>
        </section>

        <footer className="flex items-center justify-between text-[9px] font-mono text-slate-700 pb-4">
          <span>PhishNet SOC Platform · Build 4.2.1-stable · © 2025 Security Operations</span>
          <span>All data is simulated for demonstration purposes · Analyst Workstation Mode</span>
        </footer>
      </main>
    </div>
  );
}
