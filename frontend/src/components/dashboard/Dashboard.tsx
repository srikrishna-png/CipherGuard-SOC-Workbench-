import React, { useState } from 'react';
import { 
  Shield, Terminal, Database, Bot, ArrowRight, Search, Zap, 
  Activity, ShieldAlert, Lock, Bell, Network, Cpu, Globe, CheckCircle2
} from 'lucide-react';
import { SUITES_CATALOG } from '../../data/toolsRegistry';
import { ToolMetadata } from '../../types';
import { CyberButton } from '../ui/CyberButton';
import { GlitchText } from '../ui/GlitchText';

interface DashboardProps {
  onSelectTool: (tool: ToolMetadata) => void;
  onOpenWorkbench: () => void;
  onOpenLedger: () => void;
  onOpenAIAssistant: () => void;
  onOpenSearch: () => void;
}

const SUITE_ICON_MAP: Record<string, React.ElementType> = {
  Search,
  Activity,
  ShieldAlert,
  Lock,
  Bell,
  Network,
  Cpu,
  Globe
};

export const Dashboard: React.FC<DashboardProps> = ({
  onSelectTool,
  onOpenWorkbench,
  onOpenLedger,
  onOpenAIAssistant,
  onOpenSearch
}) => {
  const [heroSearch, setHeroSearch] = useState('');

  // Search results for hero search input
  const allTools = React.useMemo(() => {
    return SUITES_CATALOG.flatMap(s => s.tools.map(t => ({ ...t, suiteName: s.name })));
  }, []);

  const searchResults = React.useMemo(() => {
    if (!heroSearch.trim()) return [];
    const q = heroSearch.toLowerCase().trim();
    return allTools.filter(t => 
      t.name.toLowerCase().includes(q) || 
      t.description.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q)
    ).slice(0, 6);
  }, [allTools, heroSearch]);

  // Featured quick launch tools
  const pinnedToolIds = [
    'url_analyzer', 
    'beaconing_analyzer', 
    'yara_generator', 
    'subnet_calculator', 
    'case_timeline_builder', 
    'report_generator'
  ];
  const pinnedTools = allTools.filter(t => pinnedToolIds.includes(t.id));

  return (
    <div className="relative min-h-screen bg-[#09090b] text-zinc-100 pb-20 pt-16 overflow-hidden">
      {/* Background Matrix Grid Pattern */}
      <div className="absolute inset-0 bg-grid-cyber pointer-events-none -z-10 [mask-image:radial-gradient(ellipse_60%_50%_at_50%_35%,#000_70%,transparent_100%)]" />

      {/* Ambient Glowing Orbs */}
      <div className="absolute top-1/6 left-1/5 w-96 h-96 bg-emerald-500/15 blur-[130px] rounded-full pointer-events-none -z-10 animate-pulse-glow" />
      <div className="absolute top-1/3 right-1/5 w-96 h-96 bg-cyan-500/15 blur-[140px] rounded-full pointer-events-none -z-10 animate-pulse-glow" />

      {/* HERO SECTION */}
      <section className="relative px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto pt-10 pb-16 flex flex-col items-center text-center">
        {/* Systems Online Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-emerald-500/40 bg-emerald-950/40 text-emerald-400 text-xs font-mono mb-8 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <Shield size={14} /> SYSTEMS ONLINE // DEFENSIVE SOC ACTIVE
        </div>

        {/* Hero Title with Glitch Effect */}
        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black font-mono tracking-tight max-w-5xl leading-[1.1] mb-6">
          Master the Frontlines of <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-teal-300">
            <GlitchText text="Autonomous Cyber Defense" className="text-emerald-400" />
          </span>
        </h1>

        {/* Subtitle */}
        <p className="text-base sm:text-lg text-zinc-400 max-w-3xl mb-8 leading-relaxed font-sans">
          CipherGuard is a unified enterprise-grade defensive cybersecurity operations workbench. 
          Consolidating <strong>80 specialized triage tools</strong> across <strong>8 security suites</strong> with a standardized 
          5-layer explanation model and a <strong>SHA-256 tamper-evident cryptographic ledger</strong>.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-4 mb-12">
          <CyberButton 
            variant="primary" 
            size="lg" 
            onClick={onOpenWorkbench}
            className="w-full sm:w-auto"
          >
            Launch Workbench <ArrowRight size={18} />
          </CyberButton>
          <CyberButton 
            variant="cyan" 
            size="lg" 
            onClick={onOpenAIAssistant}
            className="w-full sm:w-auto"
          >
            <Bot size={18} /> Ask AI Copilot
          </CyberButton>
          <CyberButton 
            variant="secondary" 
            size="lg" 
            onClick={onOpenLedger}
            className="w-full sm:w-auto"
          >
            <Database size={18} /> Audit Ledger
          </CyberButton>
        </div>

        {/* Live Hero Search Input */}
        <div className="w-full max-w-2xl relative mb-4">
          <div className="relative flex items-center">
            <Search className="w-5 h-5 text-emerald-400 absolute left-4 pointer-events-none" />
            <input
              type="text"
              value={heroSearch}
              onChange={(e) => setHeroSearch(e.target.value)}
              placeholder="Instant tool search (e.g. YARA, Beaconing, Subnet, JWT, Phishing)..."
              className="w-full pl-12 pr-28 py-3.5 rounded-xl bg-zinc-900/90 border border-zinc-700/80 text-sm text-zinc-100 placeholder-zinc-500 font-mono focus:outline-none focus:border-emerald-500 focus:shadow-[0_0_20px_rgba(16,185,129,0.25)] transition-all"
            />
            <button
              onClick={onOpenSearch}
              className="absolute right-2.5 px-2.5 py-1 text-xs font-mono text-zinc-400 bg-zinc-800 rounded border border-zinc-700 hover:text-zinc-200 hover:bg-zinc-700 transition-colors"
            >
              Ctrl+K
            </button>
          </div>

          {/* Quick Search Dropdown Preview */}
          {searchResults.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl overflow-hidden z-20 text-left">
              {searchResults.map(tool => (
                <button
                  key={tool.id}
                  onClick={() => {
                    onSelectTool(tool);
                    setHeroSearch('');
                  }}
                  className="w-full flex items-center justify-between p-3 hover:bg-zinc-800/80 border-b border-zinc-800/60 last:border-0 transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <div>
                      <div className="text-xs font-bold text-zinc-200">{tool.name}</div>
                      <div className="text-[11px] text-zinc-400 truncate max-w-md">{tool.description}</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400/80 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/40">
                    Open Tool
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* TELEMETRY STATS STRIP */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-16">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm flex items-center gap-3.5">
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-black font-mono text-zinc-100">80 / 80</div>
              <div className="text-xs text-zinc-400 font-mono">Tools Fully Operational</div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm flex items-center gap-3.5">
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-black font-mono text-zinc-100">8 Suites</div>
              <div className="text-xs text-zinc-400 font-mono">Defense & Triage Domains</div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm flex items-center gap-3.5">
            <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-black font-mono text-zinc-100">100% Valid</div>
              <div className="text-xs text-zinc-400 font-mono">SHA-256 Chained Ledger</div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm flex items-center gap-3.5">
            <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-black font-mono text-zinc-100">&lt; 15 ms</div>
              <div className="text-xs text-zinc-400 font-mono">Async Engine Latency</div>
            </div>
          </div>
        </div>
      </section>

      {/* QUICK-START LAUNCHPAD */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-16">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-emerald-400" />
            <h2 className="text-base font-mono font-bold uppercase tracking-wider text-zinc-200">
              High-Frequency Triage Launchpad
            </h2>
          </div>
          <button 
            onClick={onOpenSearch}
            className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
          >
            Browse all 80 tools <ArrowRight size={14} />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {pinnedTools.map(tool => (
            <button
              key={tool.id}
              onClick={() => onSelectTool(tool)}
              className="p-4 rounded-xl bg-zinc-900/50 border border-zinc-800/90 hover:border-emerald-500/50 hover:bg-zinc-850 hover:shadow-[0_0_20px_rgba(16,185,129,0.12)] text-left transition-all group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-bold font-mono text-zinc-200 group-hover:text-emerald-400 transition-colors">
                    {tool.name}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">
                    {tool.id}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-400 line-clamp-2 mb-3">
                  {tool.description}
                </p>
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500 pt-2 border-t border-zinc-800/60">
                <span>{tool.suiteName.replace(/^\d+\.\s*/, '')}</span>
                <span className="text-emerald-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                  Launch <ArrowRight size={12} />
                </span>
              </div>
            </button>
          ))}
        </div>
      </section>

      {/* 8 SUITES CATALOG GRID */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-mono font-black text-zinc-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-emerald-400" />
              Comprehensive Security Suites
            </h2>
            <p className="text-xs text-zinc-400 font-mono mt-1">
              8 specialized domains covering 80 end-to-end incident detection and mitigation tools
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {SUITES_CATALOG.map((suite, idx) => {
            const Icon = SUITE_ICON_MAP[suite.iconName] || Terminal;
            return (
              <div
                key={suite.id}
                className="p-5 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 hover:bg-zinc-900/80 transition-all flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="p-2.5 rounded-xl bg-zinc-800/70 text-emerald-400 group-hover:bg-emerald-500/20 group-hover:text-emerald-300 transition-colors">
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-zinc-800/80 text-zinc-300 border border-zinc-700/60 font-bold">
                      Suite {idx + 1}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold font-mono text-zinc-100 mb-1.5 group-hover:text-emerald-400 transition-colors">
                    {suite.name.replace(/^\d+\.\s*/, '')}
                  </h3>
                  <p className="text-xs text-zinc-400 leading-relaxed mb-4">
                    {suite.description}
                  </p>
                </div>

                <div>
                  <div className="space-y-1.5 pt-3 border-t border-zinc-800/60 mb-4">
                    {suite.tools.slice(0, 3).map(tool => (
                      <button
                        key={tool.id}
                        onClick={() => onSelectTool(tool)}
                        className="w-full text-left text-[11px] font-mono text-zinc-400 hover:text-emerald-300 truncate flex items-center gap-1.5 transition-colors"
                      >
                        <span className="w-1 h-1 rounded-full bg-emerald-500/60" />
                        <span className="truncate">{tool.name}</span>
                      </button>
                    ))}
                    {suite.tools.length > 3 && (
                      <div className="text-[10px] font-mono text-zinc-500 italic pl-2.5">
                        +{suite.tools.length - 3} more tools
                      </div>
                    )}
                  </div>

                  <button
                    onClick={() => onSelectTool(suite.tools[0])}
                    className="w-full py-2 px-3 rounded-lg bg-zinc-800/70 hover:bg-emerald-500 hover:text-zinc-950 text-xs font-mono font-bold text-zinc-200 transition-all flex items-center justify-center gap-1.5"
                  >
                    Open Suite <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
