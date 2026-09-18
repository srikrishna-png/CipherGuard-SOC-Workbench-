import React from 'react';
import { Shield, Search, Database, Menu, Terminal, CheckCircle2 } from 'lucide-react';

interface NavbarProps {
  onOpenAuditLedger: () => void;
  onOpenSearch: () => void;
  onToggleMobileMenu: () => void;
  activeToolName: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenAuditLedger,
  onOpenSearch,
  onToggleMobileMenu,
  activeToolName
}) => {
  return (
    <header className="fixed top-0 left-0 right-0 z-40 h-16 bg-[#09090b]/90 backdrop-blur-md border-b border-zinc-800/80 px-4 lg:px-6 flex items-center justify-between">
      {/* Left: Brand & Mobile Menu */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobileMenu}
          className="lg:hidden p-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-emerald-400 transition-colors"
          aria-label="Open navigation drawer"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5 group cursor-pointer">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-emerald-500 text-zinc-950 font-mono font-bold text-sm shadow-[0_0_12px_rgba(16,185,129,0.35)]">
            CG
          </div>
          <div className="flex flex-col">
            <span className="font-mono font-bold tracking-tight text-base text-zinc-100 flex items-center gap-1">
              Cipher<span className="text-emerald-400">Guard_</span>
              <span className="hidden sm:inline text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/70 border border-emerald-800/50 text-emerald-400 ml-1 font-mono">
                SOC v2.0
              </span>
            </span>
            <span className="text-[10px] font-mono text-zinc-400 tracking-wider uppercase hidden md:inline">
              Defensive Operations & Triage Workbench
            </span>
          </div>
        </div>
      </div>

      {/* Middle: Active Tool Breadcrumb */}
      <div className="hidden xl:flex items-center gap-2 text-xs font-mono text-zinc-400 bg-zinc-900/60 px-3 py-1.5 rounded-lg border border-zinc-800">
        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
        <span>ACTIVE_TOOL:</span>
        <span className="text-zinc-200 font-semibold">{activeToolName}</span>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Search / Command Palette Trigger */}
        <button
          onClick={onOpenSearch}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/80 border border-zinc-800 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
        >
          <Search className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden sm:inline">Search Tools...</span>
          <kbd className="hidden sm:inline text-[10px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded border border-zinc-700">
            Ctrl+K
          </kbd>
        </button>

        {/* Audit Ledger Trigger */}
        <button
          onClick={onOpenAuditLedger}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/50 text-xs font-mono text-emerald-400 hover:bg-emerald-900/40 transition-colors shadow-[0_0_10px_rgba(16,185,129,0.15)]"
        >
          <Database className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Audit Ledger</span>
          <CheckCircle2 className="w-3 h-3 text-emerald-400 animate-pulse" />
        </button>
      </div>
    </header>
  );
};
