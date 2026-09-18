import React from 'react';
import { Shield, Layers, Database, Search } from 'lucide-react';

interface BottomNavProps {
  onOpenWorkbench: () => void;
  onOpenMobileDrawer: () => void;
  onOpenAuditLedger: () => void;
  onOpenSearch: () => void;
  activeView: 'workbench' | 'suites' | 'audit';
}

export const BottomNav: React.FC<BottomNavProps> = ({
  onOpenWorkbench,
  onOpenMobileDrawer,
  onOpenAuditLedger,
  onOpenSearch,
  activeView
}) => {
  return (
    <nav className="lg:hidden fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] w-[92%] max-w-[380px]">
      <div className="flex items-center justify-around p-2 bg-[#0c0c0e]/80 backdrop-blur-xl border border-zinc-800/80 rounded-2xl shadow-[0_8px_32px_rgba(0,0,0,0.6)]">
        <button
          onClick={onOpenWorkbench}
          className={`relative flex flex-col items-center gap-1 px-3 py-1.5 transition-all duration-300 ${
            activeView === 'workbench' ? 'text-emerald-400' : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Shield className="w-5 h-5" />
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider">Workbench</span>
          {activeView === 'workbench' && (
            <div className="absolute inset-0 bg-emerald-500/10 rounded-xl -z-10" />
          )}
        </button>

        <button
          onClick={onOpenMobileDrawer}
          className={`relative flex flex-col items-center gap-1 px-3 py-1.5 transition-all duration-300 ${
            activeView === 'suites' ? 'text-emerald-400' : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Layers className="w-5 h-5" />
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider">8 Suites</span>
          {activeView === 'suites' && (
            <div className="absolute inset-0 bg-emerald-500/10 rounded-xl -z-10" />
          )}
        </button>

        <button
          onClick={onOpenAuditLedger}
          className={`relative flex flex-col items-center gap-1 px-3 py-1.5 transition-all duration-300 ${
            activeView === 'audit' ? 'text-emerald-400' : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Database className="w-5 h-5" />
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider">Ledger</span>
          {activeView === 'audit' && (
            <div className="absolute inset-0 bg-emerald-500/10 rounded-xl -z-10" />
          )}
        </button>

        <button
          onClick={onOpenSearch}
          className="relative flex flex-col items-center gap-1 px-3 py-1.5 transition-all duration-300 text-zinc-400 hover:text-zinc-200"
        >
          <Search className="w-5 h-5" />
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider">Search</span>
        </button>
      </div>
    </nav>
  );
};
