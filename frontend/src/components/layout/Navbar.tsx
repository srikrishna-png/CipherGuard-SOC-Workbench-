import React from 'react';
import { 
  Shield, Search, Database, Menu, Terminal, CheckCircle2, 
  Bot, LayoutDashboard, User, LogOut
} from 'lucide-react';
import { UserProfile } from '../auth/LoginPage';

interface NavbarProps {
  currentView: 'dashboard' | 'workbench' | 'login';
  onChangeView: (view: 'dashboard' | 'workbench' | 'login') => void;
  onOpenAuditLedger: () => void;
  onOpenAIAssistant: () => void;
  onOpenSearch: () => void;
  onToggleMobileMenu: () => void;
  activeToolName: string;
  currentUser: UserProfile | null;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentView,
  onChangeView,
  onOpenAuditLedger,
  onOpenAIAssistant,
  onOpenSearch,
  onToggleMobileMenu,
  activeToolName,
  currentUser,
  onLogout
}) => {
  return (
    <header className="fixed top-0 left-0 right-0 z-40 h-16 bg-[#09090b]/90 backdrop-blur-md border-b border-zinc-800/80 px-3 sm:px-4 lg:px-6 flex items-center justify-between select-none">
      {/* Left: Brand & Mobile Hamburger */}
      <div className="flex items-center gap-3">
        {currentView === 'workbench' && (
          <button
            onClick={onToggleMobileMenu}
            className="lg:hidden p-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-emerald-400 transition-colors"
            aria-label="Open navigation drawer"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}

        <div 
          onClick={() => onChangeView('dashboard')}
          className="flex items-center gap-2.5 group cursor-pointer"
        >
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-emerald-500 text-zinc-950 font-mono font-bold text-sm shadow-[0_0_15px_rgba(16,185,129,0.4)] group-hover:bg-emerald-400 transition-colors">
            CG
          </div>
          <div className="flex flex-col">
            <span className="font-mono font-bold tracking-tight text-sm sm:text-base text-zinc-100 flex items-center gap-1">
              Cipher<span className="text-emerald-400">Guard_</span>
              <span className="hidden sm:inline text-[9px] px-1.5 py-0.5 rounded bg-emerald-950/70 border border-emerald-800/50 text-emerald-400 ml-1 font-mono font-bold">
                SOC v2.0
              </span>
            </span>
            <span className="text-[9px] font-mono text-zinc-500 tracking-wider uppercase hidden md:inline">
              Autonomous Defensive Workbench
            </span>
          </div>
        </div>
      </div>

      {/* Middle: Navigation Mode Tabs */}
      <nav className="hidden md:flex items-center gap-1 p-1 rounded-xl bg-zinc-900/80 border border-zinc-800/80">
        <button
          onClick={() => onChangeView('dashboard')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
            currentView === 'dashboard'
              ? 'bg-emerald-500 text-zinc-950 font-bold shadow-[0_0_12px_rgba(16,185,129,0.3)]'
              : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60'
          }`}
        >
          <LayoutDashboard size={14} />
          <span>Dashboard</span>
        </button>

        <button
          onClick={() => onChangeView('workbench')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
            currentView === 'workbench'
              ? 'bg-emerald-500 text-zinc-950 font-bold shadow-[0_0_12px_rgba(16,185,129,0.3)]'
              : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60'
          }`}
        >
          <Terminal size={14} />
          <span>Workbench</span>
          {currentView === 'workbench' && (
            <span className="hidden xl:inline text-[10px] opacity-80 truncate max-w-[120px]">
              ({activeToolName.split(' ')[0]})
            </span>
          )}
        </button>

        <button
          onClick={onOpenAIAssistant}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-cyan-400 hover:text-cyan-300 hover:bg-cyan-950/40 border border-transparent hover:border-cyan-800/50 transition-all"
        >
          <Bot size={14} />
          <span>AI Copilot</span>
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
        </button>

        <button
          onClick={onOpenAuditLedger}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-amber-400 hover:text-amber-300 hover:bg-amber-950/40 border border-transparent hover:border-amber-800/50 transition-all"
        >
          <Database size={14} />
          <span>Audit Ledger</span>
          <CheckCircle2 size={12} className="text-emerald-400" />
        </button>
      </nav>

      {/* Right: Search & User Session */}
      <div className="flex items-center gap-2">
        {/* Search Trigger */}
        <button
          onClick={onOpenSearch}
          className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          title="Search all 80 tools (Ctrl+K)"
        >
          <Search className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden sm:inline">Search</span>
          <kbd className="hidden sm:inline text-[9px] bg-zinc-800 text-zinc-400 px-1 py-0.5 rounded border border-zinc-700">
            Ctrl+K
          </kbd>
        </button>

        {/* AI Assistant Quick Button (Mobile) */}
        <button
          onClick={onOpenAIAssistant}
          className="md:hidden p-2 rounded-lg bg-cyan-950/40 border border-cyan-800/50 text-cyan-400"
          aria-label="Open AI Assistant"
        >
          <Bot size={16} />
        </button>

        {/* User Session Profile / Login */}
        {currentUser ? (
          <div className="flex items-center gap-1.5 pl-1.5 border-l border-zinc-800">
            <button
              onClick={() => onChangeView('login')}
              className="flex items-center gap-2 p-1 sm:px-2 sm:py-1 rounded-lg hover:bg-zinc-850 border border-transparent hover:border-zinc-800 transition-colors text-left"
              title="Switch Operator Profile"
            >
              <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center font-mono font-bold text-xs">
                {currentUser.avatarInitials}
              </div>
              <div className="hidden lg:flex flex-col">
                <span className="text-xs font-mono font-bold text-zinc-200 leading-tight">
                  {currentUser.username}
                </span>
                <span className="text-[9px] font-mono text-emerald-400 leading-none">
                  {currentUser.clearance.split('//')[0].trim()}
                </span>
              </div>
            </button>
            <button
              onClick={onLogout}
              className="p-1.5 rounded-lg text-zinc-500 hover:text-red-400 hover:bg-zinc-850 transition-colors hidden sm:inline-block"
              title="Logout session"
            >
              <LogOut size={14} />
            </button>
          </div>
        ) : (
          <button
            onClick={() => onChangeView('login')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-emerald-500/40 text-xs font-mono text-zinc-300 hover:text-emerald-400 transition-colors"
          >
            <User size={13} className="text-emerald-400" />
            <span className="hidden sm:inline">Operator Login</span>
          </button>
        )}
      </div>
    </header>
  );
};
