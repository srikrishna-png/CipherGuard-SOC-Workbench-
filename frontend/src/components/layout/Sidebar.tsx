import React, { useState } from 'react';
import { 
  Search, Activity, ShieldAlert, Lock, Bell, Network, Cpu, Globe, 
  ChevronDown, ChevronRight, Terminal 
} from 'lucide-react';
import { SUITES_CATALOG } from '../../data/toolsRegistry';
import { ToolMetadata } from '../../types';

interface SidebarProps {
  selectedToolId: string;
  onSelectTool: (tool: ToolMetadata) => void;
}

const ICON_MAP: Record<string, React.ElementType> = {
  Search,
  Activity,
  ShieldAlert,
  Lock,
  Bell,
  Network,
  Cpu,
  Globe
};

export const Sidebar: React.FC<SidebarProps> = ({ selectedToolId, onSelectTool }) => {
  // Map initially expanded suites (open current suite by default)
  const [expandedSuites, setExpandedSuites] = useState<Record<string, boolean>>({
    suite1_artifacts: true,
    suite2_telemetry: true,
  });

  const toggleSuite = (suiteId: string) => {
    setExpandedSuites(prev => ({ ...prev, [suiteId]: !prev[suiteId] }));
  };

  return (
    <aside className="hidden lg:flex flex-col w-72 h-[calc(100vh-4rem)] fixed top-16 left-0 bg-[#09090b] border-r border-zinc-800/80 z-30 overflow-y-auto select-none">
      <div className="p-3 border-b border-zinc-800/60 flex items-center justify-between">
        <span className="text-[11px] font-mono text-zinc-400 font-bold uppercase tracking-wider">
          Analysis Suites
        </span>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
          80 Tools Available
        </span>
      </div>

      <div className="p-2 space-y-1">
        {SUITES_CATALOG.map((suite) => {
          const Icon = ICON_MAP[suite.iconName] || Terminal;
          const isExpanded = !!expandedSuites[suite.id];
          const hasActiveTool = suite.tools.some(t => t.id === selectedToolId);

          return (
            <div key={suite.id} className="rounded-lg overflow-hidden">
              <button
                onClick={() => toggleSuite(suite.id)}
                className={`w-full flex items-center justify-between p-2.5 rounded-lg text-left transition-all ${
                  hasActiveTool 
                    ? 'bg-zinc-900/90 text-zinc-100 font-semibold' 
                    : 'text-zinc-300 hover:bg-zinc-900/50 hover:text-zinc-100'
                }`}
              >
                <div className="flex items-center gap-2 text-xs truncate">
                  <Icon className={`w-4 h-4 flex-shrink-0 ${hasActiveTool ? 'text-emerald-400' : 'text-zinc-400'}`} />
                  <span className="truncate">{suite.name}</span>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <span className="text-[9px] font-mono text-zinc-400 bg-zinc-800/60 px-1 rounded">
                    10
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5 text-zinc-400" />
                  )}
                </div>
              </button>

              {isExpanded && (
                <div className="pl-4 pr-1 py-1 space-y-0.5 border-l border-zinc-800/70 ml-4 my-1">
                  {suite.tools.map((tool) => {
                    const isSelected = tool.id === selectedToolId;
                    return (
                      <button
                        key={tool.id}
                        onClick={() => onSelectTool(tool)}
                        className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs text-left transition-all relative ${
                          isSelected
                            ? 'bg-emerald-950/50 text-emerald-400 font-medium border border-emerald-800/50 shadow-[0_0_8px_rgba(16,185,129,0.15)]'
                            : 'text-zinc-400 hover:bg-zinc-900/40 hover:text-zinc-200'
                        }`}
                      >
                        {isSelected && (
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
                        )}
                        <span className="truncate">{tool.name}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
};
