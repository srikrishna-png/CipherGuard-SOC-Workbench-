import React, { useState } from 'react';
import { X, ChevronDown, ChevronRight, Terminal } from 'lucide-react';
import { SUITES_CATALOG } from '../../data/toolsRegistry';
import { ToolMetadata } from '../../types';

interface MobileSidebarProps {
  isOpen: boolean;
  onClose: () => void;
  selectedToolId: string;
  onSelectTool: (tool: ToolMetadata) => void;
}

export const MobileSidebar: React.FC<MobileSidebarProps> = ({
  isOpen,
  onClose,
  selectedToolId,
  onSelectTool
}) => {
  const [expandedSuites, setExpandedSuites] = useState<Record<string, boolean>>({
    suite1_artifacts: true,
  });

  if (!isOpen) return null;

  const toggleSuite = (suiteId: string) => {
    setExpandedSuites(prev => ({ ...prev, [suiteId]: !prev[suiteId] }));
  };

  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed inset-y-0 left-0 w-[85%] max-w-[320px] bg-[#09090b] border-r border-zinc-800 p-4 flex flex-col z-50 overflow-y-auto">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-zinc-800">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-7 h-7 rounded bg-emerald-500 text-zinc-950 font-mono font-bold text-xs">
              CG
            </div>
            <span className="font-mono font-bold text-sm text-zinc-100">
              Cipher<span className="text-emerald-400">Guard</span> Suites
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-zinc-900 text-zinc-400 hover:text-zinc-100"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-2 flex-1">
          {SUITES_CATALOG.map((suite) => {
            const isExpanded = !!expandedSuites[suite.id];
            return (
              <div key={suite.id} className="rounded-lg bg-zinc-900/40 border border-zinc-800/60 overflow-hidden">
                <button
                  onClick={() => toggleSuite(suite.id)}
                  className="w-full flex items-center justify-between p-3 text-left text-xs font-semibold text-zinc-200"
                >
                  <span className="truncate pr-2">{suite.name}</span>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-zinc-400 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-zinc-400 flex-shrink-0" />
                  )}
                </button>

                {isExpanded && (
                  <div className="p-2 pt-0 space-y-1 border-t border-zinc-800/40">
                    {suite.tools.map((tool) => {
                      const isSelected = tool.id === selectedToolId;
                      return (
                        <button
                          key={tool.id}
                          onClick={() => {
                            onSelectTool(tool);
                            onClose();
                          }}
                          className={`w-full flex items-center gap-2 p-2 rounded text-xs text-left ${
                            isSelected
                              ? 'bg-emerald-950/60 text-emerald-400 font-bold border border-emerald-800/60'
                              : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/40'
                          }`}
                        >
                          <Terminal className="w-3 h-3 text-emerald-400 flex-shrink-0" />
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
      </div>
    </div>
  );
};
