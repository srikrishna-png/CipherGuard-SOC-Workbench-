import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Search, X, Terminal, ArrowRight, Shield } from 'lucide-react';
import { SUITES_CATALOG } from '../../data/toolsRegistry';
import { ToolMetadata } from '../../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTool: (tool: ToolMetadata) => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onSelectTool
}) => {
  const [query, setQuery] = useState('');
  const [selectedSuiteFilter, setSelectedSuiteFilter] = useState<string>('all');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    } else {
      setQuery('');
      setSelectedSuiteFilter('all');
    }
  }, [isOpen]);

  // Flatten all 80 tools from the 8 suites
  const allTools = useMemo(() => {
    return SUITES_CATALOG.flatMap(suite => 
      suite.tools.map(tool => ({
        ...tool,
        suiteName: suite.name,
        suiteBadge: suite.badge,
        suiteIcon: suite.iconName
      }))
    );
  }, []);

  // Filter across all 80 tools with NO truncation limit
  const filteredTools = useMemo(() => {
    return allTools.filter(t => {
      const matchesSuite = selectedSuiteFilter === 'all' || t.suiteId === selectedSuiteFilter;
      if (!matchesSuite) return false;

      if (!query.trim()) return true;

      const q = query.toLowerCase().trim();
      return (
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q) ||
        t.suiteName.toLowerCase().includes(q)
      );
    });
  }, [allTools, query, selectedSuiteFilter]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;

      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => (prev + 1) % (filteredTools.length || 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => (prev - 1 + (filteredTools.length || 1)) % (filteredTools.length || 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredTools[selectedIndex]) {
          onSelectTool(filteredTools[selectedIndex]);
          onClose();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, filteredTools, selectedIndex, onSelectTool]);

  // Scroll active item into view
  useEffect(() => {
    const activeEl = listRef.current?.querySelector(`[data-index="${selectedIndex}"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-14 md:pt-20 px-3 md:px-4">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/85 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />

      {/* Dialog */}
      <div className="relative w-full max-w-2xl bg-[#09090b] border border-zinc-700/80 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.95)] overflow-hidden z-10 flex flex-col max-h-[85vh]">
        {/* Search header bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-zinc-800/80 bg-zinc-900/60">
          <Search className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Search all 80 tools (e.g. YARA, Beaconing, JWT, Subnet, Brute-force)..."
            className="w-full bg-transparent text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none font-mono"
          />
          {query && (
            <button 
              onClick={() => {
                setQuery('');
                setSelectedIndex(0);
              }} 
              className="text-zinc-500 hover:text-zinc-300 p-1 rounded"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <span className="hidden sm:inline-block px-2 py-0.5 text-[10px] font-mono text-zinc-400 bg-zinc-800 rounded border border-zinc-700">
            ESC
          </span>
        </div>

        {/* Suite Category Filter Chips */}
        <div className="px-3 py-2 border-b border-zinc-800/60 bg-zinc-950/90 overflow-x-auto flex items-center gap-1.5 scrollbar-none">
          <button
            onClick={() => { setSelectedSuiteFilter('all'); setSelectedIndex(0); }}
            className={`px-2.5 py-1 rounded-full text-[11px] font-mono whitespace-nowrap transition-colors ${
              selectedSuiteFilter === 'all'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
            }`}
          >
            All Tools (80)
          </button>
          {SUITES_CATALOG.map(s => {
            const isSelected = selectedSuiteFilter === s.id;
            return (
              <button
                key={s.id}
                onClick={() => { setSelectedSuiteFilter(s.id); setSelectedIndex(0); }}
                className={`px-2.5 py-1 rounded-full text-[11px] font-mono whitespace-nowrap transition-colors ${
                  isSelected
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                }`}
              >
                {s.name.replace(/^\d+\.\s*/, '')} ({s.tools.length})
              </button>
            );
          })}
        </div>

        {/* Results List - Uncapped */}
        <div ref={listRef} className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredTools.length === 0 ? (
            <div className="py-12 px-4 text-center">
              <Shield className="w-8 h-8 text-zinc-600 mx-auto mb-2 opacity-50" />
              <div className="text-xs font-mono text-zinc-400">
                No matching cybersecurity tools found for "{query}".
              </div>
              <div className="text-[11px] text-zinc-600 mt-1 font-mono">
                Try searching for "URL", "hash", "firewall", "log", "beacon", or "entropy".
              </div>
            </div>
          ) : (
            filteredTools.map((item, index) => {
              const isSelected = index === selectedIndex;
              return (
                <button
                  key={item.id}
                  data-index={index}
                  onMouseEnter={() => setSelectedIndex(index)}
                  onClick={() => {
                    onSelectTool(item);
                    onClose();
                  }}
                  className={`w-full flex items-center justify-between p-3 rounded-xl text-left transition-all ${
                    isSelected
                      ? 'bg-zinc-900 border border-emerald-500/40 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
                      : 'hover:bg-zinc-900/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-2 rounded-lg transition-colors flex-shrink-0 ${
                      isSelected 
                        ? 'bg-emerald-500 text-zinc-950 font-bold' 
                        : 'bg-zinc-800 text-zinc-300'
                    }`}>
                      <Terminal className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold font-mono truncate ${
                          isSelected ? 'text-emerald-400' : 'text-zinc-200'
                        }`}>
                          {item.name}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800/80 text-zinc-400 border border-zinc-700/50 flex-shrink-0">
                          {item.suiteName.replace(/^\d+\.\s*/, '')}
                        </span>
                      </div>
                      <div className="text-[11px] text-zinc-400 truncate mt-0.5">
                        {item.description}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                    <span className="text-[10px] font-mono text-zinc-500 hidden sm:inline">
                      {item.id}
                    </span>
                    <ArrowRight className={`w-4 h-4 transition-transform ${
                      isSelected ? 'text-emerald-400 translate-x-0.5' : 'text-zinc-600'
                    }`} />
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 bg-zinc-950 border-t border-zinc-800/80 flex items-center justify-between text-[11px] font-mono text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Showing <strong className="text-emerald-400">{filteredTools.length}</strong> of 80 Tools</span>
          </div>
          <div className="flex items-center gap-3 text-zinc-500 text-[10px]">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>ESC Close</span>
          </div>
        </div>
      </div>
    </div>
  );
};
