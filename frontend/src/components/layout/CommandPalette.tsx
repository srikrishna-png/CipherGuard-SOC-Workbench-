import React, { useState, useEffect, useRef } from 'react';
import { Search, X, Terminal, ArrowRight } from 'lucide-react';
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
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(); // parent handles toggling
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Search across all 80 tools
  const allTools = SUITES_CATALOG.flatMap(s => s.tools.map(t => ({ ...t, suiteName: s.name })));
  const filtered = query.trim() === ''
    ? allTools.slice(0, 8)
    : allTools.filter(t => 
        t.name.toLowerCase().includes(query.toLowerCase()) ||
        t.description.toLowerCase().includes(query.toLowerCase()) ||
        t.suiteName.toLowerCase().includes(query.toLowerCase()) ||
        t.id.toLowerCase().includes(query.toLowerCase())
      ).slice(0, 10);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Dialog */}
      <div className="relative w-full max-w-xl bg-[#0e0e11] border border-zinc-800 rounded-xl shadow-[0_16px_48px_rgba(0,0,0,0.8)] overflow-hidden z-10">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-zinc-800">
          <Search className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a tool name, MITRE ID (T1059), or artifact (.pcap)..."
            className="w-full bg-transparent text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none font-mono"
          />
          {query && (
            <button onClick={() => setQuery('')} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Results */}
        <div className="max-h-[380px] overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-zinc-500">
              No matching cybersecurity tools found for "{query}".
            </div>
          ) : (
            <div className="space-y-1">
              {filtered.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    onSelectTool(item);
                    onClose();
                  }}
                  className="w-full flex items-center justify-between p-2.5 rounded-lg text-left hover:bg-zinc-900/80 group transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="p-1.5 rounded bg-zinc-800/80 text-emerald-400 group-hover:bg-emerald-950 group-hover:text-emerald-300 transition-colors">
                      <Terminal className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-zinc-200 group-hover:text-emerald-400 transition-colors truncate">
                        {item.name}
                      </div>
                      <div className="text-[11px] text-zinc-400 truncate">
                        {item.suiteName} &bull; {item.description}
                      </div>
                    </div>
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-emerald-400 flex-shrink-0 ml-2" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-zinc-950/80 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-500">
          <span>8 Suites &bull; 80 Tools Indexed</span>
          <span>Press ESC to close</span>
        </div>
      </div>
    </div>
  );
};
