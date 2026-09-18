import React, { useState } from 'react';
import { Copy, Check, Terminal } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  title?: string;
  platform?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, title, platform }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-zinc-800 bg-[#0c0c0e] overflow-hidden my-2">
      <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/70 border-b border-zinc-800/80 text-xs font-mono">
        <div className="flex items-center gap-2 text-zinc-400">
          <Terminal className="w-3.5 h-3.5 text-emerald-400" />
          <span className="font-semibold text-zinc-200">{title || 'Command / Rule'}</span>
          {platform && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-cyan-400 border border-zinc-700/50">
              {platform}
            </span>
          )}
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-emerald-400 transition-colors px-2 py-0.5 rounded hover:bg-zinc-800"
          title="Copy command to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-bold">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <div className="p-3 overflow-x-auto">
        <pre className="font-mono text-xs text-emerald-300/90 leading-relaxed whitespace-pre-wrap">
          {code}
        </pre>
      </div>
    </div>
  );
};
