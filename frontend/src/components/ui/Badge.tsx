import React from 'react';
import { SeverityLevel } from '../../types';

interface BadgeProps {
  level?: SeverityLevel;
  text?: string;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ level, text, className = '' }) => {
  if (level) {
    const config = {
      CLEAN: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60',
      LOW: 'bg-blue-950/60 text-blue-400 border-blue-800/60',
      SUSPICIOUS: 'bg-amber-950/60 text-amber-400 border-amber-800/60',
      MALICIOUS: 'bg-orange-950/60 text-orange-400 border-orange-800/60',
      CRITICAL: 'bg-red-950/60 text-red-400 border-red-800/60'
    }[level];

    return (
      <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${config} ${className}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
        {level}
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono border border-zinc-800 bg-zinc-900/60 text-zinc-400 ${className}`}>
      {text}
    </span>
  );
};
